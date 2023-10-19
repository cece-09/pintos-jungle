/* file.c: Implementation of memory backed file object (mmaped object). */

#include <stdio.h>

#include "vm/vm.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);
static bool file_write_back(struct page *page, struct page *head);
static bool lazy_load_file(struct page *page, void *aux);
static bool do_page_read_write(struct page *page, struct page *head,
                               file_rw_func func);
static struct page *spt_get_head(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void) {}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva) {
  /* Mapped file info. */
  struct file_page *aux = page->uninit.aux;
  if (aux == NULL) return false;

  /* Fetch first, page_initialize may overwrite the values. */
  struct file *file = aux->file;
  off_t offset = aux->offset;
  size_t length = aux->length;
  void *map_addr = aux->map_addr;

  /* Set up the handler. */
  page->operations = &file_ops;

  /* Initialize file page fields. */
  struct file_page *file_page = &page->file;
  *file_page = (struct file_page){
      .file = file,        /* mapped file ptr. */
      .offset = offset,    /* map start offset. */
      .length = length,    /* length of mapping. */
      .map_addr = map_addr /* va where mapping starts. */
  };
  free(aux);
  return true;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
  struct file_page *file_page = &page->file;
  struct page* head = spt_get_head(page);
  do_page_read_write(page, head, file_read);

  install_page(page);
  page->flags = page->flags | PTE_P;
  return true;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
  struct thread* curr = thread_current();
  struct file_page *file_page = &page->file;
  
  struct page* head = spt_get_head(page);
  if(!file_write_back(page, head)) {
    return false;
  }

  page->frame = NULL;
  pml4_clear_page(curr->pml4, page->va);
  page->flags = page->flags & ~PTE_P;
  return true;
}


/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
  struct thread *curr = thread_current();
  struct file_page *file_page = &page->file;

  /* If page is alreay written back, return. */
  if(pg_writeback(page)) {
    return;
  }

  /* Get head-page. */
  struct page *head = spt_get_head(page);
  ASSERT(head != NULL)
  page = head;

  /* For loop. */
  void *p = page->va;
  long length = (long)page->file.length;

  while (length > 0 && page) {
    /* Write back to file, exit -1 if false. */
    if (pg_present(page) && !file_write_back(page, head)) {
      curr->exit_code = -1;
      thread_exit();
    }
    page->flags = page->flags | PG_WB;

    /* Clear up. */
    pml4_clear_page(curr->pml4, page->va);
    if(page->frame) {
      palloc_free_page(page->frame->kva);
    }

    p += PGSIZE;
    length -= PGSIZE;
    page = spt_find_page(&curr->spt, p);
  }

  /* Close file. */
  file_close(file_page->file);
  return;
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file,
              off_t offset) {
  struct thread *curr = thread_current();

  /* If addr or offset is not page-aligned. */
  if ((uint64_t)addr % PGSIZE || offset % PGSIZE) {
    return NULL;
  }

  /* If addr is in spt. */
  for (void *p = addr; p < addr + length; p += PGSIZE) {
    if (spt_find_page(&curr->spt, p)) {
      return NULL;
    }
  }

  /* If addr in stack area. */
  if (addr + length > STACK_LIMIT && addr < USER_STACK) {
    return NULL;
  }

  /* Allocate page with lazy loading. */
  struct file *mmap_file = file_duplicate(file);
  long left = (long)length;
  int cnt = 0;

  while (left > 0) {
    /* Save infos for initializing file-backed page. */
    struct file_page *aux = calloc(1, sizeof(struct file_page));

    /* Only head page holds mmap_file address. */
    aux->file = cnt == 0 ? mmap_file : NULL; /* map file from */
    aux->offset = offset;                    /* offset, */
    aux->length = length;                    /* to length bytes. */
    aux->map_addr = addr;                    /* va where mapping starts. */

    if (!vm_alloc_page_with_initializer(VM_FILE, addr + (cnt * PGSIZE),
                                        writable, lazy_load_file, aux)) {
      return NULL;
    }

    left -= PGSIZE;
    cnt++;
  }
  return addr;
}

/* Do the munmap. Unmap can be called when page is not initialized. */
void do_munmap(void *addr) {
  struct thread *curr = thread_current();
  struct page *page = spt_find_page(&curr->spt, addr);

  /* If page is not found, return. */
  if (page == NULL) return;

  /* Virtual address must be the map_addr. */
  if (page->file.map_addr != addr) return;

  struct file *file = page->file.file;
  void *map_addr = page->file.map_addr;
  size_t length = page->file.length;

  /* Remove page from spt and pml4.
   * Write back file if page is VM_FILE. */
  spt_remove_page(&curr->spt, page);
}

/* Initialize file-backed frame. */
static bool lazy_load_file(struct page *page, void *aux) {
  ASSERT(page->operations->type == VM_FILE)
  ASSERT(page->frame)
  
  /* Get head-page. */
  struct thread *curr = thread_current();
  struct page *head = spt_get_head(page);
  ASSERT(head != NULL)

  /* Read file to page. */
  if (!do_page_read_write(page, head, file_read)) {
    printf("Fail to read file.\n");
    return false;
  }
  return true;
}

/* Write back to file. Called when unmap. */
static bool file_write_back(struct page *page, struct page *head) {
  ASSERT(page->operations->type == VM_FILE)

  struct thread *curr = thread_current();
  /* If page is present and not dirty, return. */
  if (!pml4_is_dirty(curr->pml4, page->va)) {
    return true;
  }

  /* Write back to file. */
  if (!do_page_read_write(page, head, file_write)) {
    printf("Fail to write back file.\n");
    return false;
  }
  return true;
}

/* Calculate page offset in mapped area
 * and execute func handed by argument. */
static bool do_page_read_write(struct page *page, struct page *head,
                               file_rw_func func) {
  struct file *file = head->file.file;
  off_t offset = page->file.offset;
  size_t length = page->file.length;
  void *map_addr = page->file.map_addr;
  void *kva = page->frame->kva;

  ASSERT(page->frame && kva)

  /* Calculate page offset. Starts from 1. */
  off_t page_offset = (page->va - map_addr) / PGSIZE;

  /* Calculate read-write-start point. */
  off_t rw_start = offset + page_offset * PGSIZE;

  /* Calculate read-write-bytes. */
  file_seek(file, rw_start);
  
  /* 
     offset                                   len  page-aligned
       +----------+----------+----------+------+---+
       |          |          |          |      |   |
       |          |          |          |      |   |
       |   page   |   page   |   page   |   page   |
       |          |          |          |      |   |
       |          |          |          |      |   |
       +----------+----------+----------+------+---+

       +----------+-------+
       |                  |
       |       file       |
       |                  |
       +----------+-------+

       Take min(PGSIZE, (off+len)-rw_start, file_left) as rw_bytes of this page.
       Page 0 takes PGSIZE,
       Page 1 takes file_left, and so on.
  */

  off_t file_left = file_length(file) - file->pos;
  size_t rw_bytes = (offset + length) - rw_start;
  rw_bytes = rw_bytes < PGSIZE ? rw_bytes : PGSIZE;
  rw_bytes = rw_bytes < file_left ? rw_bytes : file_left;

  /* Do func. */
  if (func(file, kva, rw_bytes) != (int)rw_bytes) {
    return false;
  }
  return true;
}

/* Get head page of this mapping. */
static struct page *spt_get_head(struct page *page) {
  struct thread *curr = thread_current();
  if (is_file_head(page, &page->file)) {
    return page;
  }
  return spt_find_page(&curr->spt, page->file.map_addr);
}
