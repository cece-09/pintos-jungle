/* file.c: Implementation of memory backed file object (mmaped object). */

#include <stdio.h>

#include "vm/vm.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);
static void file_write_back(struct page *page);
static bool lazy_load_file(struct page *page, void *aux);

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
      .file = file, .offset = offset, .length = length, .map_addr = map_addr};
  free(aux);
  return true;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
  struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
  struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
  struct thread *curr = thread_current();
  struct file_page *file_page = &page->file;

  /* Write back to file. */
  file_write_back(page);

  /* Clear up. */
  pml4_clear_page(curr->pml4, page->va);
  palloc_free_page(page->frame->kva);

  /* Close file. */
  // FIXME: 부모와 자식이 동일한 파일 포인터를 갖는 식으로 spt_copy를 하고 있음
  if(file_page->file->dup_cnt > 0) {
    file_page->file->dup_cnt--;
  } else {
    file_close(file_page->file);
  }
  return;
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file,
              off_t offset) {
  struct thread *curr = thread_current();

  /* If addr is null or not page-aligned. */
  if (addr == NULL || (uint64_t)addr % PGSIZE) return NULL;

  /* If addr is in spt. */
  for (void *p = addr; p < addr + length; p += PGSIZE) {
    if (spt_find_page(&curr->spt, p)) return NULL;
  }

  /* If addr in stack area. */
  if (addr + length > STACK_LIMIT && addr < USER_STACK) return NULL;

  /* Allocate page with lazy loading. */
  struct file *mmap_file = file_duplicate(file);
  int page_cnt = 0;

  while (length > 0) {
    size_t page_length = length < PGSIZE ? length : PGSIZE;

    /* Save infos for initializing file-backed page. */
    struct file_page *aux = calloc(1, sizeof(struct file_page));
    aux->file = mmap_file; /* map file from */
    aux->offset = offset;  /* offset, */
    aux->length = length;  /* to length bytes. */
    aux->map_addr = addr;  /* map-start address. */

    if (!vm_alloc_page_with_initializer(VM_FILE, addr + (page_cnt * PGSIZE),
                                        writable, lazy_load_file, aux)) {
      return NULL;
    }

    length -= page_length;
    page_cnt++;
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

  /* If addr is valid mapped-address, */
  for (void *p = addr; length > 0; p += PGSIZE) {
    size_t page_length = length < PGSIZE ? length : PGSIZE;

    page = spt_find_page(&curr->spt, p);
    if (page == NULL) {
      return;
    }

    /* Remove page from spt and pml4.
     * Write back file if page is VM_FILE. */
    spt_remove_page(&curr->spt, page);
    length -= page_length;
  }
}

/* Initialize file-backed frame. */
static bool lazy_load_file(struct page *page, void *aux) {
  ASSERT(page->operations->type == VM_FILE)
  ASSERT(page->frame)

  struct file *file = page->file.file;
  off_t offset = page->file.offset;
  size_t length = page->file.length;
  void *map_addr = page->file.map_addr;

  /* Calculate page offset. */
  off_t page_offset = (page->va - map_addr) % PGSIZE;

  /* Calculate read-start point. */
  off_t read_start = offset + page_offset * PGSIZE;

  /* Calculate read-bytes. */
  off_t file_len = file_length(file);
  size_t read_bytes = (offset + length) - read_start;
  read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
  read_bytes = read_bytes < file_len ? read_bytes : file_len;

  void *kva = page->frame->kva;
  if (kva == NULL) return false;

  /* Map with file. */
  file_seek(file, read_start);
  if (file_read(file, kva, read_bytes) != (int)read_bytes) {
    return false;
  }
  return true;
}

/* Write back to file. Called when unmap. */
static void file_write_back(struct page *page) {
  struct thread *curr = thread_current();

  ASSERT(page->operations->type == VM_FILE)

  struct file *file = page->file.file;
  off_t offset = page->file.offset;
  size_t length = page->file.length;
  void *map_addr = page->file.map_addr;
  void *kva = page->frame->kva;

  ASSERT(kva && file)

  /* If page is present and not dirty, return. */
  if (!pml4_is_dirty(curr->pml4, page->va)) {
    return;
  }
  
  // TODO: lazy_load_file과 로직이 동일함. 수정할 것.
  /* Calculate page offset. */
  off_t page_offset = (page->va - map_addr) % PGSIZE;

  /* Calculate read-start point. */
  off_t write_start = offset + page_offset * PGSIZE;

  /* Calculate read-bytes. */
  off_t file_len = file_length(file);
  size_t write_bytes = (offset + length) - write_start;
  write_bytes = write_bytes < PGSIZE ? write_bytes : PGSIZE;
  write_bytes = write_bytes < file_len ? write_bytes : file_len;

  /* Write back to file. */
  file_seek(file, write_start);
  if (file_write(file, kva, write_bytes) != (int)write_bytes) {
    PANIC("File write failed.");
  }
}
