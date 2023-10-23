/* file.c: Implementation of memory backed file object (mmaped object). */

#include <bitmap.h>
#include <stdio.h>

#include "vm/vm.h"

/* Basic operations. */
static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* Swap table. */
#define MAX_SLOTS 32768
#define SLOT_INIT (size_t)(-1)
static struct bitmap *swap_slot;
static struct page **swap_table;

/* Control lazy load order. */
static struct lock slot_lock;
static struct lock load_lock;

/* Read/Write function type. */
typedef off_t (*file_io)(struct file *, const void *, off_t);

/* === Helpers. === */
static bool file_write_back(struct page *page, struct page *head);
static void file_write_back_all(struct page *head);
static bool lazy_load_file(struct page *page, void *aux);
static bool do_file_io(struct page *page, struct page *head, file_io func);
static struct page *spt_get_head(struct page *page);

static size_t allocate_slot();
static void free_slot(size_t slot);
static bool swap_table_empty(size_t slot);
static struct page *swap_table_pop(size_t slot);
static void swap_table_push(size_t slot, struct page *page);
static struct page *swap_table_remove(size_t slot, struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void) {
  /* Create swap table. */
  size_t slots = MAX_SLOTS;
  swap_slot = bitmap_create(slots);

  /* Create swap slot table. */
  size_t page_cnt = (slots * sizeof(struct page *)) / 0x1000;
  swap_table = palloc_get_multiple(PAL_ZERO, page_cnt);

  /* Init filesys lock. */
  lock_init(&load_lock);
  lock_init(&slot_lock);
}

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
      .file = file,         /* mapped file ptr. */
      .offset = offset,     /* map start offset. */
      .length = length,     /* length of mapping. */
      .map_addr = map_addr, /* va where mapping starts. */
      .slot = SLOT_INIT     /* swap slot info. */
  };
  free(aux);
  return true;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
  ASSERT(page_get_type(page) == VM_FILE)

  struct frame *frame = page->frame;
  ASSERT(frame && kva)

  size_t slot = page->anon.slot;
  if (slot == SLOT_INIT) {
    /* If page was never swapped out, just install. */
    vm_map_frame(page, frame);
    return vm_install_page(page, page->thread);
  }

  struct page *head = spt_get_head(page);
  ASSERT(head != NULL)

  /* Read from file to kva. */
  if (!do_file_io(page, head, filesys_read)) {
    printf("File read fail in file-backed swap-in\n");
    return false;
  }

  /* Set this page's access bit. */
  pml4_set_accessed(page->thread->pml4, page->va, true);

  /* Set all linked pages present. */
  while (!swap_table_empty(slot)) {
    page = swap_table_pop(slot);
    ASSERT(page != NULL);

    /* Link with frame. */
    page->frame = frame;
    page->flags = page->flags | PTE_P;
    vm_map_frame(page, frame);
    vm_install_page(page, page->thread);

    /* Unlink with disk slot. */
    page->anon.slot = SLOT_INIT;
  }

  /* Mark as free sector. */
  free_slot(slot);
  return true;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
  struct frame *frame = page->frame;
  void *kva = page->frame->kva;
  ASSERT(frame && kva)

  struct page *head = spt_get_head(page);
  ASSERT(head != NULL)

  /* Find free swap table slot. */
  size_t slot = allocate_slot();
  if (slot == BITMAP_ERROR) {
    return false;
  }

  /* Write back to file. */
  if (!file_write_back(page, head)) {
    printf("File write fail in file-backed swap-out\n");
    return false;
  }

  /* Clear all linked pages. */
  struct thread *t;
  struct page *prev;
  struct list_elem *front;
  while (!list_empty(&frame->pages)) {
    front = list_pop_front(&frame->pages);
    page = list_entry(front, struct page, frame_elem);
    t = page->thread;

    /* Unlink with frame. */
    page->frame = NULL;
    page->flags = page->flags & ~PTE_P;
    pml4_clear_page(t->pml4, page->va);
    pml4_set_accessed(t->pml4, page->va, false);
    pml4_set_dirty(t->pml4, page->va, false);

    /* Link with disk slot. */
    page->file.slot = slot;
    swap_table_push(slot, page);
    ASSERT(!swap_table_empty(slot));
  }

  return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
  if (!pg_present(page)) {
    size_t slot = page->file.slot;
    if (!swap_table_remove(slot, page)) {
      PANIC("Page is not found while removing from list.\n");
    }
    free_slot(slot);
    return;
  }

  /* Clear up if frame-mapped page. */
  struct thread *t = page->thread;
  pml4_clear_page(t->pml4, page->va);

  struct frame *frame = page->frame;
  vm_unmap_frame(page);

  /* If page is the last, free frame. */
  if (list_empty(&frame->pages)) {
    palloc_free_page(frame->kva);
    free(frame);
  }

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

/* Do the munmap. Unmap can be called when
 * head or sub pages are not initialized. */
void do_munmap(void *addr) {
  struct thread *curr = thread_current();
  struct page *page = spt_find_page(&curr->spt, addr);

  /* If page is not found, return. */
  if (page == NULL) return;

  /* Virtual address must be the map_addr. */
  struct file_page *file_page = get_file_page(page);
  if (file_page->map_addr != addr) return;

  size_t length = file_page->length;

  /* Write back all pages starting from head. */
  file_write_back_all(page);

  /* Remove head-page and all sub-pages from spt and pml4. */
  for (void *p = addr; p < addr + length; p += PGSIZE) {
    page = spt_find_page(&curr->spt, p);
    spt_remove_page(&curr->spt, page);
  }
}

/* Hash action function which write all file-backed pages
 * back to disk if page is dirty.
 * See supplemental_page_table_kill in vm.c */
void spt_file_writeback(struct hash_elem *e, void *aux) {
  struct page *page = hash_entry(e, struct page, table_elem);
  if (page_get_type(page) != VM_FILE) return;
  if (!is_file_head(page, get_file_page(page))) return;

  /* If page is head-page of
   * file-backed pages, write back. */
  file_write_back_all(page);
}

/* Clear file sema. This function is called
 * when page fault exception occurs. */
void clear_vm_file_sema(void) {
  struct thread *curr = thread_current();
  if (load_lock.holder == curr) {
    lock_release(&load_lock);
  }
}

/* Get file_page struct. */
struct file_page *get_file_page(struct page *page) {
  ASSERT(page_get_type(page) == VM_FILE)
  if (page->operations->type == VM_FILE) {
    return &page->file;
  }
  return page->uninit.aux;
}

/* Called in supplemental table copy. */
void file_swap_table_push(size_t slot, struct page *page) {
  ASSERT(slot <= MAX_SLOTS);
  ASSERT(slot != SLOT_INIT);
  return swap_table_push(slot, page);
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
  bool succ;
  // TODO: lock?
  lock_acquire(&load_lock);
  succ = do_file_io(page, head, filesys_read);
  lock_release(&load_lock);

  return succ;
}

/* Write back all file-backed pages starting from head-page. */
static void file_write_back_all(struct page *head) {
  struct thread *curr = thread_current();

  void *p = head->va;
  void *map_addr = head->va;
  struct page *page = head;

  while (page && get_file_page(page)->map_addr == map_addr) {
    if (!pg_present(page)) {
      /* Clearing uninit page will be handled by uninit_destroy.
       * If swap-out page, no need to write back.
       * Just go to next loop. */
      p += PGSIZE;
      page = spt_find_page(&curr->spt, p);
      continue;
    }

    /* Write back to file. */
    file_write_back(page, head);

    p += PGSIZE;
    page = spt_find_page(&curr->spt, p);
  }

  /* Close file. */
  filesys_close(get_file_page(head)->file);
}

/* Write back a single page to file. Called when unmap. */
static bool file_write_back(struct page *page, struct page *head) {
  ASSERT(page->operations->type == VM_FILE)
  struct thread *curr = thread_current();

  /* If page is present and not dirty, return. */
  if (!pml4_is_dirty(curr->pml4, page->va)) {
    return true;
  }

  /* Write back to file. */
  if (!do_file_io(page, head, filesys_write)) {
    printf("Fail to write back file.\n");
    return false;
  }
  return true;
}

/* Calculate page offset in mapped area
 * and execute func handed by argument. */
static bool do_file_io(struct page *page, struct page *head, file_io func) {
  struct file *file = head->file.file;
  off_t offset = page->file.offset;
  size_t length = page->file.length;
  void *map_addr = page->file.map_addr;
  void *kva = page->frame->kva;

  ASSERT(page->frame && kva)

  /* Calculate page offset. Starts from 1. */
  off_t page_offset = (page->va - map_addr) / PGSIZE;

  /* Calculate read-write-start point. */
  off_t start = offset + page_offset * PGSIZE;

  /* Calculate read-write-bytes. */
  filesys_seek(file, start);

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

  off_t file_left = filesys_length(file) - file->pos;
  size_t bytes = (offset + length) - start;
  bytes = bytes < PGSIZE ? bytes : PGSIZE;
  bytes = bytes < file_left ? bytes : file_left;

  /* Do func. */
  if (func(file, kva, bytes) != (int)bytes) {
    return false;
  }
  return true;
}

/* Get head page of this mapping. */
static struct page *spt_get_head(struct page *page) {
  struct thread *curr = thread_current();

  /* Get file page struct. */
  struct file_page *file_page = get_file_page(page);

  if (is_file_head(page, file_page)) {
    return page;
  }
  return spt_find_page(&curr->spt, file_page->map_addr);
}

/* Find free disk slot. */
static size_t allocate_slot() {
  lock_acquire(&slot_lock);
  size_t slot = bitmap_scan_and_flip(swap_slot, 0, 1, false);
  lock_release(&slot_lock);
  return slot;
}

/* Mark as free slot. */
static void free_slot(size_t slot) {
  lock_acquire(&slot_lock);
  bitmap_set(swap_slot, slot, false);
  lock_release(&slot_lock);
}

/* Push front into swap table. */
static void swap_table_push(size_t slot, struct page *page) {
  ASSERT(slot < MAX_SLOTS);
  lock_acquire(&slot_lock);
  struct page *curr = swap_table[slot];
  page->next_swap = curr;
  swap_table[slot] = page;
  lock_release(&slot_lock);
}

/* Pop front from swap table. */
static struct page *swap_table_pop(size_t slot) {
  ASSERT(slot < MAX_SLOTS);
  lock_acquire(&slot_lock);
  /* Returns NULL if table is empty. */
  struct page *top = swap_table[slot];
  if (top != NULL) {
    swap_table[slot] = top->next_swap;
    top->next_swap = NULL;
  }
  lock_release(&slot_lock);
  return top;
}

/* Returns if swap table is empty. */
static bool swap_table_empty(size_t slot) {
  ASSERT(slot < MAX_SLOTS)
  bool rtn;
  lock_acquire(&slot_lock);
  rtn = (swap_table[slot] == NULL);
  lock_release(&slot_lock);
  return rtn;
}

/* Remove page from swap table. */
static struct page *swap_table_remove(size_t slot, struct page *page) {
  ASSERT(slot != SLOT_INIT);

  lock_acquire(&slot_lock);
  struct page *before = swap_table[slot];
  if (before == page) {
    lock_release(&slot_lock);
    return swap_table_pop(slot);
  }

  while (before->next_swap != page) {
    before = before->next_swap;
    if (before == NULL) {
      /* Page is not found. */
      lock_release(&slot_lock);
      return NULL;
    }
  }
  before->next_swap = page->next_swap;
  lock_release(&slot_lock);
  return page;
}