/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */


#include <bitmap.h>
#include <stdio.h>

#include "devices/disk.h"
#include "vm/vm.h"
#include "vm/anon.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

/* Swap table. */
static struct bitmap *swap_slot;
static struct page **swap_table;

#define MAX_DISK_SLOT 32768
#define SEC_PER_PAGE 8
#define DISK_SEC 512

/* Disk read & write func type. */
typedef (*disk_oper)(struct disk *, disk_sector_t, const void *);

/* Semaphore for sector allocation. */
static struct lock slot_lock;

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

/* Do read or write to swap disk from SECTOR
 * for NUM consecutive sectors. */
static bool do_disk_io(disk_sector_t sector, size_t num, const void *kva,
                       disk_oper func) {
  int i = 0;
  for (; i < num; i++) {
    func(swap_disk, sector + i, kva + (i * DISK_SEC));
  }
}

/* Push front into swap table. */
static void swap_table_push(size_t slot, struct page *page) {
  ASSERT(slot < MAX_DISK_SLOT)
  lock_acquire(&slot_lock);
  struct page *curr = swap_table[slot];
  page->next_swap = curr;
  swap_table[slot] = page;
  lock_release(&slot_lock);
}

/* Pop front from swap table. */
static struct page *swap_table_pop(size_t slot) {
  ASSERT(slot < MAX_DISK_SLOT)
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
  ASSERT(slot < MAX_DISK_SLOT)
  return (swap_table[slot] == NULL);
}

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
    .swap_in = anon_swap_in,
    .swap_out = anon_swap_out,
    .destroy = anon_destroy,
    .type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void) {
  /* Set up the swap_disk. */
  swap_disk = disk_get(1, 1);

  /* Calculate disk size. */
  size_t slots = disk_size(swap_disk) / SEC_PER_PAGE;
  slots = MAX_DISK_SLOT < slots ? MAX_DISK_SLOT : slots;

  /* Create swap slot table. */
  swap_slot = bitmap_create(slots);

  /* Create swap page table. */
  size_t page_cnt = (slots * sizeof(struct page *)) / 0x1000;
  swap_table = palloc_get_multiple(PAL_ZERO, page_cnt);

  /* Initialize anon sema. */
  lock_init(&slot_lock);
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
  /* Set up the handler */
  page->operations = &anon_ops;
  struct anon_page *anon_page = &page->anon;

  *anon_page = (struct anon_page){
      .disk_slot = -1,
  };
  return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool anon_swap_in(struct page *page, void *kva) {
  ASSERT(page_get_type(page) == VM_ANON)

  struct frame *frame = page->frame;
  ASSERT(frame && kva)

  size_t slot = page->anon.disk_slot;
  if ((long)slot < 0) {
    /* If page was never swapped out, just install. */
    list_push_back(&frame->pages, &page->frame_elem);
    return vm_install_page(page, page->thread);
  }

  /* Read from disk_sec */
  disk_sector_t sec = slot * SEC_PER_PAGE;
  do_disk_io(sec, SEC_PER_PAGE, kva, disk_read);

  while (!swap_table_empty(slot)) {
    page = swap_table_pop(slot);
    ASSERT(page != NULL);

    /* Link with frame. */
    page->frame = frame;
    page->flags = page->flags | PTE_P;
    vm_install_page(page, page->thread);
    list_push_back(&frame->pages, &page->frame_elem);

    /* Unlink with disk slot. */
    page->anon.disk_slot = -1;
  }

  /* Mark as free sector. */
  free_slot(slot);

  return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool anon_swap_out(struct page *page) {
  struct frame *frame = page->frame;
  void *kva = page->frame->kva;
  ASSERT(frame && kva)

  /* Find free disk sector */
  size_t slot = allocate_slot();
  if (slot == BITMAP_ERROR) {
    return false;
  }

  /* Write to swap disk. */
  disk_sector_t sec = slot * SEC_PER_PAGE;
  do_disk_io(sec, SEC_PER_PAGE, kva, disk_write);

  /* Mark as used sector. */
  struct thread *t;
  struct page *prev;
  struct list_elem *front;
  while (!list_empty(&frame->pages)) {
    front = list_pop_front(&frame->pages);
    page = list_entry(front, struct page, frame_elem);
    t = page->thread;

    /* Unlink with frame. */
    page->frame = NULL;
    pml4_clear_page(t->pml4, page->va);
    page->flags = page->flags & ~PTE_P;

    /* Link with disk slot. */
    page->anon.disk_slot = slot;
    swap_table_push(slot, page);
    ASSERT(!swap_table_empty(slot));
  }

  return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void anon_destroy(struct page *page) {
  if (!pg_present(page)) {
    return;
  }

  struct thread *t = page->thread;
  pml4_clear_page(t->pml4, page->va);

  struct frame *frame = page->frame;
  list_remove(&page->frame_elem);

  /* If page is the last, free frame. */
  if (list_empty(&frame->pages)) {
    palloc_free_page(page->frame->kva);
    free(page->frame);
  }
  /* Clear up if frame-mapped page. */
  //   if (pg_present(page)) {
  //     pml4_clear_page(curr->pml4, page->va);
  //     if (!pg_copy_on_write(page)) {
  //       palloc_free_page(page->frame->kva);
  //       free(page->frame);
  //     }
  //   }

  return;
}
