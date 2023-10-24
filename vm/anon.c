/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include <bitmap.h>
#include <stdio.h>

#include "devices/disk.h"
#include "vm/vm.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

/* Swap table. */
#define DISK_SEC 512
#define SEC_PER_PAGE 8
#define MAX_SLOTS 32768
#define SLOT_INIT (size_t)(-1)

static struct bitmap *swap_slot;
static struct page **swap_table;

/* Semaphore for sector allocation. */
static struct lock slot_lock;

/* Disk read & write func type. */
typedef void (*disk_io)(struct disk *, disk_sector_t, const void *);

/* === Helpers. === */
static size_t allocate_slot();
static void free_slot(size_t slot);
static bool swap_table_empty(size_t slot);
static struct page *swap_table_pop(size_t slot);
static void swap_table_push(size_t slot, struct page *page);
static struct page *swap_table_remove(size_t slot, struct page *page);
static bool do_disk_io(disk_sector_t sector, size_t num, const void *kva,
                       disk_io func);

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
  slots = MAX_SLOTS < slots ? MAX_SLOTS : slots;

  /* Create swap slot table. */
  swap_slot = bitmap_create(slots);

  /* Create swap page table. */
  size_t page_cnt = (slots * sizeof(struct page *)) / 0x1000;
  swap_table = palloc_get_multiple(PAL_ZERO, page_cnt);

  /* Initialize locks. */
  lock_init(&slot_lock);
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
  /* Set up the handler */
  page->operations = &anon_ops;
  struct anon_page *anon_page = &page->anon;

  *anon_page = (struct anon_page){
      .slot = SLOT_INIT,
  };
  return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool anon_swap_in(struct page *page, void *kva) {
  ASSERT(page_get_type(page) == VM_ANON)

  struct frame *frame = page->frame;
  ASSERT(frame && kva)

  size_t slot = page->anon.slot;
  if (slot == SLOT_INIT) {
    /* If page was never swapped out, just install. */
    vm_map_frame(page, frame);
    return vm_install_page(page, page->thread);
  }

  /* Read from disk_sec */
  disk_sector_t sec = slot * SEC_PER_PAGE;
  do_disk_io(sec, SEC_PER_PAGE, kva, disk_read);

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

/* Swap out the page by writing contents to the swap disk. */
static bool anon_swap_out(struct page *page) {
  struct frame *frame = page->frame;
  void *kva = page->frame->kva;
  ASSERT(frame && kva)


  /* Find free disk sector */
  size_t slot = allocate_slot();
  if (slot == BITMAP_ERROR) {
    printf("Swap disk out of memory.\n");
    return false;
  }

  /* Write to swap disk. */
  disk_sector_t sec = slot * SEC_PER_PAGE;
  do_disk_io(sec, SEC_PER_PAGE, kva, disk_write);

  /* Clear all linked pages. */
  struct thread *t;
  while (!page_stack_empty(&frame->stack)) {
    page = page_stack_pop(&frame->stack);
    t = page->thread;

    /* Unlink with frame. */
    page->frame = NULL;
    page->flags = page->flags & ~PTE_P;
    pml4_set_accessed(t->pml4, page->va, false);
    pml4_clear_page(t->pml4, page->va);

    /* Link with disk slot. */
    page->anon.slot = slot;
    swap_table_push(slot, page);
    ASSERT(!swap_table_empty(slot));
  }

  return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void anon_destroy(struct page *page) {
  /* If page is swapped out */
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

  /* Unlink with current frame. */
  struct frame* frame = page->frame;
  vm_unmap_frame(page);

  /* If page is the last, free frame. */
  if (!vm_get_page_ref(frame)) {
    palloc_free_page(frame->kva);
    free(frame);
  }

  return;
}

/* Called in supplemental table copy. */
void anon_swap_table_push(size_t slot, struct page *page) {
  ASSERT(slot <= MAX_SLOTS);
  ASSERT(slot != SLOT_INIT);
  return swap_table_push(slot, page);
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

/* Do read or write to swap disk from SECTOR
 * for NUM consecutive sectors. */
static bool do_disk_io(disk_sector_t sector, size_t num, const void *kva,
                       disk_io func) {

  int i = 0;
  for (; i < num; i++) {
    func(swap_disk, sector + i, kva + (i * DISK_SEC));
  }
}

/* Push front into swap table. */
static void swap_table_push(size_t slot, struct page *page) {
  ASSERT(slot < MAX_SLOTS);
  lock_acquire(&slot_lock);
  page_stack_push(&swap_table[slot], page);
  lock_release(&slot_lock);
}

/* Pop front from swap table. */
static struct page *swap_table_pop(size_t slot) {
  ASSERT(slot < MAX_SLOTS);
  struct page *top;
  lock_acquire(&slot_lock);
  top = page_stack_pop(&swap_table[slot]);
  lock_release(&slot_lock);
  return top;
}

/* Returns if swap table is empty. */
static bool swap_table_empty(size_t slot) {
  ASSERT(slot < MAX_SLOTS)
  bool rtn;
  lock_acquire(&slot_lock);
  rtn = page_stack_empty(&swap_table[slot]);
  lock_release(&slot_lock);
  return rtn;
}

/* Remove page from swap table. */
static struct page *swap_table_remove(size_t slot, struct page *page) {
  ASSERT(slot != SLOT_INIT);
  
  struct page *remove;
  lock_acquire(&slot_lock);
  remove = page_stack_remove(&swap_table[slot], page);
  lock_release(&slot_lock);
  return remove;
}