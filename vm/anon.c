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
static struct bitmap *swap_table;
#define SEC_PER_PAGE 8
#define DISK_SEC 512

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
  disk_sector_t capacity = disk_size(swap_disk);
  swap_table = bitmap_create(capacity / SEC_PER_PAGE);
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
  /* Set up the handler */
  page->operations = &anon_ops;
  struct anon_page *anon_page = &page->anon;

  *anon_page = (struct anon_page){
      .disk_sec = 0,
  };
  return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool anon_swap_in(struct page *page, void *kva) {
  struct anon_page *anon_page = &page->anon;
  disk_sector_t sector = anon_page->disk_sec;

  /* Read from disk_sec */
  int i = 0;
  for (; i < SEC_PER_PAGE; i++) {
    disk_read(swap_disk, sector + i, kva + (i * DISK_SEC));
  }

  /* Mark as free sector. */
  bitmap_set(swap_table, sector / SEC_PER_PAGE, false);

  /* Install page in pml4. */
  page->flags = page->flags | PTE_P;
  if(!install_page(page)) {
    return false;
  }

  return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool anon_swap_out(struct page *page) {
  ASSERT(page->frame && page->frame->kva)
  struct thread *curr = thread_current();
  struct anon_page *anon_page = &page->anon;
  void* kva = page->frame->kva;

  /* Find free disk sector */
  // TODO: size_t 와 disk_sector_t이 크기가 다름.
  size_t disk_sec = bitmap_scan(swap_table, 0, 1, false);
  if (disk_sec == BITMAP_ERROR) {
    return false;
  }
  
  /* Write to swap disk. */
  disk_sec *= SEC_PER_PAGE;
  int i = 0;
  for (; i < SEC_PER_PAGE; i++) {
    disk_write(swap_disk, disk_sec + i, kva + (i * DISK_SEC));
  }
  
  /* Mark as used sector. */
  bitmap_set(swap_table, disk_sec / SEC_PER_PAGE, true);
  anon_page->disk_sec = (disk_sector_t)disk_sec;

  page->frame = NULL;
  pml4_clear_page(curr->pml4, page->va);
  page->flags = page->flags & ~PTE_P;
  return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void anon_destroy(struct page *page) {
  struct thread *curr = thread_current();
  
  /* Clear up if frame-mapped page. */
  if (pg_present(page)) {
    pml4_clear_page(curr->pml4, page->va);
    palloc_free_page(page->frame->kva);
    free(page->frame);
  }
  return;
}
