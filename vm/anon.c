/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include <stdio.h>
#include <bitmap.h>

#include "devices/disk.h"
#include "vm/vm.h"
#include "vm/anon.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

/* Swap table. */
static struct bitmap *swap_table; // disk sector 기록용
#define SWAP_BITS 4096
#define DISK_SEC_BYTE 512


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
  swap_table = bitmap_create(SWAP_BITS);
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
  
  /* Read from disk_sec */
  for(int i = 0; i < (PGSIZE / DISK_SEC_BYTE); i++) {
    disk_read(swap_disk, anon_page->disk_sec+i, kva + (i * DISK_SEC_BYTE));
  }

  bitmap_set(swap_table, anon_page->disk_sec / (PGSIZE / DISK_SEC_BYTE), false);
  
  /* Install page in pml4. */
  install_page(page);
  page->flags = page->flags | PTE_P;

  return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool anon_swap_out(struct page *page) {
  ASSERT(page->frame && page->frame->kva)
  struct thread* curr = thread_current();

  struct anon_page *anon_page = &page->anon;

  /* Find free disk sector */
  // TODO: size_t 와 disk_sector_t이 크기가 다름.
  size_t disk_sec = bitmap_scan(swap_table, 0, 1, false);
  disk_sec *=  (PGSIZE / DISK_SEC_BYTE);

  for(int i = 0; i < (PGSIZE / DISK_SEC_BYTE); i++) {
      disk_write(swap_disk, disk_sec+i, page->frame->kva  + (i * DISK_SEC_BYTE));
  }

  bitmap_set(swap_table, disk_sec / (PGSIZE / DISK_SEC_BYTE), true);
  anon_page->disk_sec =  (disk_sector_t)disk_sec;

  page->frame = NULL;
  pml4_clear_page(curr->pml4, page->va);
  page->flags = page->flags & ~PTE_P;

  // TODO: 예외처리
  return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void anon_destroy(struct page *page) {
  struct anon_page *anon_page = &page->anon;
  if(page->frame) free(page->frame);
  return;
}
