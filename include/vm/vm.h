#ifndef VM_VM_H
#define VM_VM_H

#include <hash.h>
#include <stdbool.h>

#include "threads/palloc.h"
#include "threads/mmu.h"
#include "threads/pte.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

enum vm_type {
  /* page not initialized */
  VM_UNINIT = 0,
  /* page not related to the file, aka anonymous page */
  VM_ANON = 1,
  /* page that realated to the file */
  VM_FILE = 2,
  /* page that hold the page cache, for project 4 */
  VM_PAGE_CACHE = 3,

  /* Bit flags to store state */

  /* Auxillary bit flag marker for store information. You can add more
   * markers, until the value is fit in the int. */
  VM_MARKER_0 = (1 << 3),
  VM_MARKER_1 = (1 << 4),

  /* DO NOT EXCEED THIS VALUE. */
  VM_MARKER_END = (1 << 31),
};

#include "vm/uninit.h"
#include "vm/anon.h"
#include "vm/file.h"
#ifdef EFILESYS
#include "filesys/page_cache.h"
#endif

struct page_operations;
struct thread;

#define VM_TYPE(type) ((type) & 7)
#define PG_COW 0x80
#define PG_INIT 0x100

/* Check page flag bits. */
#define pg_writable(page) ((page->flags & PTE_W ) != 0)
#define pg_present(page) ((page->flags & PTE_P ) != 0)
#define pg_copy_on_write(page) ((page->flags & PG_COW ) != 0)
#define pg_init(page) ((page->flags & PG_INIT ) != 0)

/* Absolute stack limit. */
#define STACK_LIMIT (USER_STACK - (1 << 20))

/* The representation of "page".
 * This is kind of "parent class", which has four "child class"es, which are
 * uninit_page, file_page, anon_page, and page cache (project4).
 * DO NOT REMOVE/MODIFY PREDEFINED MEMBER OF THIS STRUCTURE. */
struct page {
  const struct page_operations *operations;
  void *va;            /* Address in terms of user space */
  struct frame *frame; /* Back reference for frame */

  struct hash_elem table_elem; /* Hash elem for spt. */
  struct list_elem frame_elem; /* List elem for frame-mapping. */

  struct page* next_swap;      /* Singly lisked list for swap-table. */
  struct thread* thread;       /* Thread info. */
  uint16_t flags;              /* Flags. */
  
  /* Per-type data are binded into the union.
   * Each function automatically detects the current union */
  union {
    struct uninit_page uninit;
    struct anon_page anon;
    struct file_page file;
#ifdef EFILESYS
    struct page_cache page_cache;
#endif
  };
};

/* The representation of "frame" */
struct frame {
  void *kva;             /* Kernel virtual address */
  struct list pages;     /* List of mapped pages. */
  uint32_t page_cnt;     /* Count of mapped pages. */
  struct list_elem elem; /* List elem for frame table.*/
};

/* The function table for page operations.
 * This is one way of implementing "interface" in C.
 * Put the table of "method" into the struct's member, and
 * call it whenever you needed. */
struct page_operations {
  bool (*swap_in)(struct page *, void *);
  bool (*swap_out)(struct page *);
  void (*destroy)(struct page *);
  enum vm_type type;
};

#define swap_in(page, v) (page)->operations->swap_in((page), v)
#define swap_out(page) (page)->operations->swap_out(page)
#define destroy(page) \
  if ((page)->operations->destroy) (page)->operations->destroy(page)

/* Representation of current process's memory space.
 * We don't want to force you to obey any specific design for this struct.
 * All designs up to you for this. */
struct supplemental_page_table {
  /* SPT - Use hash table. */
  void* stack_bottom;
  struct hash hash;
};

/* Exec file info for loading segment. */
struct file_info {
  struct file* file;
  off_t ofs;
  size_t bytes;
};


#include "threads/thread.h"
void supplemental_page_table_init(struct supplemental_page_table *spt);
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src);
void supplemental_page_table_kill(struct supplemental_page_table *spt);
struct page *spt_find_page(struct supplemental_page_table *spt, void *va);
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page);
void spt_remove_page(struct supplemental_page_table *spt, struct page *page);

void vm_init(void);
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
                         bool write, bool not_present);

#define vm_alloc_page(type, upage, writable) \
  vm_alloc_page_with_initializer((type), (upage), (writable), NULL, NULL)
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux);
void vm_dealloc_page(struct page *page);
bool vm_claim_page(void *va);
enum vm_type page_get_type(struct page *page);

/* New functions. */
void clear_vm_file_sema(void);
bool vm_handle_wp(struct page *page);
void vm_clear_frame_pages(struct page *page);
bool vm_install_page(struct page *page, struct thread* t);

void vm_unmap_frame(struct page *page);
void vm_map_frame(struct page *page, struct frame* frame);

#endif /* VM_VM_H */
