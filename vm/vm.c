/* vm.c: Generic interface for virtual memory objects. */
#include "vm/vm.h"

#include <stdio.h>

#include "threads/malloc.h"
#include "threads/pte.h"
#include "threads/vaddr.h"
#include "vm/inspect.h"

static uint64_t spt_hash_func(const struct hash_elem *, void *);
static bool spt_hash_less_func(const struct hash_elem *,
                               const struct hash_elem *, void *);
static void spt_free_page(struct hash_elem *, void *);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void) {
  vm_anon_init();
  vm_file_init();
#ifdef EFILESYS /* For project 4 */
  pagecache_init();
#endif
  register_inspect_intr();
  /* DO NOT MODIFY UPPER LINES. */
  /* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page *page) {
  int ty = VM_TYPE(page->operations->type);
  switch (ty) {
    case VM_UNINIT:
      return VM_TYPE(page->uninit.type);
    default:
      return ty;
  }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux) {
  ASSERT(VM_TYPE(type) != VM_UNINIT)

  struct supplemental_page_table *spt = &thread_current()->spt;
  struct page *page = calloc(1, sizeof(struct page));

  /* Check wheter the upage is already occupied or not. */
  if (spt_find_page(spt, upage) == NULL) {
    /* If upage is stack bottom, claim immediately. */
    // if (upage == spt->stack_bottom) {
    //   uninit_new(page, upage, init, type, aux, anon_initializer);
    //   return vm_do_claim_page(page);
    // }

    /* If upage is not a stack. */
    switch (type) {
      case VM_ANON:
        uninit_new(page, upage, init, type, aux, anon_initializer);
        break;
      case VM_FILE:
        uninit_new(page, upage, init, type, aux, file_backed_initializer);
        break;
      default:
        break;
    }

    /* Fill extra fields. */
    /* If page is writable. */
    if (writable) {
      page->flags = page->flags | PTE_W;
    }
    if (!spt_insert_page(spt, page)) {
      printf("vm.c:75 spt insert failed\n");
      goto err;
    }
    /* 만약 스택 페이지이면 즉시 claim */
    if(upage == spt->stack_bottom) {
        return vm_do_claim_page(page);
    }
    return true;
  }
err:
  return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt, void *va) {
  struct hash_elem *spt_elem;
  struct page *page = NULL;
  struct page tmp;

  /* align */
  tmp.va = pg_round_down(va);

  spt_elem = hash_find(&spt->hash, &tmp.elem);
  if (spt_elem == NULL) {
    return NULL;
  }

  page = hash_entry(spt_elem, struct page, elem);

  return page;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page) {
  int succ = false;

  /* Function hash_insert returns old hash elem. */
  hash_insert(&spt->hash, &page->elem);

  succ = true;
  return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
  hash_delete(&spt->hash, &page->elem);
  vm_dealloc_page(page);
  return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void) {
  struct frame *victim = NULL;
  /* TODO: The policy for eviction is up to you. */

  return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void) {
  struct frame *victim UNUSED = vm_get_victim();
  /* TODO: swap out the victim and return the evicted frame. */

  return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space. */
static struct frame *vm_get_frame(void) {
  struct frame *frame = NULL;
  frame = calloc(1, sizeof(struct frame));
  if (frame == NULL) {
    printf("Frame allocation failed.\n");
    return NULL;
  }

  frame->kva = palloc_get_page(PAL_USER | PAL_ZERO | PAL_ASSERT);
  if (frame->kva == NULL) {
    free(frame);
    printf("Memory is full.\n");
  }

  ASSERT(frame != NULL);
  ASSERT(frame->page == NULL);
  return frame;
}

/* Growing the stack. */
static bool vm_stack_growth(void *addr UNUSED) {
    // do_claim
    // pml4 연결
    
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {}

/* Page Fault Handler: Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
                         bool write, bool not_present) {
  struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
  struct page *page = spt_find_page(spt, addr);

  /* TODO: Your code goes here */
  if (page == NULL) {
    // printf("🔥 fault addr: %p\n", addr);
    // printf("🔥 stack bottom: %p\n", (void *)(((uint8_t *)USER_STACK) -
    // PGSIZE));
    return false;
  }
  return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
  destroy(page);
  free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED) {
  struct page *page = NULL;
  /* TODO: Fill this function */

  return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page *page) {
  struct frame *frame = vm_get_frame();
  enum vm_type type = page_get_type(page);

  /* Set links */
  frame->page = page;
  page->frame = frame;

  /* Initialize page */
  return swap_in(page, frame->kva);
}

/* SPT - Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt) {
  spt->stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);
  if (!hash_init(&spt->hash, spt_hash_func, spt_hash_less_func, NULL)) {
    PANIC("spt not initialized!\n");
  }
  return;
}

/* SPT - Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED) {}

/* SPT - Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt) {
  /* TODO: Destroy all the supplemental_page_table hold by thread and
   * TODO: writeback all the modified contents to the storage. */
  /* TODO: swap in/out or file-mapped by mmap - writeback. */
  /* SPT - writeback. */
  if (spt) hash_destroy(&spt->hash, spt_free_page);
  //   hash_init(&spt->hash, spt_hash_func, spt_hash_less_func, NULL);
  return;
}

static uint64_t spt_hash_func(const struct hash_elem *e, void *aux UNUSED) {
  struct page *page = hash_entry(e, struct page, elem);
  return hash_bytes(&page->va, sizeof(page->va));
}

static bool spt_hash_less_func(const struct hash_elem *_a,
                               const struct hash_elem *_b, void *aux UNUSED) {
  struct page *a = hash_entry(_a, struct page, elem);
  struct page *b = hash_entry(_b, struct page, elem);
  return (uint64_t)a->va < (uint64_t)b->va;
}

static void spt_free_page(struct hash_elem *e, void *aux UNUSED) {
  struct page *page = hash_entry(e, struct page, elem);
  if (page) free(page);
}