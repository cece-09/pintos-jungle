/* vm.c: Generic interface for virtual memory objects. */
#include "vm/vm.h"

#include <stdio.h>
#include <string.h>

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/pte.h"
#include "threads/vaddr.h"
#include "vm/inspect.h"

static uint64_t spt_hash_func(const struct hash_elem *, void *);
static bool spt_hash_less_func(const struct hash_elem *,
                               const struct hash_elem *, void *);
static void spt_free_page(struct hash_elem *, void *);
static void spt_copy_page(struct hash_elem *, void *);

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

/* Install page in current thread's pml4. */
bool install_page(struct page *page) {
  struct thread *curr = thread_current();
  bool writable = pg_writable(page);
  void *kva = page->frame->kva;
  ASSERT(page && kva)

  bool success = false;

  if (pml4_get_page(curr->pml4, page->va) != NULL) {
    printf("evict the page?\n");
    return false;
  }
  if(!pml4_set_page(curr->pml4, page->va, kva, writable)) {
    return false;
  }
  return true;
}

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux) {
  ASSERT(VM_TYPE(type) != VM_UNINIT)
  ASSERT(((uint64_t)upage % PGSIZE) == 0)

  struct supplemental_page_table *spt = &thread_current()->spt;
  struct page *page = NULL;

  /* Check wheter the upage is already occupied or not. */
  if (spt_find_page(spt, upage) == NULL) {
    page = calloc(1, sizeof(struct page));
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

    /* If page is writable. */
    if (writable) page->flags = page->flags | PTE_W;

    /* Insert page into spt. */
    if (!spt_insert_page(spt, page)) {
      printf("vm.c:75 spt insert failed\n");
      goto err;
    }

    /* If stack page, claim immediately. */
    if (upage == spt->stack_bottom) {
      if (!vm_do_claim_page(page)) goto err;
    }
    return true;
  }
err:
  if (page) vm_dealloc_page(page);
  return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt, void *va) {
  struct hash_elem *spt_elem;
  struct page *page = NULL;
  struct page tmp;

  /* Align to page size. */
  tmp.va = pg_round_down(va);
  spt_elem = hash_find(&spt->hash, &tmp.elem);
  if (spt_elem == NULL) return NULL;

  page = hash_entry(spt_elem, struct page, elem);
  return page;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page) {
  int succ = false;

  /* Function hash_insert returns old hash elem. */
  if (!hash_insert(&spt->hash, &page->elem)) {
    succ = true;
  }

  return succ;
}

/* Remove page in spt. */
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

  /* Get anonymous frame. */
  frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);
  if (frame->kva == NULL) {
    free(frame);
    printf("Memory is full.\n");
    return NULL;
  }

  ASSERT(frame != NULL);
  ASSERT(frame->page == NULL);
  return frame;
}

/* Growing the stack. */
static bool vm_stack_growth(void *addr) {
  /* If addr exceeds STACK_LIMIT, return false. */
  if (addr <= STACK_LIMIT) {
    return false;
  }

  struct supplemental_page_table *spt = &thread_current()->spt;
  spt->stack_bottom = addr;
  return vm_alloc_page(VM_ANON, addr, true);
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {}

/* Page Fault Handler: Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
                         bool write, bool not_present) {
  struct supplemental_page_table *spt = &thread_current()->spt;
  void *upage = pg_round_down(addr);
  void *curr_rsp = (void *)f->rsp;

  /* Validate stack overflow. */
  if (STACK_LIMIT < addr && addr < spt->stack_bottom) {
    /* If current stack is not full, not a stack overflow. */
    if (curr_rsp != addr) return false;
    /* If stack overflow */
    return vm_stack_growth(upage);
  }

  printf("@@ fault: %p, try to %s\n", addr, write ? "write" : "read");

  /* Else, search for page in spt. */
  struct page *page = spt_find_page(spt, addr);
  if (page == NULL) {
    printf("@@ page not found.\n");
    return false;
  }


  /* If page is unwritable, return false. */
  if (write && !pg_writable(page)) {
    /* TODO: handle copy-on-write. */
    printf("@@ try to access write protect page\n");
    return false;
  }

  /* Else, lazy loading. */
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

  /* Mark as present */
  page->flags = page->flags | PTE_P;

  printf("@@ do claim: %p %d\n", frame->kva, type);

  /* Initialize page */
  return swap_in(page, frame->kva);
}

/* SPT - Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt) {
  /* Set stack bottom. */
  spt->stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

  /* Initialize hash table. */
  if (!hash_init(&spt->hash, spt_hash_func, spt_hash_less_func, NULL)) {
    PANIC("spt not initialized!\n");
  }
  return;
}

/* SPT - Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dsc,
                                  struct supplemental_page_table *src) {
  /* Copy stack bottom. */
  dsc->stack_bottom = src->stack_bottom;

  /* Copy hash table. */
  src->hash.aux = dsc;
  hash_apply(&src->hash, spt_copy_page);
  src->hash.aux = NULL;
  return true;
}

/* SPT - Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt) {
  /* TODO: Destroy all the supplemental_page_table hold by thread and
   * TODO: writeback all the modified contents to the storage. */
  /* TODO: swap in/out or file-mapped by mmap - writeback. */

  /* SPT - writeback. */
  if (spt) hash_destroy(&spt->hash, spt_free_page);
  return;
}

/* SPT - Hash hash function: use hash bytes. */
static uint64_t spt_hash_func(const struct hash_elem *e, void *aux UNUSED) {
  struct page *page = hash_entry(e, struct page, elem);
  return hash_bytes(&page->va, sizeof(page->va));
}

/* SPT - Hash less function: according to va. */
static bool spt_hash_less_func(const struct hash_elem *_a,
                               const struct hash_elem *_b, void *aux UNUSED) {
  struct page *a = hash_entry(_a, struct page, elem);
  struct page *b = hash_entry(_b, struct page, elem);
  return (uint64_t)a->va < (uint64_t)b->va;
}

/* SPT -  Hash action function: free page struct. */
static void spt_free_page(struct hash_elem *e, void *aux UNUSED) {
  struct page *page = hash_entry(e, struct page, elem);
  if (page) vm_dealloc_page(page);
}

/* SPT - Hash action function: copy a single page. */
static void spt_copy_page(struct hash_elem *e, void *aux) {
  struct supplemental_page_table *dsc_spt =
      (struct supplemental_page_table *)aux;
  struct hash *dsc_hash = &dsc_spt->hash;
  struct page *src_page = hash_entry(e, struct page, elem);

  /* Copy spt entries. */
  struct page *dsc_page = calloc(1, sizeof(struct page));
  memcpy(dsc_page, src_page, sizeof(struct page));
  hash_insert(dsc_hash, &dsc_page->elem);

  /* If uninitialized segement page, copy file info. */
  struct file_info *dsc_aux;
  struct file_info *src_aux = (struct file_info *)src_page->uninit.aux;
  if (dsc_page->va < dsc_spt->stack_bottom && !pg_present(dsc_page)) {
    dsc_aux = calloc(1, sizeof(struct file_info));
    dsc_aux->ofs = src_aux->ofs;
    dsc_aux->bytes = src_aux->bytes;
    dsc_page->uninit.aux = dsc_aux;
  }

  /* Claim page if present. */
  if (pg_present(dsc_page)) {
    // TODO: handle copy-on-write.
    struct frame *dsc_frame = vm_get_frame();
    ASSERT(src_page->frame->kva)
    ASSERT(dsc_page->frame->kva)

    dsc_page->frame = dsc_frame;
    dsc_frame->page = dsc_page;
    memcpy(dsc_page->frame->kva, src_page->frame->kva, PGSIZE);

    install_page(dsc_page);
  }
}