/* vm.c: Generic interface for virtual memory objects. */
#include "vm/vm.h"

#include <stdio.h>
#include <string.h>

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/pte.h"
#include "threads/vaddr.h"
#include "vm/inspect.h"

static struct semaphore fault_sema;
static void spt_free_page(struct hash_elem *, void *);
static void spt_copy_page(struct hash_elem *, void *);
static uint64_t spt_hash_func(const struct hash_elem *, void *);
static bool spt_hash_less_func(const struct hash_elem *,
                               const struct hash_elem *, void *);

static struct list frame_table;

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

  list_init(&frame_table);
  sema_init(&fault_sema, 1);
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

/* Helpers. */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Install page in current thread's pml4. */
bool vm_install_page(struct page *page, struct thread *t) {
  bool writable = pg_writable(page);
  void *kva = page->frame->kva;
  ASSERT(page && kva)

  // TODO: logic 수정
  return pml4_set_page(t->pml4, page->va, kva, writable);
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
    if (page == NULL) PANIC("Out of memory.\n");

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

    /* Link with current thread. */
    page->thread = thread_current();

    /* Insert page into spt. */
    if (!spt_insert_page(spt, page)) {
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
  spt_elem = hash_find(&spt->hash, &tmp.table_elem);
  if (spt_elem == NULL) return NULL;

  return hash_entry(spt_elem, struct page, table_elem);
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page) {
  /* Function hash_insert returns old hash elem. */
  if (!hash_insert(&spt->hash, &page->table_elem)) {
    return true;
  }
  return false;
}

/* Remove page in spt. */
void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
  hash_delete(&spt->hash, &page->table_elem);
  vm_dealloc_page(page);
  return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void) {
  struct thread *curr = thread_current();

  if (list_empty(&frame_table)) {
    PANIC("No entry in frame table.");
  }

  // TODO: 일단 FIFO
  struct list_elem *next = list_pop_front(&frame_table);
  struct frame *victim = list_entry(next, struct frame, elem);

  //   while (pml4_is_accessed(curr->pml4, victim->page->va)) {
  //     pml4_set_accessed(curr->pml4, victim->page->va, false);
  //     list_push_back(&frame_table, &victim->elem);

  //     /* Next candidate. */
  //     next = list_pop_front(&frame_table);
  //     victim = list_entry(next, struct frame, elem);
  //   }

  return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void) {
  struct frame *victim = vm_get_victim();

  ASSERT(!list_empty(&victim->pages));
  struct list_elem *front = list_front(&victim->pages);
  struct page *page = list_entry(front, struct page, frame_elem);

  /* Remove all pages from frame and
   * push into swap table. */
  if (swap_out(page)) {
    /* After, initialize victim. */
    ASSERT(list_empty(&victim->pages));
    memset(victim->kva, 0, PGSIZE);
    return victim;
  }
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
    /* If out of memory,
     * evict frame from frame table.*/
    frame = vm_evict_frame();
  }

  /* Init page list, push into frame table. */
  list_init(&frame->pages);
  list_push_back(&frame_table, &frame->elem);

  ASSERT(frame != NULL);
  ASSERT(list_empty(&frame->pages));
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
// TODO: uninit page도 handle하게 ?
bool vm_handle_wp(struct page *page) {
  if (!pg_copy_on_write(page)) {
    /* If cow-flag is not on,
     * this page is write-protect page. */
    return false;
  }

  /* Unlink from old frame. */
  struct frame *old_frame = page->frame;
  list_remove(&page->frame_elem);

  /* If this page was the last,
   * Re-link with frame and return. */
  if (list_empty(&old_frame->pages)) {
    page->flags = page->flags & ~PG_COW;
    page->flags = page->flags | PTE_W;
    list_push_back(&old_frame->pages, &page->frame_elem);
    return vm_install_page(page, page->thread);
  }

  /* Link with new frame. */
  struct frame *new_frame;
  /* Copy-on-write pages are all present. */
  if (pg_present(page)) {
    /* Mark as no copy-on-write page. */
    page->flags = page->flags | PTE_W;
    page->flags = page->flags & ~PG_COW;

    if (!vm_do_claim_page(page)) {
      /* If swap-in fails, return false.*/
      return false;
    }

    /* Page is now swapped-in. Copy old frame. */
    new_frame = page->frame;
    memcpy(new_frame->kva, old_frame->kva, PGSIZE);
    return true;
  }
  return false;
}

/* Page Fault Handler: Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
                         bool write, bool not_present) {
  void *upage = pg_round_down(addr);
  struct thread *curr = thread_current();
  struct supplemental_page_table *spt = &curr->spt;
  void *curr_rsp = user ? (void *)f->rsp : curr->user_rsp;

  /* Validate stack growth. */
  if (STACK_LIMIT < addr && addr < spt->stack_bottom) {
    /* If current stack is not full, not a stack growth. */
    if (curr_rsp != addr) return false;
    /* If stack growth */
    return vm_stack_growth(upage);
  }

  /* Else, search for page in spt. */
  struct page *page = spt_find_page(spt, addr);
  if (page == NULL) {
    return false;
  }

  /* If page is write-protect, return handle_wp. */
  if (write && !pg_writable(page)) {
    return vm_handle_wp(page);
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

  /* Set links. Pushing into frame list
   * will be done in each swap-in functions. */
  page->frame = frame;

  /* Mark as present. */
  page->flags = page->flags | PTE_P;

  /* Initialize & install page. */
  return swap_in(page, frame->kva);
}

/* SPT - Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt) {
  /* Set stack bottom. */
  spt->stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

  /* Initialize hash table. */
  if (!hash_init(&spt->hash, spt_hash_func, spt_hash_less_func, NULL)) {
    PANIC("spt not initialized.\n");
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

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt) {
  if (!spt) return;

  /* Write back file_backed_pages first, */
  hash_apply(&spt->hash, spt_file_writeback);

  /* Destroy hash. */
  hash_destroy(&spt->hash, spt_free_page);
  return;
}

/* Hash hash function which uses hash bytes. */
static uint64_t spt_hash_func(const struct hash_elem *e, void *aux UNUSED) {
  struct page *page = hash_entry(e, struct page, table_elem);
  return hash_bytes(&page->va, sizeof(page->va));
}

/* Hash less function. */
static bool spt_hash_less_func(const struct hash_elem *_a,
                               const struct hash_elem *_b, void *aux UNUSED) {
  struct page *a = hash_entry(_a, struct page, table_elem);
  struct page *b = hash_entry(_b, struct page, table_elem);
  return (uint64_t)a->va < (uint64_t)b->va;
}

/* Hash action function which frees page struct. */
static void spt_free_page(struct hash_elem *e, void *aux UNUSED) {
  struct page *page = hash_entry(e, struct page, table_elem);
  if (page) vm_dealloc_page(page);
}

/* Hash action function which copies a single page. */
static void spt_copy_page(struct hash_elem *e, void *aux) {
  struct supplemental_page_table *dsc_spt =
      (struct supplemental_page_table *)aux;
  struct hash *dsc_hash = &dsc_spt->hash;
  struct page *src_page = hash_entry(e, struct page, table_elem);

  /* Copy spt entries. */
  struct page *dsc_page = calloc(1, sizeof(struct page));
  memcpy(dsc_page, src_page, sizeof(struct page));

  /* Deconnect from parent's hash table. */
  memset(&dsc_page->table_elem, 0, sizeof(struct hash_elem));
  memset(&dsc_page->frame_elem, 0, sizeof(struct list_elem));
  hash_insert(dsc_hash, &dsc_page->table_elem);

  /* Set new values. */
  dsc_page->next_swap = NULL;
  dsc_page->thread = thread_current();

  switch (page_get_type(src_page)) {
    case VM_ANON:
      /* Anon-uninitialized pages are segment pages. */
      if (!pg_present(src_page)) {
        struct file_info *src_aux = src_page->uninit.aux;
        struct file_info *dsc_aux = calloc(1, sizeof(struct file_info));
        memcpy(dsc_aux, src_aux, sizeof(struct file_info));
        dsc_page->uninit.aux = dsc_aux;
        return;
      }
      break;
    case VM_FILE:
      if (!pg_present(src_page)) {
        struct file_page *src_aux = src_page->uninit.aux;
        struct file_page *dsc_aux = calloc(1, sizeof(struct file_page));
        memcpy(dsc_aux, src_aux, sizeof(struct file_page));
        dsc_page->uninit.aux = dsc_aux;

        /* If head page of file-backed pages, duplicate file. */
        if (src_page->va == src_aux->map_addr) {
          dsc_aux->file = file_duplicate(src_aux->file);
        }
        return;
      }

      /* If head page of file-backed pages, duplicate file. */
      if (is_file_head(src_page, &src_page->file)) {
        dsc_page->file.file = file_duplicate(src_page->file.file);
      }

    default:
      break;
  }

  /* Copy-on-write. */
  struct frame *src_frame = src_page->frame;
  list_push_back(&src_frame->pages, &dsc_page->frame_elem);

  /* Link with frame. */
  dsc_page->frame = src_page->frame;

  /* Set write-protect. */
  src_page->flags = src_page->flags & ~PTE_W;
  dsc_page->flags = dsc_page->flags & ~PTE_W;

  /* Set copy-on-write flag. */
  src_page->flags = src_page->flags | PG_COW;
  dsc_page->flags = dsc_page->flags | PG_COW;

  vm_install_page(src_page, src_page->thread);
  vm_install_page(dsc_page, dsc_page->thread);
}