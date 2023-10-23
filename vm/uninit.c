/* uninit.c: Implementation of uninitialized page.
 *
 * All of the pages are born as uninit page. When the first page fault occurs,
 * the handler chain calls uninit_initialize (page->operations.swap_in).
 * The uninit_initialize function transmutes the page into the specific page
 * object (anon, file, page_cache), by initializing the page object,and calls
 * initialization callback that passed from vm_alloc_page_with_initializer
 * function.
 * */


#include <stdio.h>

#include "threads/pte.h"
#include "vm/vm.h"
#include "vm/uninit.h"

static bool uninit_initialize(struct page *page, void *kva);
static void uninit_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations uninit_ops = {
    .swap_in = uninit_initialize,
    .swap_out = NULL,
    .destroy = uninit_destroy,
    .type = VM_UNINIT,
};

/* DO NOT MODIFY this function */
void uninit_new(struct page *page, void *va, vm_initializer *init,
                enum vm_type type, void *aux,
                bool (*initializer)(struct page *, enum vm_type, void *)) {
  ASSERT(page != NULL);

  *page = (struct page){.operations = &uninit_ops,
                        .va = va,
                        .frame = NULL, /* no frame for now */
                        .uninit = (struct uninit_page){
                            .init = init,
                            .type = type,
                            .aux = aux,
                            .page_initializer = initializer,
                        }};
}

/* Initalize the page on first fault */
static bool uninit_initialize(struct page *page, void *kva) {
  struct thread *curr = thread_current();
  struct uninit_page *uninit = &page->uninit;
  struct frame *frame = page->frame;
  ASSERT(frame && frame->kva);

  /* Fetch first, page_initialize may overwrite the values */
  vm_initializer *init = uninit->init;
  void *aux = uninit->aux;

  if (uninit->page_initializer(page, uninit->type, kva) &&
      (init ? init(page, aux) : true)) {

    /* Mark as initialized page. */
    page->flags = page->flags | PG_INIT;
    
    /* Link with frame. */
    vm_map_frame(page, frame);
    return vm_install_page(page, curr);
  }
  /* If initializing failed, destroy do uninit_destroy.
   * Otherwise, do file_backed_destroy or anon_destory. */
  destroy(page);
  return false;
}

/* Free the resources hold by uninit_page. Although most of pages are transmuted
 * to other page objects, it is possible to have uninit pages when the process
 * exit, which are never referenced during the execution.
 * PAGE will be freed by the caller. */
static void uninit_destroy(struct page *page) {
  struct uninit_page *uninit = &page->uninit;
  /* Called before initializer function get finished. */
  if (pg_present(page)) {
    palloc_free_page(page->frame->kva);
    free(page->frame);
  }
  free(uninit->aux);
  return;
}
