/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include <stdio.h>

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* File-backed info. */
	struct file_info* aux = page->uninit.aux;
	if(aux == NULL) return false;
	
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
	file_page->file_info = aux;
	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page = &page->file;
	free(file_page->file_info);

	// TODO: write back.
	return;
}

/* Initialize file-backed frame. */
static bool mmap_init(struct page* page, void* aux) {
	struct file_info* file_info = (struct file_info*)aux;
	struct file* file = file_info->file;
	off_t ofs = file_info->ofs;
	size_t bytes = file_info->bytes;

	ASSERT(page->frame)
	void* kva = page->frame->kva;
	
	/* Map with file. */
    file_seek(file, ofs);
	file_read(file, kva, bytes);
	return true;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	struct thread* curr = thread_current();
	
	/* If addr is null or not page-aligned. */
	if(addr == NULL || (uint64_t)addr % PGSIZE) return NULL;
	
	/* If addr is in spt. */
	for(void* p = addr; p < addr + length; p += PGSIZE) {
		if(spt_find_page(&curr->spt, p)) return NULL;
	}

	/* If addr is above STACK_LIMIT. */
	if(addr + length > STACK_LIMIT) return NULL;
    
	/* Allocate page with lazy loading. */
	struct file* mmap_file = file_duplicate(file);
    size_t read_byte = length;
	int page_cnt = 0;

	while (read_byte > 0)
	{
		size_t page_read_byte = read_byte < PGSIZE ? read_byte : PGSIZE;

		struct file_info* aux = calloc(1, sizeof(struct file_info));
		aux->file = mmap_file;
		aux->ofs = offset;
		aux->bytes = page_read_byte;

		if(!vm_alloc_page_with_initializer(VM_FILE, addr+(page_cnt*PGSIZE), writable, mmap_init, aux)) {
			return NULL;
		}

		offset += page_read_byte;
		read_byte -= page_read_byte;
		page_cnt ++;
	}
	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct thread* curr = thread_current();
	struct page* page = spt_find_page(&curr->spt, addr);

	spt_remove_page(&curr->spt, page);
	pml4_clear_page(curr->pml4, addr);

	// FIXME: dealloc page.
	vm_dealloc_page(page);
}
