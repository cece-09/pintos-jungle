#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

/* Read/Write function type. */
typedef off_t file_rw_func(struct file *, const void *, off_t);

struct file_page {
    struct file* file;
    off_t offset;
    size_t length; 
    void* map_addr;
    size_t swap_slot;
};

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset);
void do_munmap (void *va);
void spt_file_writeback(struct hash_elem *e, void *aux);


#define is_file_head(page, file_page) ((page)->va == (file_page)->map_addr)
#endif
