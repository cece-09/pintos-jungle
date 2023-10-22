#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

struct file_page {
  size_t slot;
  off_t offset;
  size_t length;
  void *map_addr;
  struct file *file;
};

void vm_file_init(void);
void do_munmap(void *va);
struct file_page *get_file_page(struct page *page);
void spt_file_writeback(struct hash_elem *e, void *aux);
void file_swap_table_push(size_t slot, struct page *page);
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable, struct file *file,
              off_t offset);

#define is_file_head(page, file_page) ((page)->va == (file_page)->map_addr)
#endif
