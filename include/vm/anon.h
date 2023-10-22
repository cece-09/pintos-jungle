#ifndef VM_ANON_H
#define VM_ANON_H

#include "vm/vm.h"
#include "devices/disk.h"

struct page;
enum vm_type;

struct anon_page {
    size_t slot;
};

void vm_anon_init(void);
bool anon_initializer(struct page *page, enum vm_type type, void *kva);
void anon_swap_table_push(size_t slot, struct page *page);

#endif
