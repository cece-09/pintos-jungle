#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>

#include "threads/thread.h"

void syscall_init (void);

/* System call table. */
struct sys_args {
  uint64_t a1;
  uint64_t a2;
  uint64_t a3;
  uint64_t a4;
  uint64_t a5;
  uint64_t a6;
  struct intr_frame *intr;
};

uint64_t halt(struct sys_args);
uint64_t exit(struct sys_args);
uint64_t create(struct sys_args);
uint64_t open(struct sys_args);
uint64_t filesize(struct sys_args);
uint64_t close(struct sys_args);
uint64_t read(struct sys_args);
uint64_t write(struct sys_args);
uint64_t dup2(struct sys_args);
uint64_t fork(struct sys_args);
uint64_t exec(struct sys_args);
uint64_t wait(struct sys_args);
uint64_t remove(struct sys_args);
uint64_t seek(struct sys_args);
uint64_t tell(struct sys_args);
uint64_t mmap(struct sys_args);
uint64_t munmap(struct sys_args);

void clear_syscall_file_sema();


#endif /* userprog/syscall.h */
