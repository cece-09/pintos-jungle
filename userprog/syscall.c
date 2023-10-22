#include "userprog/syscall.h"

#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>

// #include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "vm/file.h"
#include "vm/vm.h"

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

/* Validations. */
#define is_valid_ptr(ptr) ((ptr) != NULL && (uint64_t)(ptr) < KERN_BASE)
#define is_valid_fd(int) ((int >= 0) && (int < MAX_FD))

/* Helper functions. */
static int allocate_fd(void);
static void free_fd(int fd);
static bool pg_write_protect(void *va, size_t size);
static void error_exit(int exit_code);

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* Syscall table. */
typedef uint64_t (*sys_func)(struct sys_args);
static sys_func syscall[24];
#define zero (uint64_t)0
#define error (uint64_t)(-1)

/* Filesys lock. */
static struct semaphore sys_sema;

/* Init syscall. */
void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG)
                                                               << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK,
            FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

  syscall[SYS_HALT] = halt;
  syscall[SYS_EXIT] = exit;
  syscall[SYS_FORK] = fork;
  syscall[SYS_EXEC] = exec;
  syscall[SYS_WAIT] = wait;
  syscall[SYS_CREATE] = create;
  syscall[SYS_REMOVE] = remove;
  syscall[SYS_OPEN] = open;
  syscall[SYS_FILESIZE] = filesize;
  syscall[SYS_READ] = read;
  syscall[SYS_WRITE] = write;
  syscall[SYS_SEEK] = seek;
  syscall[SYS_TELL] = tell;
  syscall[SYS_CLOSE] = close;
  syscall[SYS_MMAP] = mmap;
  syscall[SYS_MUNMAP] = munmap;
  syscall[SYS_DUP2] = dup2;

  sema_init(&sys_sema, 1);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f) {
  struct thread *curr = thread_current();
  curr->user_rsp = (void *)f->rsp;

  uint64_t num = f->R.rax;
  struct sys_args args = {.a1 = f->R.rdi,
                          .a2 = f->R.rsi,
                          .a3 = f->R.rdx,
                          .a4 = f->R.r10,
                          .a5 = f->R.r8,
                          .a6 = f->R.r9,
                          .intr = f};
  
  f->R.rax = syscall[num](args);
  if(!sys_sema.value) // sema_up(&sys_sema);
  return;
}

/* Power off system. */
uint64_t halt(struct sys_args args) {
  power_off();
  NOT_REACHED();
}

/* Terminate current process. */
uint64_t exit(struct sys_args args) {
  int status = (int)args.a1;
  thread_current()->exit_code = status;
  thread_exit();
}

/* Create a new file. */
uint64_t create(struct sys_args args) {
  const char *file = (const char *)args.a1;
  unsigned initial_size = (unsigned)args.a2;

  if (!is_valid_ptr(file)) {
    error_exit(-1);
  }

  bool rtn;
  // sema_down(&sys_sema);
  rtn = filesys_create(file, initial_size);
  // sema_up(&sys_sema);
  return (uint64_t)rtn;
}

/* Open a new file. */
uint64_t open(struct sys_args args) {
  const char *file_name = (const char *)args.a1;
  if (!is_valid_ptr(file_name)) {
    error_exit(-1);
  }

  // sema_down(&sys_sema);
  struct thread *curr = thread_current();

  int fd = allocate_fd();
  if (!is_valid_fd(fd)) {
    goto err;
  }

  struct file *file = filesys_open(file_name);
  if (file == NULL) {
    free_fd(fd);
    goto err;
  }

  curr->fdt[fd] = file;
  // sema_up(&sys_sema);
  return (uint64_t)fd;
err:
  // sema_up(&sys_sema);
  return error;
}

/* Close a file. */
uint64_t close(struct sys_args args) {
  struct file **fdt = thread_current()->fdt;
  int fd = (int)args.a1;

  if (!is_valid_fd(fd)) {
    return zero;
  }

  /* Standard I/O */
  if (fdt[fd] == OPEN_STDIN) {
    fdt[fd] = CLOSE_STDIN;
    return zero;
  }
  if (fdt[fd] == OPEN_STDOUT) {
    fdt[fd] = CLOSE_STDOUT;
    return zero;
  }
  if (is_file_std(fdt[fd])) {
    return zero;
  }

  /* Close file. */
  struct file *file = fdt[fd];
  if (file == NULL) {
    return zero;
  }

  /* Remove from fd list. */
  if (file->dup_cnt > 0) {
    free_fd(fd);
    file->dup_cnt--;

    return zero;
  }

  free_fd(fd);
  // sema_down(&sys_sema);
  filesys_close(file);
  // sema_up(&sys_sema);
}

/* Read from file to buffer. */
uint64_t read(struct sys_args args) {
  int fd = (int)args.a1;
  void *buffer = (void *)args.a2;
  unsigned size = (unsigned)args.a3;

  /* If ptr is not valid, exit. */
  if (!is_valid_ptr(buffer)) {
    error_exit(-1);
  }

  /* If page is write-protect, exit. */
  if (pg_write_protect(buffer, size)) {
    error_exit(-1);
  }

  /* If fd is not valid, return error. */
  if (!is_valid_fd(fd)) {
    return error;
  }

  // sema_down(&sys_sema);
  struct file **fdt = thread_current()->fdt;

  /* Standard I/O */
  if (is_file_std(fdt[fd])) {
    if (fdt[fd] == OPEN_STDIN) {
      // sema_up(&sys_sema);
      return input_getc();
    } else
      goto err;
  }

  /* Normal file. */
  struct file *file = fdt[fd];
  if (file == NULL) {
    goto err;
  }

  int rtn = filesys_read(file, buffer, size);
  // TODO:
  // sema_up(&sys_sema);
  return (uint64_t)rtn;
err:
  // sema_up(&sys_sema);
  return error;
}

/* Write from buffer to file. */
uint64_t write(struct sys_args args) {
  int fd = (int)args.a1;
  const void *buffer = (const void *)args.a2;
  unsigned size = (unsigned)args.a3;

  /* If ptr is not valid, exit. */
  if (!is_valid_ptr(buffer)) {
    error_exit(-1);
  }

  /* If fd is not valid, return error. */
  if (!is_valid_fd(fd)) {
    return error;
  }

  // sema_down(&sys_sema);
  struct file **fdt = thread_current()->fdt;

  /* Standard I/O */
  if (is_file_std(fdt[fd])) {
    if (fdt[fd] == OPEN_STDOUT) {
      putbuf((char *)buffer, size);
      // sema_up(&sys_sema);
      return (uint64_t)size;
    } else
      goto err;
  }

  struct file *file = fdt[fd];
  if (file == NULL || file->deny_write) {
    goto err;
  }

  int rtn = filesys_write(file, buffer, size);
  // TODO:
  // sema_up(&sys_sema);
  return (uint64_t)rtn;
err:
  // sema_up(&sys_sema);
  return error;
}

/* Duplicate file of oldfd to newfd. */
uint64_t dup2(struct sys_args args) {
  int oldfd = (int)args.a1;
  int newfd = (int)args.a2;

  /* If invalid fd, return error. */
  if (!is_valid_fd(oldfd) || !is_valid_fd(newfd)) {
    return error;
  }

  /* If same fd, return newfd. */
  if (oldfd == newfd) {
    return (uint64_t)newfd;
  }

  /* If oldfd has no fild, return error. */
  struct file **fdt = thread_current()->fdt;
  if (fdt[oldfd] == NULL) {
    return error;
  }

  /* If newfd already has a file, close. */
  if (fdt[newfd]) {
    args.a1 = newfd;
    // FIXME: syscall안에서 syscall이 불려도 될까?
    close(args);
  }

  /* If standard i/o, just copy value. */
  if (is_file_std(fdt[oldfd])) {
    fdt[newfd] = fdt[oldfd];
    return (uint64_t)newfd;
  }

  /* Duplicate file descriptor. */
  fdt[newfd] = fdt[oldfd];
  fdt[newfd]->dup_cnt++;
  return (uint64_t)newfd;
}

/* Return filesize. */
uint64_t filesize(struct sys_args args) {
  int fd = (int)args.a1;
  if (!is_valid_fd(fd)) {
    return error;
  }

  struct file **fdt = thread_current()->fdt;
  if (fdt[fd] == NULL || is_file_std(fdt[fd])) {
    return error;
  }

  off_t rtn;
  // sema_down(&sys_sema);
  rtn = filesys_length(fdt[fd]);
  // sema_up(&sys_sema);
  return (uint64_t)rtn;
}

/* Fork a child process. */
uint64_t fork(struct sys_args args) {
  const char *thread_name = (const char *)args.a1;
  struct intr_frame *user_if = (struct intr_frame *)args.intr;
  ASSERT(user_if);

  if (!is_valid_ptr(thread_name)) {
    error_exit(-1);
  }

  tid_t rtn;
  // sema_up(&sys_sema);
  //   // // sema_down(&sys_sema);
  rtn = process_fork(thread_name, user_if);
  //   // // sema_up(&sys_sema);
  return (uint64_t)rtn;
}

/* Wait for child tid to exit. */
uint64_t wait(struct sys_args args) {
  tid_t tid = (tid_t)args.a1;
  ASSERT(tid >= 0);
  // sema_up(&sys_sema);

  return (uint64_t)process_wait(tid);
}

/* Execute process. */
uint64_t exec(struct sys_args args) {
  const char *cmd_line = (const char *)args.a1;
  if (!is_valid_ptr(cmd_line)) {
    error_exit(-1);
  }

  /* Copy cmd line. */
  const char *cmd_copy = palloc_get_page(0);
  strlcpy(cmd_copy, cmd_line, strlen(cmd_line) + 1);

  /* Execute. If succeed, there's no return value. */
  int success = process_exec(cmd_copy);
  if (success < 0) return error;
}

/* Remove file. */
uint64_t remove(struct sys_args args) {
  const char *file = (const char *)args.a1;
  if (!is_valid_ptr(file)) {
    error_exit(-1);
  }

  /* If there's no file to remove, return 0. */
  if (file == NULL) {
    return zero;
  }

  bool rtn;
  // sema_down(&sys_sema);
  rtn = filesys_remove(file);
  // sema_up(&sys_sema);
  return (uint64_t)rtn;
}

/* Seek file. */
uint64_t seek(struct sys_args args) {
  int fd = (int)args.a1;
  unsigned position = (unsigned)args.a2;
  if (!is_valid_fd(fd)) {
    return error;
  }

  struct file **fdt = thread_current()->fdt;
  if (fdt[fd] == NULL || is_file_std(fdt[fd])) {
    return error;
  }

  // sema_down(&sys_sema);
  filesys_seek(fdt[fd], position);
  // sema_up(&sys_sema);
}

/* Tell file. */
uint64_t tell(struct sys_args args) {
  int fd = (int)args.a1;
  if (!is_valid_fd(fd)) {
    return error;
  }

  struct file **fdt = thread_current()->fdt;
  if (fdt[fd] == NULL || is_file_std(fdt[fd])) {
    return error;
  }

  unsigned rtn;
  // sema_down(&sys_sema);
  rtn = filesys_tell(fdt[fd]);
  // sema_up(&sys_sema);
  return (uint64_t)rtn;
}

/* Memory mapping. */
uint64_t mmap(struct sys_args args) {
  int fd = (int)args.a4;
  int writable = (int)args.a3;
  void *addr = (void *)args.a1;
  off_t offset = (off_t)args.a5;
  size_t length = (size_t)args.a2;

  /* If ptr is not valid, return zero. */
  if (!is_valid_ptr(addr) || !is_valid_ptr(addr + length)) {
    return zero;
  }

  /* If there's no file, return zero. */
  if (!is_valid_fd(fd)) {
    return zero;
  }

  struct file **fdt = thread_current()->fdt;
  struct file *file = fdt[fd];

  /* If file is standard i/o, return zero. */
  if (is_file_std(file)) {
    return zero;
  }

  /* If length is not positive, return zero. */
  if ((long)length <= 0) {
    return zero;
  }

  return (uint64_t)do_mmap(addr, length, writable, file, offset);
}

/* Unmap memory. */
uint64_t munmap(struct sys_args args) {
  void *addr = (void *)args.a1;
  if (!is_valid_ptr(addr)) {
    return zero;
  }

  do_munmap(addr);
  return zero;
}

/* ====== Helper Functions ====== */

/* Clear sema. See exception.c */
void clear_syscall_file_sema() {
  if (sys_sema.value == 0) {
    // sema_up(&sys_sema);
  }
}

/* Get freed file descriptor */
static int allocate_fd() {
  struct thread *curr = thread_current();
  int fd;
  for (fd = MIN_FD; fd < MAX_FD; fd++) {
    if (curr->fdt[fd] != NULL) continue;
    ASSERT(is_valid_fd(fd))
    return fd;
  }
  return -1;
}

/* Free file descriptor */
static void free_fd(int fd) {
  ASSERT(is_valid_fd(fd))
  thread_current()->fdt[fd] = NULL;
}

/* Returns if present page is writable.
 * Returns false if page is not present.
 * Returns false if page is copy-on-write. */
static bool pg_write_protect(void *va, size_t size) {
  struct thread *curr = thread_current();

  /* From va to va + size. */
  for (void *p = va; p < va + size; p += PGSIZE) {
    uint64_t *pte = pml4e_walk(curr->pml4, pg_round_down(p), 0);
    if (*pte != NULL && !is_writable(pte)) {
      struct page *page = spt_find_page(&curr->spt, va);
      return !vm_handle_wp(page);
    }
  }
  return false;
}

/* Call thread exit with error code.
 * Used when invalid ptr is handed in. */
static void error_exit(int exit_code) {
  thread_current()->exit_code = exit_code;
  thread_exit();
}