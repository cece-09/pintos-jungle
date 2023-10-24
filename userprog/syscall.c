#include "userprog/syscall.h"

#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>

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
static struct file *read_fdt(int fd);
static void set_fdt(int fd, struct file *file);
static bool pg_write_protect(void *va, size_t size);
static void error_exit(int exit_code);
static void trigger_fault(void *buffer, size_t size);

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* Syscall table. */
typedef uint64_t (*sys_func)(struct sys_args);
static sys_func syscall[24];

#define zero (uint64_t)0
#define error (uint64_t)(-1)

/* Filesys lock. */
static struct lock fdt_lock;
static struct file **fdt;

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

  /* Init fdt lock. */
  lock_init(&fdt_lock);
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

  return (uint64_t)filesys_create(file, initial_size);
}

/* Open a new file. */
uint64_t open(struct sys_args args) {
  const char *file_name = (const char *)args.a1;
  if (!is_valid_ptr(file_name)) {
    error_exit(-1);
  }

  int fd = allocate_fd();
  if (!is_valid_fd(fd)) {
    return error;
  }

  struct file *file = filesys_open(file_name);
  if (file == NULL) {
    free_fd(fd);
    return error;
  }

  set_fdt(fd, file);
  return (uint64_t)fd;
}

/* Close a file. */
uint64_t close(struct sys_args args) {
  int fd = (int)args.a1;

  if (!is_valid_fd(fd)) {
    return zero;
  }

  struct file *file = read_fdt(fd);

  /* Standard I/O */
  if (file == OPEN_STDIN) {
    set_fdt(fd, CLOSE_STDIN);
    return zero;
  }
  if (file == OPEN_STDOUT) {
    set_fdt(fd, CLOSE_STDOUT);
    return zero;
  }
  if (is_file_std(file)) {
    return zero;
  }

  /* Close file. */
  if (file == NULL) {
    return zero;
  }

  /* Remove from fd list. */
  if (filesys_get_dup(file) > 0) {
    free_fd(fd);
    filesys_decr_dup(file);
    return zero;
  }

  free_fd(fd);
  filesys_close(file);
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

  struct file *file = read_fdt(fd);
  /* Standard I/O */
  if (is_file_std(file)) {
    if (file == OPEN_STDIN) {
      return input_getc();
    } else
      return error;
  }

  /* Normal file. */
  if (file == NULL) {
    return error;
  }
  
  /* Deliverately trigger page fault. */
  trigger_fault(buffer, size);

  return (uint64_t)filesys_read(file, buffer, size);
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

  struct file *file = read_fdt(fd);
  /* Standard I/O */
  if (is_file_std(file)) {
    if (file == OPEN_STDOUT) {
      putbuf((char *)buffer, size);
      return (uint64_t)size;
    } else
      return error;
  }

  if (file == NULL || file->deny_write) {
    return error;
  }

  /* Deliverately trigger page fault. */
  trigger_fault(buffer, size);

  return (uint64_t)filesys_write(file, buffer, size);
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
  struct file *old_file = read_fdt(oldfd);
  struct file *new_file = read_fdt(newfd);
  if (old_file == NULL) {
    return error;
  }

  /* If newfd already has a file, close. */
  if (new_file) {
    args.a1 = newfd;
    // FIXME: syscall안에서 syscall이 불려도 될까?
    close(args);
  }

  /* If standard i/o, just copy value. */
  if (is_file_std(old_file)) {
    set_fdt(newfd, old_file);
    return (uint64_t)newfd;
  }

  /* Duplicate file descriptor. */
  set_fdt(newfd, old_file);
  filesys_incr_dup(new_file);
  return (uint64_t)newfd;
}

/* Return filesize. */
uint64_t filesize(struct sys_args args) {
  int fd = (int)args.a1;
  if (!is_valid_fd(fd)) {
    return error;
  }

  struct file *file = read_fdt(fd);
  if (file == NULL || is_file_std(file)) {
    return error;
  }

  return (uint64_t)filesys_length(file);
}

/* Fork a child process. */
uint64_t fork(struct sys_args args) {
  const char *thread_name = (const char *)args.a1;
  struct intr_frame *user_if = (struct intr_frame *)args.intr;
  ASSERT(user_if);

  if (!is_valid_ptr(thread_name)) {
    error_exit(-1);
  }

  return (uint64_t)process_fork(thread_name, user_if);
}

/* Wait for child tid to exit. */
uint64_t wait(struct sys_args args) {
  tid_t tid = (tid_t)args.a1;

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

  return (uint64_t)filesys_remove(file);
}

/* Seek file. */
uint64_t seek(struct sys_args args) {
  int fd = (int)args.a1;
  unsigned position = (unsigned)args.a2;
  if (!is_valid_fd(fd)) {
    return error;
  }

  struct file *file = read_fdt(fd);
  if (file == NULL || is_file_std(file)) {
    return error;
  }

  filesys_seek(file, position);
}

/* Tell file. */
uint64_t tell(struct sys_args args) {
  int fd = (int)args.a1;
  if (!is_valid_fd(fd)) {
    return error;
  }

  struct file *file = read_fdt(fd);
  if (file == NULL || is_file_std(file)) {
    return error;
  }

  return (uint64_t)filesys_tell(file);
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

  struct file *file = read_fdt(fd);

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
  //   if (sys_sema.value == 0) {
  //     // sema_up(&sys_sema);
  //   }
  return;
}

static struct file *read_fdt(int fd) {
  if (!is_valid_fd(fd)) {
    return NULL;
  }

  struct file *file;
  lock_acquire(&fdt_lock);
  fdt = thread_current()->fdt;
  file = fdt[fd];
  lock_release(&fdt_lock);
  return file;
}

static void set_fdt(int fd, struct file *file) {
  if (!is_valid_fd(fd)) {
    return NULL;
  }

  lock_acquire(&fdt_lock);
  fdt = thread_current()->fdt;
  fdt[fd] = file;
  lock_release(&fdt_lock);
}

/* Get freed file descriptor */
static int allocate_fd() {
  lock_acquire(&fdt_lock);

  fdt = thread_current()->fdt;
  int fd = -1;
  for (fd = MIN_FD; fd < MAX_FD; fd++) {
    if (fdt[fd] == NULL) {
      ASSERT(is_valid_fd(fd))
      break;
    }
  }

  lock_release(&fdt_lock);
  return fd;
}

/* Free file descriptor */
static void free_fd(int fd) {
  if (!is_valid_fd(fd)) {
    return;
  }

  lock_acquire(&fdt_lock);
  fdt = thread_current()->fdt;
  fdt[fd] = NULL;
  lock_release(&fdt_lock);
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

/* Make fault for lazy loading. */
static void trigger_fault(void *buffer, size_t size) {
  void *p = pg_round_down(buffer);
  for (; p < (buffer + size); p += PGSIZE) {
    volatile char *ptr = (char *)(p);
    *ptr = *ptr;
  }
}