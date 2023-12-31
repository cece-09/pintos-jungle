#include "userprog/syscall.h"

#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "vm/vm.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void halt(void);
void exit(int);
bool create(const char *, unsigned);
int open(const char *);
void close(int);
int read(int, void *, unsigned);
int write(int, const void *, unsigned);
int dup2(int, int);
tid_t fork(const char *, struct intr_frame *);
int exec(const char *);
bool remove(const char *);
void seek(int, unsigned);
unsigned tell(int);
void *mmap(void *, size_t, int, int, off_t);
void munmap(void *);

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

static int allocate_fd(void);
static void free_fd(int fd);
static bool pg_write_protect(void *va, size_t size);

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG)
                                                               << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK,
            FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* System call table. */

/* The main system call interface */
void syscall_handler(struct intr_frame *f) {
  switch (f->R.rax) {
    case SYS_HALT: {
      halt();
      break;
    }
    case SYS_EXIT: {
      exit((int)f->R.rdi);
      break;
    }
    case SYS_FORK: {
      f->R.rax = fork((const char *)f->R.rdi, f);
      break;
    }
    case SYS_EXEC: {
      f->R.rax = exec((const char *)f->R.rdi);
      break;
    }
    case SYS_WAIT: {
      f->R.rax = wait((tid_t)f->R.rdi);
      break;
    }
    case SYS_CREATE: {
      f->R.rax = create((char *)f->R.rdi, f->R.rsi);
      break;
    }
    case SYS_REMOVE: {
      f->R.rax = remove((const char *)f->R.rdi);
      break;
    }
    case SYS_OPEN: {
      f->R.rax = open((const char *)f->R.rdi);
      break;
    }
    case SYS_FILESIZE: {
      f->R.rax = filesize((int)f->R.rdi);
      break;
    }
    case SYS_READ: {
      f->R.rax = read((int)f->R.rdi, (void *)f->R.rsi, (unsigned)f->R.rdx);
      break;
    }
    case SYS_WRITE: {
      f->R.rax = write((int)f->R.rdi, (void *)f->R.rsi, (unsigned)f->R.rdx);
      break;
    }
    case SYS_SEEK: {
      seek((int)f->R.rdi, (unsigned)f->R.rsi);
      break;
    }
    case SYS_TELL: {
      f->R.rax = tell((int)f->R.rdi);
      break;
    }
    case SYS_CLOSE: {
      close((int)f->R.rdi);
      break;
    }
    case SYS_DUP2: {
      f->R.rax = dup2((int)f->R.rdi, (int)f->R.rsi);
      break;
    }
    case SYS_MMAP: {
      f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
      break;
    }
    case SYS_MUNMAP: {
      munmap(f->R.rdi);
      break;
    }
    default:
      break;
  }
}

/* Power off system. */
void halt(void) {
  power_off();
  NOT_REACHED();
}

/* Terminate current process. */
void exit(int status) {
  thread_current()->exit_code = status;
  thread_exit();
  return;
}

/* Create a new file. */
bool create(const char *file, unsigned initial_size) {
  if (!is_valid_ptr(file)) exit(-1);
  return filesys_create(file, initial_size);
}

/* Open a new file. */
int open(const char *file_name) {
  if (!is_valid_ptr(file_name)) exit(-1);
  if (file_name == NULL) return -1;
  struct thread *curr = thread_current();

  int fd = allocate_fd();
  if (!is_valid_fd(fd)) return -1;

  struct file *file = filesys_open(file_name);

  if (file == NULL) {
    free_fd(fd);
    return -1;
  }
  curr->fdt[fd] = file;
  return fd;
}

/* Close a file. */
void close(int fd) {
  if (!is_valid_fd(fd)) return;
  struct file **fdt = thread_current()->fdt;

  /* Standard I/O */
  if (fdt[fd] == OPEN_STDIN) {
    fdt[fd] = CLOSE_STDIN;
    return;
  }
  if (fdt[fd] == OPEN_STDOUT) {
    fdt[fd] = CLOSE_STDOUT;
    return;
  }

  if (is_file_std(fdt[fd])) return;

  /* Close file. */
  struct file *file = fdt[fd];
  if (file == NULL) return;

  /* Remove from fd list. */
  if (file->dup_cnt > 0) {
    file->dup_cnt--;
    free_fd(fd);
    return;
  }

  free_fd(fd);
  file_close(file);
}

/* Read from file to buffer. */
int read(int fd, void *buffer, unsigned size) {
  if (!is_valid_ptr(buffer)) exit(-1);
  /* If page is write-protect, exit. */
  if (pg_write_protect(buffer, size)) exit(-1);

  if (!is_valid_fd(fd)) return 0;
  struct file **fdt = thread_current()->fdt;

  /* Standard I/O */
  if (is_file_std(fdt[fd])) {
    if (fdt[fd] == OPEN_STDIN) {
      return input_getc();
    } else
      return 0;
  }

  struct file *file = fdt[fd];
  if (file == NULL) return -1;

  int bytes = 0;
  lock_acquire(file_inode_lock(file));
  bytes = file_read(file, buffer, size);
  lock_release(file_inode_lock(file));
  return bytes;
}

/* Write from buffer to file. */
int write(int fd, const void *buffer, unsigned size) {
  if (!is_valid_ptr(buffer)) exit(-1);
  if (!is_valid_fd(fd)) return 0;
  struct file **fdt = thread_current()->fdt;

  /* Standard I/O */
  if (is_file_std(fdt[fd])) {
    if (fdt[fd] == OPEN_STDOUT) {
      putbuf((char *)buffer, size);
      return size;
    } else
      return 0;
  }

  struct file *file = fdt[fd];
  if (file == NULL || !file_writable(file)) return 0;

  int bytes = 0;
  lock_acquire(file_inode_lock(file));
  bytes = file_write(file, buffer, size);
  lock_release(file_inode_lock(file));
  return bytes;
}

/* Duplicate file of oldfd to newfd. */
int dup2(int oldfd, int newfd) {
  if (!is_valid_fd(oldfd)) return -1;
  if (!is_valid_fd(newfd)) return -1;

  struct file **fdt = thread_current()->fdt;

  if (oldfd == newfd) return newfd;
  if (fdt[oldfd] == NULL) return -1;

  /* If newfd already has a file, close. */
  if (fdt[newfd]) {
    close(newfd);
  }

  /* If standard i/o, just copy value. */
  if (is_file_std(fdt[oldfd])) {
    fdt[newfd] = fdt[oldfd];
    return newfd;
  }

  /* Duplicate file descriptor. */
  fdt[newfd] = fdt[oldfd];
  fdt[newfd]->dup_cnt++;
  return newfd;
}

/* Return filesize. */
int filesize(int fd) {
  if (!is_valid_fd(fd)) return -1;
  struct file **fdt = thread_current()->fdt;
  if (fdt[fd] == NULL) return -1;
  if (is_file_std(fdt[fd])) return -1;

  return file_length(fdt[fd]);
}

/* Fork a child process. */
tid_t fork(const char *thread_name, struct intr_frame *user_if) {
  if (!is_valid_ptr(thread_name)) exit(-1);
  ASSERT(user_if);
  return process_fork(thread_name, user_if);
}

/* Wait for child tid to exit. */
int wait(tid_t tid) {
  ASSERT(tid >= 0);
  return process_wait(tid);
}

/* Execute process. */
int exec(const char *cmd_line) {
  if (!is_valid_ptr(cmd_line)) exit(-1);
  const char *fn_copy = palloc_get_page(0);
  strlcpy(fn_copy, cmd_line, strlen(cmd_line) + 1);
  int success = process_exec(fn_copy);
  if (success < 0) exit(-1);
}

/* Remove file. */
bool remove(const char *file) {
  if (!is_valid_ptr(file)) exit(-1);
  if (file == NULL) return false;
  return filesys_remove(file);
}

/* Seek file. */
void seek(int fd, unsigned position) {
  if (!is_valid_fd(fd)) return;
  struct file **fdt = thread_current()->fdt;

  if (fdt[fd] == NULL) return;
  if (is_file_std(fdt[fd])) return;

  lock_acquire(file_inode_lock(fdt[fd]));
  file_seek(fdt[fd], position);
  lock_release(file_inode_lock(fdt[fd]));
}

/* Tell file. */
unsigned tell(int fd) {
  if (!is_valid_fd(fd)) return -1;
  struct file **fdt = thread_current()->fdt;
  unsigned rtn;

  if (fdt[fd] == NULL) return -1;
  if (is_file_std(fdt[fd])) return -1;

  lock_acquire(file_inode_lock(fdt[fd]));
  rtn = file_tell(fdt[fd]);
  lock_release(file_inode_lock(fdt[fd]));
  return rtn;
}

/* Memory mapping. */
void *mmap(void *addr, size_t length, int writable, int fd, off_t offset) {
  if (!is_valid_ptr(addr)) return NULL;
  if (!is_valid_ptr(addr + length)) return NULL;
  if (!is_valid_fd(fd)) return NULL;

  struct file **fdt = thread_current()->fdt;
  struct file *file = fdt[fd];

  /* Exceptions. */
  if (is_file_std(file)) return NULL;
  if (length <= 0) return NULL;

  return do_mmap(addr, length, writable, file, offset);
}

/* Unmap memory. */
void munmap(void *addr) {
  if (!is_valid_ptr(addr)) return NULL;
  do_munmap(addr);
}

/* Get freed file descriptor */
static int allocate_fd() {
  struct thread *curr = thread_current();
  int fd;
  for (fd = MIN_FD; fd < MAX_FD; fd++) {
    if (curr->fdt[fd] == NULL) {
      ASSERT(is_valid_fd(fd))
      return fd;
    }
  }
  return -1;
}

/* Free file descriptor */
static void free_fd(int fd) {
  ASSERT(is_valid_fd(fd))
  thread_current()->fdt[fd] = NULL;
}

/* Returns if present page is writable.
 * Returns false if page is not present. */
static bool pg_write_protect(void *va, size_t size) {
  struct thread *curr = thread_current();
  /* from va to va + size. */
  for (void *p = va; p < va + size; p += PGSIZE) {
    uint64_t *pte = pml4e_walk(curr->pml4, pg_round_down(p), 0);
    if (*pte != NULL && !is_writable(pte)) {
      return true;
    }
  }
  return false;
}