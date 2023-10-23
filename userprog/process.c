#include "userprog/process.h"

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/tss.h"

#define VM
#ifdef VM
#include "vm/vm.h"
#endif

#define MAX_ARGS 100

static void __do_fork(void *);
static void initd(void *f_name);
static void process_cleanup(void);
static void exec_file_cleanup(void);
static void fdt_cleanup(struct file **);
static void child_list_cleanup(struct list *);
static void duplicate_fdt(struct thread *, struct thread *);
static bool load(const char *file_name, struct intr_frame *if_);

/* Filesys sema. Used in process.c and vm/file.c */
static struct lock load_lock;

/* General process initializer for initd and other process. */
static bool process_init(void) {
  struct thread *curr = thread_current();

  /* Set as user task. */
  curr->task = USER_TASK;

  /* Create file descriptor table. */
  curr->fdt = palloc_get_page(PAL_ZERO);
  if (curr->fdt == NULL) return false;
  return true;
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *file_name) {
  char *fn_copy;
  tid_t tid;

  /* Init load lock. */
  lock_init(&load_lock);

  /* Make a copy of FILE_NAME.
   * Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL) return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */
  char *save_ptr;
  strtok_r(file_name, " ", &save_ptr);

  tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
  if (tid == TID_ERROR) palloc_free_page(fn_copy);
  return tid;
}

/* A thread function that launches first user process. */
static void initd(void *f_name) {
#ifdef VM
  supplemental_page_table_init(&thread_current()->spt);
#endif

  struct thread *curr = thread_current();

  /* Create file descriptor table. */
  bool success = process_init();
  if (success == false) {
    PANIC("Fail to create file descriptor table.\n");
  }

  /* Initiate standard I/0 */
  curr->fdt[STDIN_FILENO] = OPEN_STDIN;
  curr->fdt[STDOUT_FILENO] = OPEN_STDOUT;

  if (process_exec(f_name) < 0) PANIC("Fail to launch initd\n");
  NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created.
 * Clone current thread to new thread. */
tid_t process_fork(const char *name, struct intr_frame *if_) {
  struct thread *parent = thread_current();

  /* Backup parent's context before fork. */
  memcpy(&parent->fork_tf, if_, sizeof(struct intr_frame));

  /* Create thread to fork process. */
  tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, parent);

  /* If thread_create fails, return TID_ERROR */
  if (tid == TID_ERROR) {
    printf("🔥 child creation failed.\n");
    return TID_ERROR;
  }

  /* Lock parent. */
  sema_down(&parent->fork_sema);

  /* If fork is not successful, return TID_ERROR. */
  struct thread_child *child = thread_get_child(&parent->children, tid);
  if (!child) {
    printf("🔥 no child.\n");
    return TID_ERROR;
  }
  if (child->addr->exit_code == FORK_FAIL) {
    printf("🔥 fork failed.\n");
    return TID_ERROR;
  }
  return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2.
 * @param va is virtual address of pte. */
static bool duplicate_pte(uint64_t *pte, void *va, void *aux) {
  struct thread *curr = thread_current();
  struct thread *parent = (struct thread *)aux;
  void *parent_page;
  void *newpage;
  bool writable;

  /* If the parent_page is kernel page, then return immediately. */
  if (is_kernel_vaddr(va)) {
    return true;
  }

  /* Resolve VA from the parent's page map level 4. */
  parent_page = pml4_get_page(parent->pml4, va);

  /* Allocate new PAL_USER page for the child and set result to
   * NEWPAGE. */
  if (!(newpage = palloc_get_page(PAL_USER))) {
    printf("page allocation error\n");
    return false;
  }

  /* Duplicate parent's page to the new page and
   * check whether parent's page is writable or not (set WRITABLE
   * according to the result). */
  writable = is_writable(pte);
  memcpy(newpage, parent_page, PGSIZE);

  /* Add new page to child's page table at address VA with WRITABLE
   * permission. */
  if (!pml4_set_page(curr->pml4, va, newpage, writable)) {
    palloc_free_page(newpage);
    return false;
  }
  return true;
}
#endif

/* A thread function that copies parent's execution context.*/
static void __do_fork(void *aux) {
  struct intr_frame if_;
  struct thread *parent = (struct thread *)aux;
  struct thread *curr = thread_current();
  bool succ = true;


  /* Mark that current thread is in forking process. */
  curr->exit_code = FORK_SUCC;

  /* Read the cpu context to local stack. */
  memcpy(&if_, &parent->fork_tf, sizeof(struct intr_frame));

  /* Duplicate page table. */
  curr->pml4 = pml4_create();
  if (curr->pml4 == NULL) {
    printf("pml4 creation failed\n");
    goto error;
  }

  /* Activate current process. */
  process_activate(curr);

  /* Duplicate exec file. */
  curr->exec_file = filesys_duplicate(parent->exec_file);
  printf("🔥 do fork?\n");

#ifdef VM
  supplemental_page_table_init(&curr->spt);
  if (!supplemental_page_table_copy(&curr->spt, &parent->spt)) {
    printf("spt copy failed\n");
    goto error;
  }

#else
  if (!pml4_for_each(parent->pml4, duplicate_pte, parent)) goto error;
#endif

  /* Get new page for fdt. */
  if (process_init() == false) {
    printf("process_init failed\n");
    goto error;
  }

  /* Duplicate file descriptor table. */
  duplicate_fdt(parent, curr);

  /* Forked process return value. */
  if_.R.rax = 0;

  /* Finally, switch to the newly created process. */
  if (succ) {
    /* Let parent run. */
    curr->exit_code = BASE_EXIT;
    sema_up(&parent->fork_sema);
    do_iret(&if_);
  }

error:
  curr->exit_code = FORK_FAIL;
  sema_up(&parent->fork_sema);
  thread_exit();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec(void *f_name) {
  struct thread *curr = thread_current();
  char *file_name = f_name;
  bool success = false;

  /* We cannot use the intr_frame in the thread structure.
   * This is because when current thread rescheduled,
   * it stores the execution information to the member. */
  struct intr_frame _if;
  _if.ds = _if.es = _if.ss = SEL_UDSEG;
  _if.cs = SEL_UCSEG;
  _if.eflags = FLAG_IF | FLAG_MBS;

  /* We first kill the current context */
  process_cleanup();

  /* Close current exec file. */
  exec_file_cleanup();

#ifdef VM
  /* Create new spt. */
  supplemental_page_table_init(&curr->spt);
#endif

  /* And then load the binary */
  lock_acquire(&load_lock);
  success = load(file_name, &_if);
  lock_release(&load_lock);

  /* If load failed, quit. */
  palloc_free_page(file_name);
  if (!success) {
    return -1;
  }

  /* Start switched process. */
  do_iret(&_if);
  NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting. */
int process_wait(tid_t child_tid) {
  struct thread *parent = thread_current();
  struct thread_child *child;

  int rtn;

  /* If child_tid is invalid, return error */
  child = thread_get_child(&parent->children, child_tid);
  if (child == NULL) {
    return -1;
  }

  /* Block parent until child exit. */
  do {
    /* If child exit, remove from list and return. */
    if (child->status == CHILD_EXIT) {
      rtn = child->rtn_value;
      list_remove(&child->elem);
      sema_init(&parent->wait_sema, 0);
      free(child);
      return rtn;
    }
    /* Wait for child_tid to exit. */
    sema_down(&parent->wait_sema);
  } while (child);
  NOT_REACHED();
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void) {
  struct thread *curr = thread_current();
  struct thread_child *child;

  /* Clean child list. */
  child_list_cleanup(&curr->children);

  /* Clean file descriptor table. */
  fdt_cleanup(curr->fdt);

  /* Close exec file. */
  exec_file_cleanup();

  /* If current is user process, */
  if (curr->task == USER_TASK) {
    /* Print termination message. */
    printf("%s: exit(%lld)\n", curr->name, curr->exit_code);
  }

  /* Clean up pml4 */
  process_cleanup();

  /* Let parent process run. */
  if (curr->parent) {
    child = thread_get_child(&curr->parent->children, curr->tid);
    if (child) {
      child->status = CHILD_EXIT;
      child->rtn_value = curr->exit_code;
      sema_up(&curr->parent->wait_sema);
    }
  }
}

/* Clear file sema. This function is called
 * when page fault exception occurs. */
void clear_process_file_sema(void) {
  struct thread *curr = thread_current();
  if (load_lock.holder == curr) {
    lock_release(&load_lock);
  }
}

/* Close exec_file. */
static void exec_file_cleanup(void) {
  struct thread *curr = thread_current();
  if (curr->exec_file) {
    filesys_close(curr->exec_file);
    curr->exec_file = NULL;
  }
}

/* Free the current process's resources. */
static void process_cleanup(void) {
  struct thread *curr = thread_current();

#ifdef VM
  supplemental_page_table_kill(&curr->spt);
#endif

  uint64_t *pml4;
  /* Destroy the current process's page directory and switch back
   * to the kernel-only page directory. */
  pml4 = curr->pml4;
  if (pml4 != NULL) {
    /* Correct ordering here is crucial.  We must set
     * cur->pagedir to NULL before switching page directories,
     * so that a timer interrupt can't switch back to the
     * process page directory.  We must activate the base page
     * directory before destroying the process's page
     * directory, or our active page directory will be one
     * that's been freed (and cleared). */
    curr->pml4 = NULL;
    pml4_activate(NULL);
    pml4_destroy(pml4);
  }
}

/* Duplicate the parent's file descriptor table.
 * Copy fdt entirely including dup2 status.
 */
static void duplicate_fdt(struct thread *parent, struct thread *child) {
  for (int fd = 0; fd < MAX_FD; fd++) {
    if (parent->fdt[fd] == NULL) continue;

    /* If alreay copied, ignore. */
    if (child->fdt[fd]) continue;

    if (is_file_std(parent->fdt[fd])) {
      /* If file is standard I/O, copy value. */
      child->fdt[fd] = parent->fdt[fd];
    } else {
      /* If it's a normal file, duplicate first. */
      child->fdt[fd] = file_duplicate(parent->fdt[fd]);
      child->fdt[fd]->dup_cnt = parent->fdt[fd]->dup_cnt;
    }

    /* Copy all duplicated. */
    for (int dup_fd = fd + 1; dup_fd < MAX_FD; dup_fd++) {
      if (parent->fdt[dup_fd] != parent->fdt[fd]) continue;
      child->fdt[dup_fd] = child->fdt[fd];
    }
  }
}

/* Clean child list.
 * Make child process orphan. */
static void child_list_cleanup(struct list *list) {
  struct list_elem *front;
  struct thread_child *child;
  while (!list_empty(list)) {
    front = list_pop_front(list);
    child = list_entry(front, struct thread_child, elem);
    /* Make child orphan. */
    child->addr->parent = NULL;
    free(child);
  }
}

/* Clean up all file descriptor table.
 * Release lock if needed. */
static void fdt_cleanup(struct file **fdt) {
  struct thread *curr = thread_current();
  struct lock *inode_lock;
  struct file *file;

  if (fdt == NULL) return;

  /* Close all files */
  for (int fd = 0; fd < MAX_FD; fd++) {
    if (fdt[fd] == NULL) continue;
    if (is_file_std(fdt[fd])) continue;

    /* Close file. */
    file = fdt[fd];

    /* If duplicated file descriptor. */
    if (file->dup_cnt > 0) {
      file->dup_cnt--;
      continue;
    }

    file_close(file);
  }
  /* And free file descriptor table. */
  curr->fdt = NULL;
  palloc_free_page(fdt);
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next) {
  /* Activate thread's page tables. */
  pml4_activate(next->pml4);

  /* Set thread's kernel stack for use in processing interrupts. */
  tss_update(next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

struct ELF64_PHDR {
  uint32_t p_type;   /* type of segment */
  uint32_t p_flags;  /* flags. including permission */
  uint64_t p_offset; /* segment offset */
  uint64_t p_vaddr;  /* what va the first byte of segment should be? */
  uint64_t p_paddr;  /* physical address */
  uint64_t p_filesz; /* bytes of segment's file image */
  uint64_t p_memsz;  /* bytes of sement's memory image */
  uint64_t p_align;  /* alignment */
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool load(const char *file_name, struct intr_frame *if_) {
  struct thread *t = thread_current();
  struct ELF ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Arguments to pass. */
  char *args[MAX_ARGS];

  /* Parse f_name. */
  char *token, *save_ptr;
  int args_cnt = 0, args_len = 0;

  for (token = strtok_r(file_name, " ", &save_ptr); token != NULL;
       token = strtok_r(NULL, " ", &save_ptr)) {
    args[args_cnt++] = token;
    args_len += strlen(token) + 1;
  }

  /* Allocate and activate page directory. */
  t->pml4 = pml4_create();  // 여기서 초기화됨
  if (t->pml4 == NULL) {
    printf("load: %s: error creating pml4\n", file_name);
    goto done;
  }

  process_activate(thread_current());

  /* Open executable file. */
  file = filesys_open(file_name);

  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Set this file unwritable */
  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 ||
      ehdr.e_machine != 0x3E  // amd64
      || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) ||
      ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file)) goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD: /* if segment is loadable, */
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint64_t file_page = phdr.p_offset & ~PGMASK;
          uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint64_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
             * Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes =
                (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
             * Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void *)mem_page, read_bytes,
                            zero_bytes, writable)) {
            printf("load: %s: error loading segment\n", file_name);
            goto done;
          }
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(if_)) {
    printf("load: %s: error setting up stack\n", file_name);
    goto done;
  }

  /* Start address. */
  if_->rip = ehdr.e_entry;

  /* Argument passing. */
  if_->rsp -= ROUND_UP(args_len, 8);

  char *cur = if_->rsp;  // 문자열 부분 시작점
  char *des = if_->rsp;  // 다음에 스택에 쓸 곳

  /* Push string arguments. */
  for (int i = 0; i < args_cnt; i++) {
    memcpy(des, args[i], strlen(args[i]) + 1);
    des += (strlen(args[i]) + 1);
  }

  /* Push 0. */
  if_->rsp -= sizeof(uintptr_t);
  memset(if_->rsp, 0, sizeof(uintptr_t));

  /* Push arguments' address. */
  if_->rsp -= (args_cnt * sizeof(uintptr_t));
  des = if_->rsp;

  for (int i = 0; i < args_cnt; i++) {
    __asm __volatile(
        "movq %0, %%rax\n"
        "movq %1, %%rcx\n"
        "movq %%rax, (%%rcx)\n"
        :
        : "g"(cur), "g"(des)
        :);
    cur += (strlen(args[i]) + 1);
    des += sizeof(uintptr_t);
  }

  /* Set arguments. */
  if_->R.rsi = (uint64_t)if_->rsp;
  if_->R.rdi = (uint64_t)args_cnt;

  /* Push return address. */
  if_->rsp -= sizeof(uintptr_t);
  memset(if_->rsp, 0, sizeof(uintptr_t));

  /* Return value. */
  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  if (!success)
    file_close(file);
  else {
    /* Write exec file of this process. */
    t->exec_file = file;
  }
  return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Phdr *phdr, struct file *file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (uint64_t)file_length(file)) return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0) return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr)) return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz))) return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr) return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE) return false;

  /* It's okay. */
  return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool setup_stack(struct intr_frame *if_) {
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
    if (success)
      if_->rsp = USER_STACK;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable) {
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
   * address, then map our page there. */
  return (pml4_get_page(t->pml4, upage) == NULL &&
          pml4_set_page(t->pml4, upage, kpage, writable));
}

static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Do calculate how to fill this page.
     * We will read PAGE_READ_BYTES bytes from FILE
     * and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t *kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL) return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }

    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      printf("fail\n");
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on
 * the upper block. */

/* Load the segment from the file.
 * This called when the first page fault occurs on address VA.
 * VA is available when calling this function. */
static bool lazy_load_segment(struct page *page, void *aux) {
  struct thread *curr = thread_current();
  void *upage = page->va;

  /* Get a page of memory. */
  struct frame *frame = page->frame;
  void *kva = frame->kva;
  if (frame == NULL || kva == NULL) {
    printf("process.c:827 No frame is allocated.\n");
    return false;
  }

  /* File information to read. */
  struct file_info *file_info = (struct file_info *)aux;
  struct file *file = curr->exec_file;
  uint32_t bytes = file_info->bytes;
  off_t ofs = file_info->ofs;

  /* Load this page. */
  bool read_succ = true;
  lock_acquire(&load_lock);
  file_seek(file, ofs);
  if (file_read(file, kva, bytes) != (int)bytes) {
    printf("process.c:838 File is not read properly.\n");
    read_succ = false;
  }
  lock_release(&load_lock);
  if (!read_succ) return false;

  /* Free file info. */
  free(file_info);
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  off_t read_start = ofs;

  while (read_bytes > 0 || zero_bytes > 0) {
    /* Do calculate how to fill this page.
     * We will read PAGE_READ_BYTES bytes from FILE
     * and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* SPT - Set up aux to pass information to the lazy_load_segment. */
    struct file_info *aux = calloc(1, sizeof(struct file_info));
    aux->ofs = read_start;
    aux->bytes = page_read_bytes;

    if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable,
                                        lazy_load_segment, aux)) {
      return false;
    }

    /* Advance. */
    read_start += page_read_bytes;
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack(struct intr_frame *if_) {
  void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);
  bool success = false;

  /* Since addr is stack bottom, vm_alloc_page claims page immediately. */
  if (vm_alloc_page(VM_ANON, stack_bottom, true)) {
    if_->rsp = USER_STACK;
    success = true;
  }
  return success;
}
#endif /* VM */
