#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool
is_valid_ptr(const void *usr_ptr)
{
    struct thread *cur;

    /* 1. Get current thread */
    cur = thread_current();

    /* 2. Basic checks */
    if (usr_ptr == NULL) {
        return false;
    }
    if (!is_user_vaddr(usr_ptr)) {
        return false;
    }

    /* 3. Page directory check */
    if (pagedir_get_page(cur->pagedir, usr_ptr) == NULL) {
        return false;
    }

    return true;
}

static void
syscall_handler (struct intr_frame *f) 
{
  void *esp;
  int syscall_number;

  esp = f->esp;

  /* 1. Validate stack pointer */
  if (!is_valid_ptr(esp)) {
  exit(-1);  /* or thread_exit(), depending on your policy */
  }

  /* 2. Extract system call number */
  syscall_number = *(int *)esp;

  /* 3. Process system call */
  switch (syscall_number) {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    if (!is_valid_ptr(esp + 4)) {
      exit(-1);
    }
    exit(*(int *)(esp + 4));
    break;
  case SYS_EXEC:
    if (!is_valid_ptr(esp + 4)) {
      exit(-1);
    }
    f->eax = exec(*(char **)(esp + 4));
    break;
  case SYS_WAIT:
    if (!is_valid_ptr(esp + 4)) {
      exit(-1);
    }
    f->eax = wait(*(pid_t *)(esp + 4));
    break;
  /* Add other cases here */
  default:
    exit(-1);
    break;
  }
}
