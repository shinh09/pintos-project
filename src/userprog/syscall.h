#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/kernel/list.h"

void syscall_init (void);

typedef int tid_t;

struct file_descriptor {
    int fd_num;
    tid_t owner;
    struct file *file_struct;
    struct list_elem elem;
};

#endif /* userprog/syscall.h */
