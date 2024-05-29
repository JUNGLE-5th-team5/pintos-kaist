#include "include/threads/synch.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
struct lock filesys_lock;

void check_address(void *addr);
void get_argument(void *rsp, int *arg, int count);
bool remove(const char *file);
bool create(const char *file, unsigned initial_size);
void halt(void);
void exit(int status);
int write(int fd, const void *buffer, unsigned length);
int read(int fd, void *buffer, unsigned size);
int exec(const char *file);
int open(const char *file);
void close(int fd);
int filesize(int fd);
void seek(int fd, unsigned position);
unsigned tell(int fd);

#endif /* userprog/syscall.h */
