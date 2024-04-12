#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
// #include "threads/synch.h"
void syscall_init (void);
/* ---- Project 2 : File Descriptor ---- */
/* 파일 사용 시 lock하여 상호배제 구현 */
struct lock filesys_lock;
#endif /* userprog/syscall.h */
