#include <stdio.h>
#include <string.h>

#ifndef __FILESYS_H__
#define __FILESYS_H__



int s_open (const char *pathname, int flags, mode_t mode);
int s_lseek (int fd, long offset, int whence);
ssize_t s_write (int fd, const void *buf, size_t count);
ssize_t s_read (int fd, void *buf, size_t count);
int s_close (int fd);
void get_sha1_hash (const void *buf, int len, const void *sha1);
int filesys_init (void);
int helper();
int read_into_array(char *ptr, FILE* sp);
void get_root_hash(FILE* sp,char* ptr);
void display();
void update_hash_val(char* rhash,char* filename);
int get_old_hash(char* ptrh,char* ptrn);

#endif
