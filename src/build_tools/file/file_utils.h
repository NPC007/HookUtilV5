//
// Created by root on 9/26/20.
//

#ifndef HOOKUTILV3_FILE_UTILS_H
#define HOOKUTILV3_FILE_UTILS_H

#include <elf.h>
#include "include/hook.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>


long get_file_size(char* file);
long padding_size(long size);
void write_file_line(int fd,char* line);
void write_marco_define(int fd,char* marco_name,char* marco_value);
void write_marco_str_define(int fd,char* marco_name,char* marco_value);
void increase_file(char* file,int total_length);
char* get_file_content(char* config_file_name);
char* get_file_content_length(char* file,int offset,int len);
void copy_file(char* old_file,char* new_file);
void open_mmap_check(char* file_name,int mode,int *fd,void** mmap_base,int prot,int flag,long* size);
void close_and_munmap(char* file_name,int fd,char* base,long *size);
void init_logger(char* name,int re_create);
int check_file_exist(const char* file_name);
void logger(const char* format,...);

#endif //HOOKUTILV3_FILE_UTILS_H
