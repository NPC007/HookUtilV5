//
// Created by root on 9/26/20.
//

#ifndef HOOKUTILV3_ELF_UTILS_H
#define HOOKUTILV3_ELF_UTILS_H

#include <elf.h>
#include "include/hook.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <elf.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <capstone/capstone.h>
#include "utils/common.h"
#include "utils/md5.h"


Elf_Phdr* get_elf_phdr_type(void* elf_base,int type);
Elf_Dyn* get_elf_dyn_by_type(void* elf_base,int type);
Elf_Shdr* get_elf_section_by_index(long index,Elf_Ehdr* elf_base);
Elf_Shdr* get_elf_shstrtab(Elf_Ehdr* elf_base);
Elf_Shdr* get_elf_section_by_type(int type,Elf_Ehdr* elf_base);
Elf_Shdr* get_elf_section_by_name(char* section_name,Elf_Ehdr* elf_base);
unsigned long get_offset_by_vaddr(unsigned long v_addr,Elf_Ehdr* elf_base);
void get_section_data(Elf_Ehdr* ehdr,char* section_name,void** buf,int* len);
void get_section_data_from_file(char* file,char* section_name,void** buf,int* len);
unsigned long get_elf_load_base(Elf_Ehdr *ehdr);


void _add_segment_desc(char* elf_base,Elf_Phdr* phdr);

void add_segment(char* elf_file,Elf_Phdr* phdr);

#define MAX_SO_FILE_SIZE 0x1000000
void _padding_elf(char* elf_file_base,char *elf_file);
void padding_elf(char *elf_file);

void mov_phdr(char* elf_file);
unsigned long get_elf_file_load_base(char* elf_file);

void check_elf_arch(char* file_name);

#endif //HOOKUTILV3_ELF_UTILS_H
