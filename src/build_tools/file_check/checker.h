//
// Created by root on 9/26/20.
//

#ifndef HOOKUTILV3_CHECKER_H
#define HOOKUTILV3_CHECKER_H

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


void check_so_file_no_rela_section(Elf_Ehdr* ehdr,char* file_name);
void check_so_file_no_dynsym_section(Elf_Ehdr* ehdr);
void check_so_file_no_rodata_section(Elf_Ehdr* ehdr);
void check_so_file_no_data_section(Elf_Ehdr* ehdr);
void check_so_file_no_got_section(Elf_Ehdr *ehdr);
void check_so_file_no_gotplt_section(Elf_Ehdr *ehdr);
void check_so_file_no_plt_section(Elf_Ehdr *ehdr);
void check_so_file_no_bss_section(Elf_Ehdr *ehdr);
void check_libloader_stage_three(char* libloader_stage_three);
void check_libloader_stage_two(char* libloader_stage_two);
void check_libloader_stage_one(char* libloader_stage_one);

#endif //HOOKUTILV3_CHECKER_H
