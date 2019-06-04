#include "config.h"
#include "hook.h"
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include "errno.h"
#include <sys/select.h>

/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <elf.h>


#ifdef __x86_64__
#include "x64_syscall.h"
#include "loader_x64.h"
#elif __i386__
#include "x86_syscall.h"
#include "loader_x86.h"
#elif __arm__
#include "arm_syscall.h"
#include "loader_arm.h"
#elif __aarch64__
#include "aarch64_syscall.h"
#include "loader_aarch64.h"
#elif __mips__
#include "mips_syscall.h"
#include "loader_mips.h"
#endif


#define IN_LINE static inline __attribute__((always_inline))

IN_LINE long my_open(char* name,long mode,long flag){
    long res = 0;
    asm_open(name,mode,flag,res);
    return res;
}
IN_LINE long my_close(long fd){
    long res = 0;
    asm_close(fd,res);
    return res;
}

IN_LINE long my_mprotect(void *start, size_t len, long prot){
    long res = 0;
    asm_mprotect((long)start,(long)len,(long)prot,res);
    return res;
}
IN_LINE long my_mmap(long addr, size_t length, int prot, int flags,
                     int fd, off_t offset){
    long res = 0;
    asm_mmap(addr,(long)length,(long)prot,(long)flags,(long)fd,(long)offset,res);
    return res;
}
IN_LINE int  my_memcpy(char *dst, const char *src,int len){
    int i = 0;
    while(i<len){
        dst[i] = src[i];
        i++;
    }
    return 0;
}

IN_LINE void my_memset(char *dst,char chr,int len){
    int i = 0;
    for(i=0;i<len;i++)
        dst[i] = chr;
}


void loader_stage_two_start(LIBC_START_MAIN_ARG, int(*__libc_start_main)(LIBC_START_MAIN_ARG_PROTO),void* first_instruction){
    HOOK_CODE *code_stage_one = (HOOK_CODE*)(PATCH_DATA_MMAP_FILE_BASE);
    char* loader_stage_two = (char*)(PATCH_DATA_MMAP_FILE_BASE+sizeof(HOOK_CODE)+code_stage_one->length+sizeof(HOOK_CODE));
    Elf_Ehdr* ehdr = (Elf_Ehdr*)(loader_stage_two+sizeof(HOOK_CODE));
    char* elf_load_base = (char*)(PATCH_DATA_MMAP_CODE_BASE);
    for(int i=0;i<ehdr->e_phnum;i++){
        Elf_Phdr* phdr = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + ehdr->e_phentsize*i);
        if(phdr->p_type == PT_LOAD){
            int flag = 0;
            if(phdr->p_flags & 0x1)
                flag |= PROT_EXEC;
            if(phdr->p_flags & 0x2)
                flag |= PROT_WRITE;
            if(phdr->p_flags & 0x4)
                flag |= PROT_READ;
            my_mmap(DOWN_PADDING(elf_load_base + phdr->p_vaddr,0x1000),UP_PADDING(phdr->p_memsz,0x1000),PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
            my_memcpy((elf_load_base + phdr->p_vaddr), ((char*)ehdr) + phdr->p_offset,phdr->p_filesz);
            my_memset(((char*)ehdr) + phdr->p_offset,0xFF,phdr->p_filesz);
            my_mprotect(DOWN_PADDING(elf_load_base + phdr->p_vaddr,0x1000),UP_PADDING(phdr->p_memsz,0x1000),flag);
        }
    }
    int(*patch_entry)(LIBC_START_MAIN_ARG_PROTO,int(*)(LIBC_START_MAIN_ARG_PROTO),void*) = (int(*)(LIBC_START_MAIN_ARG_PROTO,int(*)(LIBC_START_MAIN_ARG_PROTO),void*))((char*)loader_stage_two + ((HOOK_CODE*)loader_stage_two)->entry);
    patch_entry(MAIN,ARGC,UBP_AV,INIT,FINI,RTLD_FINI,STACK_END,__libc_start_main,first_instruction);
}