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

IN_LINE long my_mprotect(void *start, long len, long prot){
    long res = 0;
    asm_mprotect((long)start,(long)len,(long)prot,res);
    return res;
}
IN_LINE long my_mmap(long addr, long length, int prot, int flags,
                     int fd, long offset){
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

#if(PATCH_DEBUG == 1)
IN_LINE int  my_strlen(const char *src){
    int i = 0;
    while(src[i]!='\0')
        i++;
    return i;
}

IN_LINE long my_write(int fd,const char* buf,long length){
    long res = 0;
    asm_write(fd,buf,length,res);
    return res;
}
IN_LINE void my_puts(char* str){
    char end[] = {"\n"};
    my_write(1,str,my_strlen(str));
    my_write(1,end,1);
}
#endif

#if(PATCH_DEBUG==1)
#define DEBUG_LOG(STR)  {char data[] = {STR};my_puts(data);}
#else
#define DEBUG_LOG(STR)
#endif

void _start(LIBC_START_MAIN_ARG,void* first_instruction,LOADER_STAGE_TWO* two_base){
    DEBUG_LOG("stage_two_start");
    Elf_Ehdr* ehdr = (Elf_Ehdr*)((char*)two_base+sizeof(LOADER_STAGE_TWO)+two_base->length + sizeof(LOADER_STAGE_THREE));
    LOADER_STAGE_THREE* three_base = (LOADER_STAGE_THREE*)((char*)two_base+sizeof(LOADER_STAGE_TWO)+two_base->length);
    three_base->patch_data_mmap_file_base = (void*)two_base;
    //todo elf_load_base should find an empty space, not just add 0x1000100
    char* elf_load_base = (char*)three_base->patch_data_mmap_file_base + 0x10001000 ;
    three_base->patch_data_mmap_code_base = elf_load_base;
    long map_size = 0;
    Elf_Phdr* phdr = NULL;
    for(int i=0;i<ehdr->e_phnum;i++){
        phdr = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + ehdr->e_phentsize*i);
        if(phdr->p_type == PT_LOAD){
            int flag = 0;
            if(phdr->p_flags & 0x1)
                flag |= PROT_EXEC;
            if(phdr->p_flags & 0x2)
                flag |= PROT_WRITE;
            if(phdr->p_flags & 0x4)
                flag |= PROT_READ;
            if((phdr->p_vaddr + phdr->p_memsz)%0x1000 == 0)
                map_size = phdr->p_vaddr + phdr->p_memsz  - DOWN_PADDING(phdr->p_vaddr,0x1000);
            else
                map_size = UP_PADDING(phdr->p_vaddr + phdr->p_memsz, 0x1000) - DOWN_PADDING(phdr->p_vaddr, 0x1000);
            /*if(elf_load_base == NULL) {
                elf_load_base = (char*)my_mmap(0,map_size , PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if(elf_load_base == NULL || elf_load_base == (char*)-1)
                    return;
                elf_load_base = elf_load_base - DOWN_PADDING(phdr->p_vaddr,0x1000);
                three_base->patch_data_mmap_code_base = elf_load_base;
            }
            else*/
                {
                my_mmap( DOWN_PADDING(elf_load_base + phdr->p_vaddr,0x1000), map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            }
            my_memcpy((elf_load_base + phdr->p_vaddr), ((char*)ehdr) + phdr->p_offset,phdr->p_filesz);
            my_mprotect((void*)(DOWN_PADDING((long)elf_load_base + phdr->p_vaddr,0x1000)),map_size,flag);
        }
    }
    DEBUG_LOG("stage_two_end");
    void(*patch_entry)(LIBC_START_MAIN_ARG_PROTO,void*,void*) = (void(*)(LIBC_START_MAIN_ARG_PROTO,void*,void*))((char*)elf_load_base + three_base->entry_offset);
    patch_entry(LIBC_START_MAIN_ARG_VALUE,first_instruction,(void*)three_base);
}