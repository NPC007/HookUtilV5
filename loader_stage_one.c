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


//#define IN_LINE static inline __attribute__((always_inline))
#define IN_LINE static

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
           int fd, off_t offset){
    long res = 0;
    asm_mmap(addr,(long)length,(long)prot,(long)flags,(long)fd,(long)offset,res);
    return res;
}

IN_LINE long my_munmap(void* addr,long length){
    long res = 0;
    asm_munmap((long)addr,(long)length,res);
    return res;
}

void _start(){
    START();
}


#if(CONFIG_LOADER_TYPE == LOAD_FROM_FILE)
unsigned long __loader_start(LIBC_START_MAIN_ARG, void* first_instruction){
    char patch_data[] = {PATCH_DATA_PATH};
    long patch_fd = my_open(patch_data,O_RDONLY,0);
    if(patch_fd < 0)
        goto failed_load_patch;
    char* mmap_addr = (char*)my_mmap(0,(int)UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000),PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE,patch_fd,0);
    if(mmap_addr == NULL || mmap_addr ==(char*)-1) {
        my_close(patch_fd);
        goto failed_load_patch;
    }
    void (*stage_two_entry)(LIBC_START_MAIN_ARG_PROTO,void*,void*) = (void(*)(LIBC_START_MAIN_ARG_PROTO,void*,void*))(mmap_addr+sizeof(LOADER_STAGE_TWO)+((LOADER_STAGE_TWO*)(mmap_addr))->entry_offset);
    stage_two_entry(LIBC_START_MAIN_ARG_VALUE,first_instruction,(void*)mmap_addr);
    failed_load_patch:
    if(mmap_addr>0)my_munmap((void*)mmap_addr,UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000));
#if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
    return *(long*)LIB_C_START_MAIN_ADDR;
#elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
    return LIB_C_START_MAIN_ADDR;
#endif
}


#elif(CONFIG_LOADER_TYPE == LOAD_FROM_MEM)
unsigned long  __loader_start(LIBC_START_MAIN_ARG,void* first_instruction){
    void* base = (void*)DOWN_PADDING((long)_start,0x1000)+0x1000;
    void (*stage_two_entry)(LIBC_START_MAIN_ARG_PROTO,void*,void*) = (void(*)(LIBC_START_MAIN_ARG_PROTO,void*,void*))(base+sizeof(LOADER_STAGE_TWO)+((LOADER_STAGE_TWO*)(base))->entry_offset);
    stage_two_entry(LIBC_START_MAIN_ARG_VALUE,first_instruction,(void*)base);
    my_munmap((void*)base,UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000));
#if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
    return *(long*)LIB_C_START_MAIN_ADDR;
#elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
    return LIB_C_START_MAIN_ADDR;
#endif
}
#elif(CONFIG_LOADER_TYPE == LOAD_FROM_SHARE_MEM)
IN_LINE unsigned long  __loader_start(LIBC_START_MAIN_ARG,void* first_instruction){
    failed_load_patch:
#if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
    return *(long*)LIB_C_START_MAIN_ADDR;
#elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
    return LIB_C_START_MAIN_ADDR;
#endif
}
#elif(CONFIG_LOADER_TYPE == LOAD_FROM_SOCKET)
IN_LINE unsigned long  __loader_start(LIBC_START_MAIN_ARG,void* first_instruction){
    failed_load_patch:
#if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
    return *(long*)LIB_C_START_MAIN_ADDR;
#elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
    return LIB_C_START_MAIN_ADDR;
#endif
}
#endif

#if __i386__
void* get_eip(){
    return get_eip;
}
#endif