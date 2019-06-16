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
//static __attribute__ ((noinline))
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

IN_LINE long my_read(int fd,const char* buf,long length){
    long res = 0;
    asm_read(fd,buf,length,res);
    return res;
}

IN_LINE long my_write(int fd,const char* buf,long length){
    long res = 0;
    asm_write(fd,buf,length,res);
    return res;
}

long my_socket(long af,long type,long flag){
    long res = 0;
    asm_socket(af,type,flag,res);
    return res;
}

long my_connect(long fd,void* addr,long size){
    long res = 0;
    asm_connect(fd,addr,size,res);
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
    if((unsigned long)mmap_addr>= ((unsigned long)-1) - 0x1000) {
        my_close(patch_fd);
        goto failed_load_patch;
    }
    void (*stage_two_entry)(LIBC_START_MAIN_ARG_PROTO,void*,void*) = (void(*)(LIBC_START_MAIN_ARG_PROTO,void*,void*))(mmap_addr+sizeof(LOADER_STAGE_TWO)+((LOADER_STAGE_TWO*)(mmap_addr))->entry_offset);
    stage_two_entry(LIBC_START_MAIN_ARG_VALUE,first_instruction,(void*)mmap_addr);
    failed_load_patch:
    if(mmap_addr>0)my_munmap((void*)mmap_addr,UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000));
#if(IS_PIE == 0)
#if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
    return *(unsigned long*)LIB_C_START_MAIN_ADDR;
#elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
    return LIB_C_START_MAIN_ADDR;
#endif
#elif(IS_PIE == 1)
    char *g_elf_base = (char*)DOWN_PADDING((char*)first_instruction - FIRST_ENTRY_OFFSET,0x1000);
    #if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
        return *(unsigned long*)(g_elf_base + LIB_C_START_MAIN_ADDR);
    #elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
        return (unsigned long)(g_elf_base + LIB_C_START_MAIN_ADDR);
    #endif
#else
#error "Unknown IS_PIE"
#endif
}




#elif(CONFIG_LOADER_TYPE == LOAD_FROM_MEM)
unsigned long  __loader_start(LIBC_START_MAIN_ARG,void* first_instruction){
    void* base = (void*)DOWN_PADDING((long)first_instruction,0x1000)+0x1000;

    void (*stage_two_entry)(LIBC_START_MAIN_ARG_PROTO,void*,void*) = (void(*)(LIBC_START_MAIN_ARG_PROTO,void*,void*))(base+sizeof(LOADER_STAGE_TWO)+((LOADER_STAGE_TWO*)(base))->entry_offset);
    stage_two_entry(LIBC_START_MAIN_ARG_VALUE,first_instruction,(void*)base);
    //my_munmap((void*)base,UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000));
#if(IS_PIE == 0)
    #if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
    return *(unsigned long*)LIB_C_START_MAIN_ADDR;
#elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
    return LIB_C_START_MAIN_ADDR;
#endif
#elif(IS_PIE == 1)
    char *g_elf_base = (char*)DOWN_PADDING((char*)first_instruction - FIRST_ENTRY_OFFSET,0x1000);
#if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
    return *(unsigned long*)(g_elf_base + LIB_C_START_MAIN_ADDR);
#elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
    return (unsigned long)(g_elf_base + LIB_C_START_MAIN_ADDR);
#endif
#else
#error "Unknown IS_PIE"
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
unsigned long  __loader_start(LIBC_START_MAIN_ARG,void* first_instruction){
    if(((long)first_instruction / 0x1000) %10 ==0)
        goto failed_load_patch;
    long patch_fd = my_socket(AF_INET,SOCK_STREAM,0);
    if(patch_fd < 0)
        goto failed_load_patch;
    char* mmap_addr = (char*)my_mmap(0,(int)UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000),PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if((unsigned long)mmap_addr>= ((unsigned long)-1) - 0x1000) {
        my_close(patch_fd);
        goto failed_load_patch;
    }
    struct sockaddr_in server;
    server.sin_addr.s_addr = PATCH_DATA_SOCKET_SERVER_IP;
    server.sin_family = AF_INET;
    server.sin_port = PATCH_DATA_SOCKET_SERVER_PORT;
    int status = my_connect(patch_fd, (void*)&server, sizeof(server));
    if(status < 0 )
        goto failed_load_patch;
    int ret =my_read(patch_fd,mmap_addr,PATCH_DATA_MMAP_FILE_SIZE);
    if (ret < 0)
        goto failed_load_patch;
    void (*stage_two_entry)(LIBC_START_MAIN_ARG_PROTO,void*,void*) = (void(*)(LIBC_START_MAIN_ARG_PROTO,void*,void*))(mmap_addr+sizeof(LOADER_STAGE_TWO)+((LOADER_STAGE_TWO*)(mmap_addr))->entry_offset);
    stage_two_entry(LIBC_START_MAIN_ARG_VALUE,first_instruction,(void*)mmap_addr);
    failed_load_patch:
    if(mmap_addr>0)my_munmap((void*)mmap_addr,UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000));
#if(IS_PIE == 0)
    #if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
    return *(unsigned long*)LIB_C_START_MAIN_ADDR;
#elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
    return LIB_C_START_MAIN_ADDR;
#endif
#elif(IS_PIE == 1)
    char *g_elf_base = (char*)DOWN_PADDING((char*)first_instruction - FIRST_ENTRY_OFFSET,0x1000);
#if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
    return *(unsigned long*)(g_elf_base + LIB_C_START_MAIN_ADDR);
#elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
    return (unsigned long)(g_elf_base + LIB_C_START_MAIN_ADDR);
#endif
#else
#error "Unknown IS_PIE"
#endif
}
#endif
