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
#include <sys/time.h>
#include <sys/types.h>
#include <elf.h>

#include "arch/common/arch.h"


#ifdef PATCH_DEBUG
static int my_strlen(const char *src){
    int i = 0;
    while(src[i]!='\0')
        i++;
    return i;
}
static void my_write_stdout(const char* str){
    long res;
    asm_write(1,str,my_strlen(str),res);
}
#endif


#if(CONFIG_LOADER_TYPE == LOAD_FROM_FILE)

unsigned long __loader_start(LIBC_START_MAIN_ARG, void* first_instruction){
    char patch_data[] = {PATCH_DATA_PATH};
    long patch_fd = 0;
    long res = 0;
    DEBUG_LOG("__loader_start from file");
    asm_open(patch_data,O_RDONLY,0,patch_fd);
    if(patch_fd < 0)
        goto failed_load_patch;
    char* mmap_addr = NULL;
    asm_mmap(0,(int)UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000),PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE,patch_fd,0,mmap_addr);
    if((unsigned long)mmap_addr>= ((unsigned long)-1) - 0x1000) {
        asm_close(patch_fd,res);
        goto failed_load_patch;
    }
    void (*stage_two_entry)(LIBC_START_MAIN_ARG_PROTO,void*,void*) = (void(*)(LIBC_START_MAIN_ARG_PROTO,void*,void*))(mmap_addr+sizeof(LOADER_STAGE_TWO)+((LOADER_STAGE_TWO*)(mmap_addr))->entry_offset);
    stage_two_entry(LIBC_START_MAIN_ARG_VALUE,first_instruction,(void*)mmap_addr);
    failed_load_patch:
    if(mmap_addr>0)asm_munmap((void*)mmap_addr,UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000),res);
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
    DEBUG_LOG("__loader_start from memory");
#if(IS_PIE == 0)
    void* base = (void*)PATCH_DATA_MMAP_FILE_VADDR;
#elif(IS_PIE == 1)
    void* base = (char*)DOWN_PADDING((char*)first_instruction - FIRST_ENTRY_OFFSET,0x1000) + PATCH_DATA_MMAP_FILE_VADDR;
#else
#error "Unknown IS_PIE"
#endif

    void (*stage_two_entry)(LIBC_START_MAIN_ARG_PROTO,void*,void*) = (void(*)(LIBC_START_MAIN_ARG_PROTO,void*,void*))(base+sizeof(LOADER_STAGE_TWO)+((LOADER_STAGE_TWO*)(base))->entry_offset);
    stage_two_entry(LIBC_START_MAIN_ARG_VALUE,first_instruction,(void*)base);
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
unsigned long  __loader_start(LIBC_START_MAIN_ARG,void* first_instruction){
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
    long patch_fd = 0;
    long res = 0;
    asm_socket(AF_INET,SOCK_STREAM,0,patch_fd);
    if(patch_fd < 0)
        goto failed_load_patch;
    char* mmap_addr = NULL;
    asm_mmap(0,(int)UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000),PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS,-1,0,mmap_addr);
    if((unsigned long)mmap_addr>= ((unsigned long)-1) - 0x1000) {
        asm_close(patch_fd,res);
        goto failed_load_patch;
    }
    struct sockaddr_in server;
    server.sin_addr.s_addr = PATCH_DATA_SOCKET_SERVER_IP;
    server.sin_family = AF_INET;
    server.sin_port = PATCH_DATA_SOCKET_SERVER_PORT;
    long status = 0;
    asm_connect(patch_fd, (void*)&server, sizeof(server),status);
    if(status < 0 )
        goto failed_load_patch;
    int ret = 0;
    asm_read(patch_fd,mmap_addr,PATCH_DATA_MMAP_FILE_SIZE,ret);
    if (ret < 0)
        goto failed_load_patch;
    void (*stage_two_entry)(LIBC_START_MAIN_ARG_PROTO,void*,void*) = (void(*)(LIBC_START_MAIN_ARG_PROTO,void*,void*))(mmap_addr+sizeof(LOADER_STAGE_TWO)+((LOADER_STAGE_TWO*)(mmap_addr))->entry_offset);
    stage_two_entry(LIBC_START_MAIN_ARG_VALUE,first_instruction,(void*)mmap_addr);
    failed_load_patch:
    if(mmap_addr>0)asm_munmap((void*)mmap_addr,UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000),res);
#if(IS_PIE == 0)
    #if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
    return *(unsigned long*)LIB_C_START_MAIN_ADDR;
#elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
    return LIB_C_START_MAIN_ADDR;
#endif
#elif(IS_PIE == 1)
    char *g_elf_base = (char*)DOWN_PADDING((char*)first_instruction - FIRST_ENTRY_OFFSET,0x1000);
#if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
    return *(unsigned long*)(g_elf_base + LIB_C_STAR T_MAIN_ADDR);
#elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
    return (unsigned long)(g_elf_base + LIB_C_START_MAIN_ADDR);
#endif
#else
#error "Unknown IS_PIE"
#endif
}
#endif

