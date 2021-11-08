#include <stddef.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include "include/hook.h"
#include "debug_config.h"
#include "stage_one_config.h"
#include "arch/common/arch.h"

#ifdef OFFSET
    #define ASM_JUMP  asm volatile("jmp " OFFSET);
#else
    #define ASM_JUMP return;
#endif
#if PATCH_DEBUG
#define DEBUG_LOG(STR)  do{char data[] = {STR "\n"};my_write_stdout(data);}while(0)
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
#else
#define DEBUG_LOG(STR)
#endif

extern void _start();



#if(CONFIG_LOADER_TYPE == LOAD_FROM_FILE)
__attribute__((section(".text"))) __attribute__((aligned(1))) char patch_data[] = {PATCH_DATA_PATH};


void __loader_start(){
    int patch_fd = 0;
    long res = 0;
    char *g_elf_base;
// #if(IS_PIE==1)
// #ifdef __x86_64__
//     asm volatile("lea -7(%rip), %r15");
// #elif __i386__
//     asm volatile("push %eip");
// #endif
// #endif
#ifdef __x86_64__
    // asm volatile("mov %rsp, %r14"); 
#elif __i386__
    // asm volatile("push %esp");
    asm volatile("lea %0, %%ebx"::"m"(patch_data));
    // register long patch asm("ebx") = patch_data;
    // long __attribute__((register("ebx"))) ebx = patch_data;

#endif

    // DEBUG_LOG("__loader_start from file");

    asm_open_one(patch_data,O_RDONLY,0,patch_fd);
    if(patch_fd < 0){
        asm volatile("xor %ebx,%ebx");
        ASM_JUMP
    }

#ifdef __i386__
    asm volatile("mov %edx, %ebx"); //arg 0
    asm volatile("mov %eax, %edi"); //arg 5  fd
#endif
    char* mmap_addr = NULL;
    asm_mmap_one(0,(int)UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000),PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE,patch_fd,0,mmap_addr);
    // asm_close(3, res);
#ifdef __x86_64__
    asm volatile("add $0x18, %rax");
    asm volatile("call %rax");
#elif __i386__
    asm volatile("add $0x10, %eax");
    // asm volatile("pop %ebp");
    asm volatile("call %eax");
#endif


    // void (*stage_two_entry)(STAGE_TWO_MAIN_ARG_PROTO) = (void (*)(STAGE_TWO_MAIN_ARG_PROTO))(mmap_addr + sizeof(LOADER_STAGE_TWO));
    // stage_two_entry(STAGE_TWO_MAIN_ARG_VALUE);
    //好家伙，一行c语言不写就可以规避多余的寄存器保护了
    //好家伙，x86还是会push寄存器
}

// unsigned long __loader_start(){
//     long patch_fd = 0;
//     long res = 0;
//     char *g_elf_base;
//     int size = (int)UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE, 0x1000);
//     asm volatile("mov %rsp, %rbp");
//     asm volatile("xor %edx, %edx");
//     // asm volatile("lea %0, %%rdi"::""(&patch_data));
//     asm volatile("mov %rdx, %rsi");
//     asm volatile("push 2");
//     asm volatile("pop %rax");
//     asm volatile("syscall"::"D"((long)patch_data));
//     asm volatile("xor %r9d, %r9d");
//     asm volatile("mov %rax, %r8");
//     asm volatile("mov %0，%%esi"::"i"(size));
//     asm volatile("mov %rdx, %rdi");
//     asm volatile("push 9");
//     asm volatile("pop %rax");
//     asm volatile("push 7");
//     asm volatile("pop %rdx");
//     asm volatile("push 2");
//     asm volatile("pop r10");
//     asm volatile("syscall":"=a"(res));
//     asm volatile("add $0x18, %rax");
//     asm volatile("mov %rbp, %rdi");
//     asm volatile("call %rax");
// }


#elif(CONFIG_LOADER_TYPE == LOAD_FROM_MEM)


unsigned long  __loader_start(STAGE_ONE_MAIN_ARG){
    DEBUG_LOG("__loader_start from memory");
#if(IS_PIE == 0)
    void* base = (void*)PATCH_DATA_MMAP_FILE_VADDR;
#elif(IS_PIE == 1)
    void* base = (char*)DOWN_PADDING((char*)_start - FIRST_ENTRY_OFFSET,0x1000) + PATCH_DATA_MMAP_FILE_VADDR;
#else
#error "Unknown IS_PIE"
#endif



#if(IS_PIE == 0)
#elif(IS_PIE == 1)
    //LOADER_STAGE_TWO *two_base = (LOADER_STAGE_TWO *)base;
    //two_base ->elf_load_base = (char*)_start - FIRST_ENTRY_OFFSET;
    //two_base ->elf_load_base = FIRST_ENTRY_OFFSET;
#else
    #error "Unknown IS_PIE"
#endif

    void (*stage_two_entry)(STAGE_TWO_MAIN_ARG_PROTO) = (void (*)(STAGE_TWO_MAIN_ARG_PROTO))(base + sizeof(LOADER_STAGE_TWO));
    stage_two_entry(STAGE_TWO_MAIN_ARG_VALUE);

#if(IS_PIE == 0)
    #if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
    return *(unsigned long*)LIB_C_START_MAIN_ADDR;
    #elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
    return LIB_C_START_MAIN_ADDR;
    #endif
#elif(IS_PIE == 1)
    char *g_elf_base = (char*)_start - FIRST_ENTRY_OFFSET;
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
#define IPC_CREAT        01000                /* Create key if key does not exist. */
#define IPC_EXCL        02000                /* Fail if key exists.  */
#define IPC_NOWAIT        04000                /* Return error on wait.  */
#define SHM_R                0400        /* or S_IRUGO from <linux/stat.h> */
#define SHM_W                0200        /* or S_IWUGO from <linux/stat.h> */
#define        SHM_RDONLY        010000        /* read-only access */
#define        SHM_RND                020000        /* round attach address to SHMLBA boundary */
#define        SHM_REMAP        040000        /* take-over region on attach */
#define        SHM_EXEC        0100000        /* execution access */

// unsigned long  __loader_start(STAGE_ONE_MAIN_ARG){
//     register char *g_elf_base;
//     register long res;
//     asm_shmget(PATCH_DATA_SHARE_MEM_ID,(int)UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000),0777,res);
//     if((unsigned long)res>= ((unsigned long)-1) - 0x1000) {
//         if (res < 0) {
//             goto failed_load_patch;
//         }
//     }
//     asm_shmat(res,0,SHM_EXEC|SHM_R|SHM_W, res);
// #ifdef __i386__
//     if((unsigned long)res>= ((unsigned long)-1) - 0x1000) {
//         goto failed_load_patch;
//     }
// #elif __x86_64__
//    /* if(res < 0) {
//         goto failed_load_patch;
//     }*/
// #else
// #error unsupport other arch
// #endif

//     register void* base = (void*)res;

// #if(IS_PIE == 0)
// #elif(IS_PIE == 1)
//     //LOADER_STAGE_TWO *two_base = (LOADER_STAGE_TWO *)base;
//     //two_base ->elf_load_base = (char*)_start - FIRST_ENTRY_OFFSET;
//     //two_base ->elf_load_base = FIRST_ENTRY_OFFSET;
// #else
//     #error "Unknown IS_PIE"
// #endif

//     //void (*stage_two_entry)(STAGE_TWO_MAIN_ARG_PROTO) = (void (*)(STAGE_TWO_MAIN_ARG_PROTO))(base + two_base->entry_offset + sizeof(LOADER_STAGE_TWO));
//     void (*stage_two_entry)(STAGE_TWO_MAIN_ARG_PROTO) = (void (*)(STAGE_TWO_MAIN_ARG_PROTO))(base + sizeof(LOADER_STAGE_TWO));
//     stage_two_entry(STAGE_TWO_MAIN_ARG_VALUE);

//     failed_load_patch:
// #if(IS_PIE == 0)
//     #if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
//     return *(unsigned long*)LIB_C_START_MAIN_ADDR;
//     #elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
//         return LIB_C_START_MAIN_ADDR;
//     #endif

// #elif(IS_PIE == 1)
//     g_elf_base = (char*)_start - FIRST_ENTRY_OFFSET;
//     #if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
//         return *(unsigned long*)(g_elf_base + LIB_C_START_MAIN_ADDR);
//     #elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
//         return (unsigned long)(g_elf_base + LIB_C_START_MAIN_ADDR);
//     #endif
// #else
// #error "Unknown IS_PIE"
// #endif
// }

unsigned long  __loader_start(){
    //long res = 0;
    int res = 0;
    #ifdef __i386__
    #elif __x86_64__
    #endif
    asm_shmget_one(PATCH_DATA_SHARE_MEM_ID,(int)UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000),0777,res);
    #ifdef __i386__
    asm volatile("mov %eax,%ebx");
    #elif __x86_64__
    #endif
    asm_shmat_one(res,0,SHM_EXEC|SHM_R|SHM_W, res);

    // register void (*base)() = (void*)res+sizeof(LOADER_STAGE_TWO);
#ifdef __x86_64__
    asm volatile("add $0x18, %rax");
    asm volatile("call %rax");
#elif __i386__
    asm volatile("add $0x10, %eax");
    asm volatile("push %esp");
    asm volatile("pop %ebp");
    asm volatile("call %eax");
#endif

}
#elif(CONFIG_LOADER_TYPE == LOAD_FROM_SOCKET)


unsigned long  __loader_start(STAGE_ONE_MAIN_ARG){
    //if(((long)_start / 0x1000) %10 ==0)
    //    goto failed_load_patch;
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
    int need_count = PATCH_DATA_MMAP_FILE_SIZE;
    while(need_count > 0){
        asm_read(patch_fd,mmap_addr + (PATCH_DATA_MMAP_FILE_SIZE - need_count),need_count,ret);
        if (ret < 0)
            goto failed_load_patch;
        else
            need_count = need_count - ret;
    }


#if(IS_PIE == 0)
#elif(IS_PIE == 1)
    //LOADER_STAGE_TWO *two_base = (LOADER_STAGE_TWO *)mmap_addr;
    //two_base ->elf_load_base = (char*)_start - FIRST_ENTRY_OFFSET;
    //two_base ->elf_load_base = FIRST_ENTRY_OFFSET;
#else
    #error "Unknown IS_PIE"
#endif


    //void (*stage_two_entry)(STAGE_TWO_MAIN_ARG_PROTO) = (void (*)(STAGE_TWO_MAIN_ARG_PROTO))(mmap_addr + two_base->entry_offset + sizeof(LOADER_STAGE_TWO));
    void (*stage_two_entry)(STAGE_TWO_MAIN_ARG_PROTO) = (void (*)(STAGE_TWO_MAIN_ARG_PROTO))(mmap_addr + sizeof(LOADER_STAGE_TWO));
    stage_two_entry(STAGE_TWO_MAIN_ARG_VALUE);



    char *g_elf_base;
failed_load_patch:
    //if(mmap_addr>0)asm_munmap((void*)mmap_addr,UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000),res);
#if(IS_PIE == 0)
    #if  (LIBC_START_MAIN_ADDR_TYPE == PTR)
    return *(unsigned long*)LIB_C_START_MAIN_ADDR;
#elif(LIBC_START_MAIN_ADDR_TYPE == CODE)
    return LIB_C_START_MAIN_ADDR;
#endif
#elif(IS_PIE == 1)
    g_elf_base = (char*)_start - FIRST_ENTRY_OFFSET;
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
