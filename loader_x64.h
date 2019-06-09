#include "config.h"

#define NO_AUX

#ifdef NO_AUX
//rax in start function is unused,just for padding, so wo need not to push it in our function
#define START()                                                                  \
        __asm__ __volatile__ ("movq 0x10(%rsp),%rax");                           \
        __asm__ __volatile__ ("movq 0x18(%rsp),%rbx");                           \
        __asm__ __volatile__ ("pushq %rdi");                                     \
        __asm__ __volatile__ ("pushq %rsi");                                     \
        __asm__ __volatile__ ("pushq %rdx");                                     \
        __asm__ __volatile__ ("pushq %rcx");                                     \
        __asm__ __volatile__ ("pushq %r8");                                      \
        __asm__ __volatile__ ("pushq %r9");                                      \
        __asm__ __volatile__ ("lea -0x19(%rip),%rbp");                           \
        __asm__ __volatile__ ("pushq %rbp");                                     \
        __asm__ __volatile__ ("pushq %rbx");                                     \
        __asm__ __volatile__ ("call __loader_start");                            \
        __asm__ __volatile__ ("popq %rbx");                                      \
        __asm__ __volatile__ ("popq %rbx");                                      \
        __asm__ __volatile__ ("popq %r9");                                       \
        __asm__ __volatile__ ("popq %r8");                                       \
        __asm__ __volatile__ ("popq %rcx");                                      \
        __asm__ __volatile__ ("popq %rdx");                                      \
        __asm__ __volatile__ ("popq %rsi");                                      \
        __asm__ __volatile__ ("popq %rdi");                                      \
        __asm__ __volatile__ ("jmp *%rax");

#define LIBC_START_MAIN_ARG int(*MAIN)(int,char**,char**),int ARGC,char **UBP_AV,void(*INIT)(void),void(*FINI)(void),void(*RTLD_FINI)(void),void* STACK_END
#define LIBC_START_MAIN_ARG_PROTO int(*)(int,char**,char**),int,char **,void(*)(void),void(*)(void),void(*)(void),void*
#define LIBC_START_MAIN_ARG_VALUE MAIN,ARGC,UBP_AV,INIT,FINI,RTLD_FINI,STACK_END
#else

#endif