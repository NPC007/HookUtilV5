#include "config.h"
#define START()                                                                  \
        __asm__ __volatile__ ("pushq $" LIB_C_START_MAIN);                       \
        __asm__ __volatile__ ("lea [%rip],%rbp");                                \
        __asm__ __volatile__ ("pushq %rbp");                                     \
        __asm__ __volatile__ ("movq %0,%%rbp"::"a"(__loader_start));             \
        __asm__ __volatile__ ("jmp *%rbp");

#define NO_AUX

#ifdef NO_AUX
#define LIBC_START_MAIN_ARG int(*MAIN)(int,char**,char**),int ARGC,char **UBP_AV,void(*INIT)(void),void(*FINI)(void),void(*RTLD_FINI)(void),void* STACK_END
#define LIBC_START_MAIN_ARG_PROTO int(*)(int,char**,char**),int,char **,void(*)(void),void(*)(void),void(*)(void),void*
#else

#endif