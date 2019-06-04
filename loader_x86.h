#include "config.h"
#define START()                                                                 \
        __asm__ __volatile__ ("pushl $" LIB_C_START_MAIN);                      \
        __asm__ __volatile__ ("lea [%eip],%ebp" );                              \
        __asm__ __volatile__ ("pushl %ebp");                                    \
        __asm__ __volatile__ ("movl %0,%%ebp"::"r"(__loader_start));            \
        __asm__ __volatile__ ("jmp *%ebp");

#define NO_AUX

#ifdef NO_AUX
#define LIBC_START_MAIN_ARG int(*MAIN)(int,char**,char**),int ARGC,char **UBP_AV,void(*INIT)(void),void(*FINI)(void),void(*RTLD_FINI)(void),void* STACK_END
#define LIBC_START_MAIN_ARG_PROTO int(*)(int,char**,char**),int,char **,void(*)(void),void(*)(void),void(*)(void),void*
#else

#endif