#ifndef __ARCH_H__
#define __ARCH_H__

#if(PATCH_DEBUG == 1)
#define IN_LINE static
#define DEBUG_LOG(STR)  {char data[] = {STR};my_puts(data);}
#else
#define IN_LINE static inline __attribute__((always_inline))
#define DEBUG_LOG(format,...)
#endif




#ifdef __x86_64__
#include "../amd64/x64_syscall.h"
#include "../amd64/loader_x64.h"
#elif __i386__
#include "../i386/x86_syscall.h"
#include "../i386/loader_x86.h"
#elif __arm__

#elif __aarch64__

#elif __mips__

#endif


#endif