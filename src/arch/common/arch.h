#ifndef __ARCH_H__
#define __ARCH_H__

#if(PATCH_DEBUG == 1)
#define IN_LINE static
#else
#define IN_LINE static inline __attribute__((always_inline))
#endif




#ifdef __x86_64__

#include "../amd64/x64_syscall.h"
#include "../amd64/loader_x64.h"

#elif __i386__

#include "../i386/x86_syscall.h"
#include "../i386/loader_x86.h"

#elif __arm__

#include "../arm/arm_syscall.h"
#include "../arm/loader_arm.h"

#elif __aarch64__

#elif __mips__

#endif


#endif