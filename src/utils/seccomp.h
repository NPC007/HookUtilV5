//
// Created by runshine on 10/19/20.
//

#ifndef HOOKUTILV3_SECCOMP_H
#define HOOKUTILV3_SECCOMP_H



#include "arch/common/arch.h"
#include <sys/prctl.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef SECCOMP_MODE_FILTER
# define SECCOMP_MODE_FILTER	2 /* uses user-supplied filter. */
# define SECCOMP_RET_KILL	0x00000000U /* kill the task immediately */
# define SECCOMP_RET_TRAP	0x00030000U /* disallow and force a SIGSYS */
# define SECCOMP_RET_ALLOW	0x7fff0000U /* allow */
struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};
#endif
#ifndef SYS_SECCOMP
# define SYS_SECCOMP 1
#endif

#define syscall_nr (offsetof(struct seccomp_data, nr))

#if defined(__i386__)
# define REG_SYSCALL	REG_EAX
# define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define REG_SYSCALL	REG_RAX
# define ARCH_NR	AUDIT_ARCH_X86_64
#else
# error "Platform does not support seccomp filter yet"
#endif

#define ALLOW_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define DISALLOW_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)



IN_LINE int init_seccomp_defense(){
    //http://ptrace.fefe.de/seccompfail.c
    struct sock_filter filter[] = {
            BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
            DISALLOW_SYSCALL(execve),
            BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
            .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
            .filter = filter
    };
    my_prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
    return my_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (unsigned long)&prog,0,0);
}

/*
int main(int argc,char* argv[]) {
    install_syscall_filter();
    seccomp_denyfile();
    seccomp_denysocket();
    seccomp_denysocket();
    return 0;
}
*/


#endif //HOOKUTILV3_SECCOMP_H
