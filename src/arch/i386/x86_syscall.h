#ifndef __X86_SYSCALL_H__
#define __X86_SYSCALL_H__

#include <sys/syscall.h>
#include "unistd_syscall.h"

#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
#define SYS_LISTEN	4		/* sys_listen(2)		*/
#define SYS_ACCEPT	5		/* sys_accept(2)		*/
#define SYS_GETSOCKNAME	6		/* sys_getsockname(2)		*/
#define SYS_GETPEERNAME	7		/* sys_getpeername(2)		*/
#define SYS_SOCKETPAIR	8		/* sys_socketpair(2)		*/
#define SYS_SEND	9		/* sys_send(2)			*/
#define SYS_RECV	10		/* sys_recv(2)			*/
#define SYS_SENDTO	11		/* sys_sendto(2)		*/
#define SYS_RECVFROM	12		/* sys_recvfrom(2)		*/
#define SYS_SHUTDOWN	13		/* sys_shutdown(2)		*/
#define SYS_SETSOCKOPT	14		/* sys_setsockopt(2)		*/
#define SYS_GETSOCKOPT	15		/* sys_getsockopt(2)		*/
#define SYS_SENDMSG	16		/* sys_sendmsg(2)		*/
#define SYS_RECVMSG	17		/* sys_recvmsg(2)		*/
#define SYS_ACCEPT4	18		/* sys_accept4(2)		*/
#define SYS_RECVMMSG	19		/* sys_recvmmsg(2)		*/
#define SYS_SENDMMSG	20		/* sys_sendmmsg(2)		*/


#define asm_open(FILE,FLAG,MODE,RES) __asm__ __volatile__ ("int $0x80"\
                                                        :"=a" (RES)\
                                                        :"0"(__NR_open),"b"((long)FILE),"c"((long)FLAG),"d"((long)MODE)\
                                                        :"cc","memory");

#define asm_open_one(FILE,FLAG,MODE,RES) __asm__ __volatile__ ("push %1;\n\tpop %%eax;\n\tint $0x80"\
                                                        :"=a" (RES)\
                                                        :""(__NR_open),"c"((long)FLAG),"d"((long)MODE)\
                                                        :"cc","memory");

#define asm_close(FD,RES) __asm__ __volatile__ ("int $0x80"\
                                            :"=a" (RES)\
                                            :"0"(__NR_close),"b"((long)FD));

#define asm_write(FD,BUF,N,RES) __asm__ __volatile__ ("int $0x80"\
                                                :"=a" (RES)\
                                                :"0"(__NR_write),"b"((long)FD),"c"((long)BUF),"d"((long)N)\
                                                :"cc","memory");

#define asm_read(FD,BUF,N,RES) __asm__ __volatile__ ("int $0x80"\
                                                :"=a" (RES)\
                                                :"0"(__NR_read),"b"((long)FD),"c"((long)BUF),"d"((long)N)\
                                                :"cc","memory");

#define asm_nanosleep(TIMESPEC,ARGV,RES) __asm__ __volatile__("int $0x80"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_nanosleep),"b"((long) TIMESPEC),"c"((long )ARGV)\
                                                    :"cc","memory");

#define asm_pipe(FDS,RES) __asm__ __volatile__("int $0x80"\
                                    : "=a" (RES)\
                                    :"0"(__NR_pipe),"b"((long)FDS)\
                                    :"cc","memory");

#define asm_execve(BASH,ARG,ENV,RES) __asm__ __volatile__("int $0x80"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_execve),"b"((long)BASH),"c"((long)ARG),"d"((long)ENV)\
                                                    :"cc","memory");

#define asm_fork(RES) __asm__ __volatile__("int $0x80"\
                                : "=a" (RES)\
                                : "0" (__NR_fork)\
                                :"cc","memory");

#define asm_waitpid(PID,STAT,ARG,RES)  __asm__ __volatile__("int $0x80"\
                                                        : "=a" (RES)\
                                                        :"0"(__NR_wait4),"b"((long)PID),"c"((long)STAT),"d"((long)ARG),"S"((long)0)\
                                                        :"cc","memory");

#define asm_fcntl(FD,CMD,ARG,RES) __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_fcntl),"b"((long)FD),"c"((long)CMD),"d"((long)ARG)\
                                                :"cc","memory");

#define asm_dup2(OLDFD,NEWFD,RES) __asm__ __volatile__("int $0x80"\
                                            : "=a" (RES)\
                                            :"0"(__NR_dup2),"b"((long)OLDFD),"c"((long)NEWFD)\
                                            :"cc","memory");

typedef struct SYS_SOCKET_STRUCT{
    void* af;
    void* socket;
    void* arg;
} __attribute__((aligned (4)))  SYS_SOCKET_STRUCT;
#define asm_socket(AF,SOCKET,ARG,RES) {      SYS_SOCKET_STRUCT arg_struct;      \
                                             arg_struct.af = (void*)AF;         \
                                             arg_struct.socket = (void*)SOCKET; \
                                             arg_struct.arg = (void*)ARG;       \
                                            __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_socketcall),"b"((long)SYS_SOCKET),"c"((long)&arg_struct)\
                                                :"cc","memory");}

typedef struct SYS_CONNECT_STRUCT{
    void* fd;
    void* addr;
    void* addr_size;
}__attribute__((aligned (4))) SYS_CONNECT_STRUCT;
#define asm_connect(FD,ADDR,ADDR_SIZE,RES){    SYS_CONNECT_STRUCT arg_struct; \
                                               arg_struct.fd = (void*)FD;     \
                                               arg_struct.addr = (void*)ADDR; \
                                               arg_struct.addr_size = (void*)ADDR_SIZE;\
                                                __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_socketcall),"b"((long)SYS_CONNECT),"c"((long)&arg_struct)\
                                                :"cc","memory");}

typedef struct SYS_BIND_STRUCT{
    void* fd;
    void* addr;
    void* addr_size;
}__attribute__((aligned (4))) SYS_BIND_STRUCT;
#define asm_bind(FD,ADDR,ADDR_SIZE,RES){       SYS_BIND_STRUCT arg_struct; \
                                               arg_struct.fd = (void*)FD;     \
                                               arg_struct.addr = (void*)ADDR; \
                                               arg_struct.addr_size = (void*)ADDR_SIZE;\
                                                __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_socketcall),"b"((long)SYS_BIND),"c"((long)&arg_struct)\
                                                :"cc","memory");}

typedef struct SYS_LISTEN_STRUCT{
    void* fd;
    void* max_client;
}__attribute__((aligned (4))) SYS_LISTEN_STRUCT;
#define asm_listen(FD,MAX_CLIENT,RES){         SYS_LISTEN_STRUCT arg_struct; \
                                               arg_struct.fd = (void*)FD;     \
                                               arg_struct.max_client = (void*)MAX_CLIENT; \
                                               __asm__ __volatile__("int $0x80"\
                                               : "=a" (RES)\
                                               :"0"(__NR_socketcall),"b"((long)SYS_LISTEN),"c"((long)&arg_struct)\
                                               :"cc","memory");}


typedef struct SYS_SEND_STRUCT{
    void* fd;
    void* buf;
    void* buf_size;
    void* flag;
}__attribute__((aligned (4))) SYS_SEND_STRUCT;
#define asm_send(FD,BUF,BUF_SIZE,FLAG,RES) {   SYS_SEND_STRUCT arg_struct;\
                                               arg_struct.fd = (void*)FD; \
                                               arg_struct.buf = (void*)BUF; \
                                               arg_struct.buf_size = (void*)BUF_SIZE;\
                                               arg_struct.FLAG = (void*)FLAG;\
                                                __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_socketcall),"b"((long)SYS_SEND),"c"((long)&arg_struct)\
                                                :"cc","memory");}

typedef struct SYS_ACCEPT_STRUCT{
    void* fd;
    void* addr;
    void* addr_size;
    void* flag;
}__attribute__((aligned (4))) SYS_ACCEPT_STRUCT;
#define asm_accept(FD,ADDR,ADDR_SIZE,FLAG,RES) {   SYS_ACCEPT_STRUCT arg_struct;\
                                                   arg_struct.fd = (void*)FD; \
                                                   arg_struct.addr = (void*)ADDR; \
                                                   arg_struct.addr_size = (void*)ADDR_SIZE;\
                                                   arg_struct.flag = (void*)FLAG;\
                                                   __asm__ __volatile__("int $0x80"\
                                                   : "=a" (RES)\
                                                   :"0"(__NR_socketcall),"b"((long)SYS_ACCEPT4),"c"((long)&arg_struct)\
                                                   :"cc","memory");}

typedef struct SYS_SENDTO_STRUCT{
    void* fd;
    void* buf;
    void* len;
    void* flag;
    void* addr;
    void* addr_size;
}__attribute__((aligned (4))) SYS_SENDTO_STRUCT;
#define asm_sendto(FD,BUF,LEN,FLAG,ADDR,ADDR_SIZE,RES) {  SYS_SENDTO_STRUCT   arg_struct;\
                                                arg_struct.fd = (void*)FD;\
                                                arg_struct.buf = (void*)BUF;\
                                                arg_struct.len = (void*)LEN;\
                                                arg_struct.flag = (void*)FLAG;\
                                                arg_struct.addr = (void*)ADDR;\
                                                arg_struct.addr_size = (void*)ADDR_SIZE;\
                                                __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                : "0"(__NR_socketcall),"b"((long)SYS_SENDTO),"c"((long)&arg_struct)\
                                                :"cc","memory");}

#define asm_exit(CODE,RES)  __asm__ __volatile__("int $0x80"\
                                            : "=a" (RES)\
                                            :"0"(__NR_exit_group),"b"((long)CODE)\
                                            :"cc","memory");

#define asm_exit_group(CODE,RES)  __asm__ __volatile__("int $0x80"\
                                            : "=a" (RES)\
                                            :"0"(__NR_exit_group),"b"((long)CODE)\
                                            :"cc","memory");

#define asm_kill(PID,SIG,RES)  __asm__ __volatile__("int $0x80"\
                                            : "=a" (RES)\
                                            :"0"(__NR_kill),"b"((long)PID),"c"((long)SIG)\
                                            :"cc","memory");

#define asm_select(NFDS,READFDS,WRITEFDS,EXCEPTFDS,TIMEOUT,RES) __asm__ __volatile__("int $0x80"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR__newselect),"b"((long)NFDS),"c"((long)READFDS),"d"((long)WRITEFDS),"S"((long)EXCEPTFDS),"D"((long)TIMEOUT)\
                                                    :"cc","memory");

typedef struct SYS_SETSOCKOPT_STRUCT{
    void* fd;
    void* level;
    void* optname;
    void* optval;
    void* optlen;
}__attribute__((aligned (4))) SYS_SETSOCKOPT_STRUCT;

#define asm_setsockopt(FD,LEVEL,OPTNAME,OPTVAL,OPTLEN,RES) {SYS_SETSOCKOPT_STRUCT arg_struct;\
                                                    arg_struct.fd = (void*)FD;\
                                                    arg_struct.level = (void*)LEVEL;\
                                                    arg_struct.optname = (void*)OPTNAME;\
                                                    arg_struct.optval = (void*)OPTVAL;\
                                                    arg_struct.optlen = (void*)OPTLEN;\
                                                    __asm__ __volatile__("int $0x80"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_socketcall),"b"((long)SYS_SETSOCKOPT),"c"((long)&arg_struct)\
                                                    :"cc","memory");}

typedef struct SYS_GETSOCKOPT_STRUCT{
    void* fd;
    void* level;
    void* optname;
    void* optval;
    void* optlen;
}__attribute__((aligned (4))) SYS_GETSOCKOPT_STRUCT;

#define asm_getsockopt(FD,LEVEL,OPTNAME,OPTVAL,OPTLEN,RES) { SYS_SETSOCKOPT_STRUCT arg_struct;\
                                                    arg_struct.fd = (void*)FD;\
                                                    arg_struct.level = (void*)LEVEL;\
                                                    arg_struct.optname = (void*)OPTNAME;\
                                                    arg_struct.optval = (void*)OPTVAL;\
                                                    arg_struct.optlen = (void*)OPTLEN;\
                                                    __asm__ __volatile__("int $0x80"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_socketcall),"b"((long)SYS_GETSOCKOPT),"c"((long)&arg_struct)\
                                                    :"cc","memory");}




#define asm_clone(FLAGS,CHILD_STACK,PTID,CTID,TLS,RES) __asm__ __volatile__("int $0x80"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_clone),"b"((long)FLAGS),"c"((long)CHILD_STACK),"d"((long)PTID),"S"((long)TLS),"D"((long)CTID)\
                                                    :"cc","memory");

#define asm_mprotect(START,LENGTH,PROTO,RES) __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_mprotect),"b"((long)START),"c"((long)LENGTH),"d"((long)PROTO)\
                                                :"cc","memory");

#define asm_alarm(TIME,RES)  __asm__ __volatile__("int $0x80"\
                                            : "=a" (RES)\
                                            :"0"(__NR_alarm),"b"((long)TIME)\
                                            :"cc","memory");

#define asm_chroot(PATH,RES)  __asm__ __volatile__("int $0x80"\
                                            : "=a" (RES)\
                                            :"0"(__NR_chroot),"b"((long)PATH)\
                                            :"cc","memory");

#define asm_mmap(ADDR,LENGTH,PROT,FLAGS,FD,OFFSET,RES) ({\
                                                __asm__ __volatile__("pushl %%ebp;xor %%ebp,%%ebp;int $0x80;popl %%ebp"\
                                                : "=a" (RES)\
                                                :"0"(__NR_mmap2),"b"((long)ADDR),"c"((long)LENGTH),"d"((long)PROT),"S"((long)FLAGS),"D"((long)FD)\
                                                :"cc","memory");})


#define asm_mmap_one(ADDR,LENGTH,PROT,FLAGS,FD,OFFSET,RES) ({\
                                                __asm__ __volatile__("xor %%ebp,%%ebp;push %3;pop %%edx;push %4;pop %%esi;int $0x80;"\
                                                : "=a" (RES)\
                                                :"0"(__NR_mmap2),"c"((long)LENGTH),""((long)PROT),""((long)FLAGS)\
                                                :"cc","memory");})

#define asm_munmap(ADDR,LENGTH,RES) __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_munmap),"b"((long)ADDR),"c"((long)LENGTH)\
                                                :"cc","memory");

#define asm_syscall_test(SYSCALL_ID,RES) __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(SYSCALL_ID)\
                                                :"cc","memory");


#define asm_brk(ADDR,RES) __asm__ __volatile__("int $0x80"\
                                    : "=a" (RES)\
                                    :"0"(__NR_brk),"b"((long)ADDR)\
                                    :"cc","memory");

#define asm_rt_sigaction(SIG,NEW_ACTION,OLD_ACTION,RES) __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_rt_sigaction),"b"((long)SIG),"c"((long)NEW_ACTION),"d"((long)OLD_ACTION)\
                                                :"cc","memory");

#define asm_shmget(KEY,SIZE,FLAG,RES) __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_shmget),"b"((long)KEY),"c"((long)SIZE),"d"((long)FLAG)\
                                                :"cc","memory");

#define asm_shmget_one(KEY,SIZE,FLAG,RES) __asm__ __volatile__("push %2;\n\tpop %%ebx;\n\tint $0x80"\
                                                :"=a"(RES):"0"(__NR_shmget),""((long)KEY),"c"((long)SIZE),"d"((long)FLAG)\
                                                :"cc","memory");

#define asm_shmat(ID,ADDR,FLAG,RES) __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_shmat),"b"((long)ID),"c"((long)ADDR),"d"((long)FLAG)\
                                                :"cc","memory");

#define asm_shmat_one(ID,ADDR,FLAG,RES) __asm__ __volatile__("int $0x80"\
                                                :"=a"(RES):"0"(__NR_shmat),"c"((long)ADDR),"d"((long)FLAG)\
                                                :"cc","memory");

#define asm_prctl(OPTIONS,ARG2,ARG3,ARG4,ARG5,RES) __asm__ __volatile__("int $0x80"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_prctl),"b"((long)OPTIONS),"c"((long)ARG2),"d"((long)ARG3),"S"((long)ARG4),"D"((long)ARG5)\
                                                    :"cc","memory");

#define asm_unlink(FILE,RES) __asm__ __volatile__("int $0x80"\
                                    : "=a" (RES)\
                                    :"0"(__NR_unlink),"b"((long)FILE)\
                                    :"cc","memory");

#define asm_umask(MASK,RES) __asm__ __volatile__("int $0x80"\
                                    : "=a" (RES)\
                                    :"0"(__NR_umask),"b"((long)MASK)\
                                    :"cc","memory");

#define asm_setsid(RES) __asm__ __volatile__("int $0x80"\
                                    : "=a" (RES)\
                                    :"0"(__NR_setsid)\
                                    :"cc","memory");
// #define asm_stat(PATH,MODE,RES) __asm__ __volatile__("int $0x80"\
//                                     : "=a" (RES), "b"((long)PATH),"c"((long)MODE)\
//                                     :"0"(__NR__stat)\
//                                     :"cc",)

#endif