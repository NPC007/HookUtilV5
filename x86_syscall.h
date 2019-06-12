#include <sys/syscall.h>

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
                                                        :"0"(__NR_open),"b"((long)FILE),"c"((long)FLAG),"d"((long)MODE));

#define asm_close(FD,RES) __asm__ __volatile__ ("int $0x80"\
                                            :"=a" (RES)\
                                            :"0"(__NR_close),"b"((long)FD));

#define asm_write(FD,BUF,N,RES) __asm__ __volatile__ ("int $0x80"\
                                                :"=a" (RES)\
                                                :"0"(__NR_write),"b"((long)FD),"c"((long)BUF),"d"((long)N));

#define asm_read(FD,BUF,N,RES) __asm__ __volatile__ ("int $0x80"\
                                                :"=a" (RES)\
                                                :"0"(__NR_read),"b"((long)FD),"c"((long)BUF),"d"((long)N));

#define asm_nanosleep(TIMESPEC,ARGV,RES) __asm__ __volatile__("int $0x80"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_nanosleep),"b"((long) TIMESPEC),"c"((long )ARGV));

#define asm_pipe(FDS,RES) __asm__ __volatile__("int $0x80"\
                                    : "=a" (RES)\
                                    :"0"(__NR_pipe),"b"((long)FDS));

#define asm_execve(BASH,ARG,ENV,RES) __asm__ __volatile__("int $0x80"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_execve),"b"((long)BASH),"c"((long)ARG),"d"((long)ENV));

#define asm_fork(RES) __asm__ __volatile__("int $0x80"\
                                : "=a" (RES)\
                                : "0" (__NR_fork));

#define asm_waitpid(PID,STAT,ARG,RES)  __asm__ __volatile__("int $0x80"\
                                                        : "=a" (RES)\
                                                        :"0"(__NR_wait4),"b"((long)PID),"c"((long)STAT),"d"((long)ARG));

#define asm_fcntl(FD,CMD,ARG,RES) __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_fcntl),"b"((long)FD),"c"((long)CMD),"d"((long)ARG));

#define asm_dup2(OLDFD,NEWFD,RES) __asm__ __volatile__("int $0x80"\
                                            : "=a" (RES)\
                                            :"0"(__NR_dup2),"b"((long)OLDFD),"c"((long)NEWFD));

#define asm_socket(AF,SOCKET,ARG,RES) __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_socketcall),"b"((long)SYS_SOCKET),"c"((long)&AF));

#define asm_connect(FD,ADDR,ADDR_SIZE,RES) __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_socketcall),"b"((long)SYS_CONNECT),"c"((long)&FD));

#define asm_send(FD,BUF,BUF_SIZE,FLAG,RES) __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_socketcall),"b"((long)SYS_SEND),"c"((long)&FD));

#define asm_sendto(FD,BUF,LEN,FLAG,ADDR,ADDR_SIZE,RES) __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                : "0"(__NR_socketcall),"b"((long)SYS_SENDTO),"c"((long)&FD));

#define asm_exit(CODE,RES)  __asm__ __volatile__("int $0x80"\
                                            : "=a" (RES)\
                                            :"0"(__NR_exit),"b"((long)CODE));

#define asm_kill(PID,SIG,RES)  __asm__ __volatile__("int $0x80"\
                                            : "=a" (RES)\
                                            :"0"(__NR_kill),"b"((long)PID),"c"((long)SIG));

#define asm_select(NFDS,READFDS,WRITEFDS,EXCEPTFDS,TIMEOUT,RES) __asm__ __volatile__("int $0x80"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR__newselect),"b"((long)NFDS),"c"((long)READFDS),"d"((long)WRITEFDS),"S"((long)EXCEPTFDS),"D"((long)TIMEOUT));

#define asm_setsockopt(FD,LEVEL,OPTNAME,OPTVAL,OPTLEN,RES) __asm__ __volatile__("int $0x80"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_socketcall),"b"((long)SYS_SETSOCKOPT),"c"((long)&FD));
#define asm_getsockopt(FD,LEVEL,OPTNAME,OPTVAL,OPTLEN,RES) __asm__ __volatile__("int $0x80"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_socketcall),"b"((long)SYS_GETSOCKOPT),"c"((long)&FD));

#define asm_clone(FN,CHILD_STACK,FLAGS,ARG,RES) __asm__ __volatile__("int $0x80"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_clone),"b"((long)FN),"c"((long)CHILD_STACK),"d"((long)FLAGS),"S"((long)ARG));

#define asm_mprotect(START,LENGTH,PROTO,RES) __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_mprotect),"b"((long)START),"c"((long)LENGTH),"d"((long)PROTO));

#define asm_alarm(TIME,RES)  __asm__ __volatile__("int $0x80"\
                                            : "=a" (RES)\
                                            :"0"(__NR_alarm),"b"((long)TIME));

#define asm_chroot(PATH,RES)  __asm__ __volatile__("int $0x80"\
                                            : "=a" (RES)\
                                            :"0"(__NR_chroot),"b"((long)PATH));

#define asm_mmap(ADDR,LENGTH,PROT,FLAGS,FD,OFFSET,RES) ({\
                                                __asm__ __volatile__("pushl %%ebp;xor %%ebp,%%ebp;int $0x80;popl %%ebp"\
                                                : "=a" (RES)\
                                                :"0"(__NR_mmap2),"b"((long)ADDR),"c"((long)LENGTH),"d"((long)PROT),"S"((long)FLAGS),"D"((long)FD));\
                                                })


#define asm_munmap(ADDR,LENGTH,RES) __asm__ __volatile__("int $0x80"\
                                                : "=a" (RES)\
                                                :"0"(__NR_munmap),"b"((long)ADDR),"c"((long)LENGTH));

