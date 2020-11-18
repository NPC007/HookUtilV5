#ifndef __X64_SYSCALL_H__
#define __X64_SYSCALL_H__
#include <sys/syscall.h>
#include "unistd_syscall.h"

#define asm_open(FILE,FLAG,MODE,RES) __asm__ __volatile__ ("syscall"\
                                                    :"=a" (RES)\
                                                    :"0"(__NR_open),"D"((long)FILE),"S"((long)FLAG),"d"((long)MODE)\
                                                    :"memory","cc","rcx","r11");

#define asm_close(FD,RES)  __asm__ __volatile__ ("syscall"\
                                            :"=a" (RES)\
                                            :"0"(__NR_close),"D"((long)FD)\
                                            :"memory","cc","rcx","r11");

#define asm_write(FD,BUF,N,RES) __asm__ __volatile__ ("syscall"\
                                                :"=a" (RES)\
                                                :"0"(__NR_write),"D"((long)FD),"S"((long)BUF),"d"((long)N)\
                                                :"memory","cc","rcx","r11");

#define asm_read(FD,BUF,N,RES)  __asm__ __volatile__ ("syscall"\
                                                    :"=a" (RES)\
                                                    :"0"(__NR_read),"D"((long)FD),"S"((long)BUF),"d"((long)N)\
                                                    :"memory","cc","rcx","r11");

#define asm_nanosleep(TIMESPEC,ARGV,RES) __asm__ __volatile__("syscall"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_nanosleep),"D"((long)TIMESPEC),"S"((long)ARGV)\
                                                    :"memory","cc","rcx","r11");

#define asm_pipe(FDS,RES) __asm__ __volatile__("syscall"\
                                        : "=a" (RES)\
                                        :"0"(__NR_pipe),"D"((long)FDS)\
                                        :"memory","cc","rcx","r11");

#define asm_execve(BASH,ARG,ENV,RES)  __asm__ __volatile__("syscall"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_execve),"D"((long)BASH),"S"((long)ARG),"d"((long)ENV)\
                                                    :"memory","cc","rcx","r11");

#define asm_fork(RES) __asm__ __volatile__("syscall"\
                                    : "=a" (RES)\
                                    : "0" (__NR_fork)\
                                    :"memory","cc","rcx","r11");

#define asm_waitpid(PID,STAT,ARG,RES)  {    register long _rusage_  asm("r10")= (long)0;\
                                            __asm__ __volatile__("syscall"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_wait4),"D"((long)PID),"S"((long)STAT),"d"((long)ARG),"r"(_rusage_)\
                                                    :"memory","cc","rcx","r11");\
                                            }

#define asm_fcntl(FD,CMD,ARG,RES) __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_fcntl),"D"((long)FD),"S"((long)CMD),"d"((long)ARG)\
                                                :"memory","cc","rcx","r11");

#define asm_dup2(OLDFD,NEWFD,RES) __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_dup2),"D"((long)OLDFD),"S"((long)NEWFD)\
                                            :"memory","cc","rcx","r11");

#define asm_socket(AF,SOCKET,ARG,RES) __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_socket),"D"((long)AF),"S"((long)SOCKET),"d"((long)ARG)\
                                                :"memory","cc","rcx","r11");

#define asm_connect(FD,ADDR,ADDR_SIZE,RES) __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_connect),"D"((long)FD),"S"((long)ADDR),"d"((long)ADDR_SIZE)\
                                                :"memory","cc","rcx","r11");

#define asm_bind(FD,ADDR,ADDR_SIZE,RES) __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_bind),"D"((long)FD),"S"((long)ADDR),"d"((long)ADDR_SIZE)\
                                                :"memory","cc","rcx","r11");

#define asm_listen(FD,MAX_CLIENT,RES) __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_listen),"D"((long)FD),"S"((long)MAX_CLIENT)\
                                                :"memory","cc","rcx","r11");

#define asm_accept(FD,ADDR,ADDR_SIZE,FLAG,RES) ({\
                                                register long _flag_  asm("r10")= (long)FLAG;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_accept4),"D"((long)FD),"S"((long)ADDR),"d"((long)ADDR_SIZE),"r"((long)_flag_)\
                                                :"memory","cc","rcx","r11");})


#define asm_send(FD,BUF,LEN,FLAG,RES) ({\
                                                register long _flag_  asm("r10")= (long)FLAG;\
                                                register long _addr_  asm("r8")= (long)0;\
                                                register long _addr_size_ asm("r9")= (long)0;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_sendto),"D"((long)FD),"S"((long)BUF),"d"((long)LEN),"r"((long)_flag_),"r"((long)_addr_),"r"((long)_addr_size_)\
                                                :"memory","cc","rcx","r11");})


#define asm_sendto(FD,BUF,LEN,FLAG,ADDR,ADDR_SIZE,RES) ({\
                                                register long _flag_  asm("r10")= (long)FLAG;\
                                                register long _addr_  asm("r8")= (long)ADDR;\
                                                register long _addr_size_ asm("r9")= (long)ADDR_SIZE;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_sendto),"D"((long)FD),"S"((long)BUF),"d"((long)LEN),"r"((long)_flag_),"r"((long)_addr_),"r"((long)_addr_size_)\
                                                :"memory","cc","rcx","r11");})

#define asm_exit(CODE,RES)  __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_exit),"D"((long)CODE)\
                                            :"memory","cc","rcx","r11");

#define asm_exit_group(CODE,RES)  __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_exit_group),"D"((long)CODE)\
                                            :"memory","cc","rcx","r11");

#define asm_kill(PID,SIG,RES)  __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_kill),"D"((long)PID),"S"((long)SIG)\
                                            :"memory","cc","rcx","r11");

#define asm_select(NFDS,READFDS,WRITEFDS,EXCEPTFDS,TIMEOUT,RES) ({\
                                                register long _exceptfds_  asm("r10")= (long)EXCEPTFDS;\
                                                register long _timeout_  asm("r8")= (long)TIMEOUT;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_select),"D"((long)NFDS),"S"((long)READFDS),"d"((long)WRITEFDS),"r"((long)_exceptfds_),"r"((long)_timeout_)\
                                                :"memory","cc","rcx","r11");})

#define asm_setsockopt(FD,LEVEL,OPTNAME,OPTVAL,OPTLEN,RES) ({\
                                                register long _optval_  asm("r10")= (long)OPTVAL;\
                                                register long _optlen_  asm("r8")= (long)OPTLEN;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_setsockopt),"D"((long)FD),"S"((long)LEVEL),"d"((long)OPTNAME),"r"((long)_optval_),"r"((long)_optlen_)\
                                                :"memory","cc","rcx","r11");})

#define asm_getsockopt(FD,LEVEL,OPTNAME,OPTVAL,OPTLEN,RES) ({\
                                                register long _optval_  asm("r10")= (long)OPTVAL;\
                                                register long _optlen_  asm("r8")= (long)OPTLEN;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_getsockopt),"D"((long)FD),"S"((long)LEVEL),"d"((long)OPTNAME),"r"((long)_optval_),"r"((long)_optlen_)\
                                                :"memory","cc","rcx","r11");})

#define asm_clone(FLAGS,CHILD_STACK,PTID,CTID,TLS,RES) ({\
                                                register long _ctid_  asm("r10")= (long)CTID;\
                                                register long _tls_  asm("r8")= (long)CTID;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_clone),"D"((long)FLAGS),"S"((long)CHILD_STACK),"d"((long)PTID),"r"((long)_ctid_),"r"((long)_tls_)\
                                                :"memory","cc","rcx","r11");})

#define asm_mprotect(START,LENGTH,PROTO,RES) __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_mprotect),"D"((long)START),"S"((long)LENGTH),"d"((long)PROTO)\
                                                :"memory","cc","rcx","r11");

#define asm_alarm(TIME,RES)  __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_alarm),"D"((long)TIME)\
                                            :"memory","cc","rcx","r11");

#define asm_chroot(PATH,RES)  __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_chroot),"D"((long)PATH)\
                                            :"memory","cc","rcx","r11");

#define asm_mmap(ADDR,LENGTH,PROT,FLAGS,FD,OFFSET,RES) ({\
                                                __volatile__ register long _flag_  asm("r10")= (long)FLAGS;\
                                                __volatile__ register long _fd_  asm("r8")= (long)FD;\
                                                __volatile__ register long _offset_ asm("r9")= (long)OFFSET;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_mmap),"D"((long)ADDR),"S"((long)LENGTH),"d"((long)PROT),"r"((long)_flag_),"r"((long)_fd_),"r"((long)_offset_)\
                                                :"memory","cc","rcx","r11");})

#define asm_munmap(ADDR,LENGTH,RES) __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_munmap),"D"((long)ADDR),"S"((long)LENGTH)\
                                                :"memory","cc","rcx","r11");

#define asm_syscall_test(SYSCALL_ID,RES) __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(SYSCALL_ID)\
                                                :"memory","cc","rcx","r11");

#define asm_sbrk(ADDR,RES)  __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_sbrk),"D"((long)ADDR)\
                                            :"memory","cc","rcx","r11");

#define asm_brk(ADDR,RES)  __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_brk),"D"((long)ADDR)\
                                            :"memory","cc","rcx","r11");

#define asm_rt_sigaction(SIG,NEW_ACTION,OLD_ACTION,RES) __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_rt_sigaction),"D"((long)SIG),"S"((long)NEW_ACTION),"d"((long)OLD_ACTION)\
                                            :"memory","cc","rcx","r11");


#define asm_shmget(KEY,SIZE,FLAG,RES)__asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_shmget),"D"((long)KEY),"S"((long)SIZE),"d"((long)FLAG)\
                                            :"memory","cc","rcx","r11");

#define asm_shmat(ID,ADDR,FLAG,RES)__asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_shmat),"D"((long)ID),"S"((long)ADDR),"d"((long)FLAG)\
                                            :"memory","cc","rcx","r11");

#define asm_prctl(OPTIONS,ARG2,ARG3,ARG4,ARG5,RES) ({\
                                                register long _arg4_  asm("r10")= (long)ARG4;\
                                                register long _arg5_  asm("r8")= (long)ARG5;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_prctl),"D"((long)OPTIONS),"S"((long)ARG2),"d"((long)ARG3),"r"((long)_arg4_),"r"((long)_arg5_)\
                                                :"memory","cc","rcx","r11");})

#define asm_unlink(FILE,RES) __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_unlink),"D"((long)FILE)\
                                            :"memory","cc","rcx","r11");

#define asm_umask(MASK,RES) __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_umask),"D"((long)MASK)\
                                            :"memory","cc","rcx","r11");

#define asm_setsid(RES) __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_setsid)\
                                            :"memory","cc","rcx","r11");

#endif