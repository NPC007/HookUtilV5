#ifndef __X64_SYSCALL_H__
#define __X64_SYSCALL_H__
#include <sys/syscall.h>
#include "unistd_syscall.h"

#define asm_open(FILE,FLAG,MODE,RES) __asm__ __volatile__ ("syscall"\
                                                    :"=a" (RES)\
                                                    :"0"(__NR_open),"D"((long)FILE),"S"((long)FLAG),"d"((long)MODE)\
                                                    :"%rcx","%r11");

#define asm_close(FD,RES)  __asm__ __volatile__ ("syscall"\
                                            :"=a" (RES)\
                                            :"0"(__NR_close),"D"((long)FD)\
                                            :"%rcx","%r11");

#define asm_write(FD,BUF,N,RES) __asm__ __volatile__ ("syscall"\
                                                :"=a" (RES)\
                                                :"0"(__NR_write),"D"((long)FD),"S"((long)BUF),"d"((long)N)\
                                                :"%rcx","%r11");

#define asm_read(FD,BUF,N,RES)  __asm__ __volatile__ ("syscall"\
                                                    :"=a" (RES)\
                                                    :"0"(__NR_read),"D"((long)FD),"S"((long)BUF),"d"((long)N));

#define asm_nanosleep(TIMESPEC,ARGV,RES) __asm__ __volatile__("syscall"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_nanosleep),"D"((long)TIMESPEC),"S"((long)ARGV));

#define asm_pipe(FDS,RES) __asm__ __volatile__("syscall"\
                                        : "=a" (RES)\
                                        :"0"(__NR_pipe),"D"((long)FDS));

#define asm_execve(BASH,ARG,ENV,RES)  __asm__ __volatile__("syscall"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_execve),"D"((long)BASH),"S"((long)ARG),"d"((long)ENV));

#define asm_fork(RES) __asm__ __volatile__("syscall"\
                                    : "=a" (RES)\
                                    : "0" (__NR_fork));

#define asm_waitpid(PID,STAT,ARG,RES)  __asm__ __volatile__("syscall"\
                                                    : "=a" (RES)\
                                                    :"0"(__NR_wait4),"D"((long)PID),"S"((long)STAT),"d"((long)ARG));

#define asm_fcntl(FD,CMD,ARG,RES) __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_fcntl),"D"((long)FD),"S"((long)CMD),"d"((long)ARG));

#define asm_dup2(OLDFD,NEWFD,RES) __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_dup2),"D"((long)OLDFD),"S"((long)NEWFD));

#define asm_socket(AF,SOCKET,ARG,RES) __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_socket),"D"((long)AF),"S"((long)SOCKET),"d"((long)ARG));

#define asm_connect(FD,ADDR,ADDR_SIZE,RES) __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_connect),"D"((long)FD),"S"((long)ADDR),"d"((long)ADDR_SIZE));

#define asm_send(FD,BUF,LEN,FLAG,RES) ({\
                                                register long _flag_  asm("r10")= (long)FLAG;\
                                                register long _addr_  asm("r8")= (long)0;\
                                                register long _addr_size_ asm("r9")= (long)0;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_sendto),"D"((long)FD),"S"((long)BUF),"d"((long)LEN),"r"((long)_flag_),"r"((long)_addr_),"r"((long)_addr_size_));})


#define asm_sendto(FD,BUF,LEN,FLAG,ADDR,ADDR_SIZE,RES) ({\
                                                register long _flag_  asm("r10")= (long)FLAG;\
                                                register long _addr_  asm("r8")= (long)ADDR;\
                                                register long _addr_size_ asm("r9")= (long)ADDR_SIZE;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_sendto),"D"((long)FD),"S"((long)BUF),"d"((long)LEN),"r"((long)_flag_),"r"((long)_addr_),"r"((long)_addr_size_));})

#define asm_exit(CODE,RES)  __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_exit),"D"((long)CODE));

#define asm_kill(PID,SIG,RES)  __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_kill),"D"((long)PID),"S"((long)SIG));

#define asm_select(NFDS,READFDS,WRITEFDS,EXCEPTFDS,TIMEOUT,RES) ({\
                                                register long _exceptfds_  asm("r10")= (long)EXCEPTFDS;\
                                                register long _timeout_  asm("r8")= (long)TIMEOUT;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_select),"D"((long)NFDS),"S"((long)READFDS),"d"((long)WRITEFDS),"r"((long)_exceptfds_),"r"((long)_timeout_));})

#define asm_setsockopt(FD,LEVEL,OPTNAME,OPTVAL,OPTLEN,RES) ({\
                                                register long _optval_  asm("r10")= (long)OPTVAL;\
                                                register long _optlen_  asm("r8")= (long)OPTLEN;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_setsockopt),"D"((long)FD),"S"((long)LEVEL),"d"((long)OPTNAME),"r"((long)_optval_),"r"((long)_optlen_));})

#define asm_getsockopt(FD,LEVEL,OPTNAME,OPTVAL,OPTLEN,RES) ({\
                                                register long _optval_  asm("r10")= (long)OPTVAL;\
                                                register long _optlen_  asm("r8")= (long)OPTLEN;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_getsockopt),"D"((long)FD),"S"((long)LEVEL),"d"((long)OPTNAME),"r"((long)_optval_),"r"((long)_optlen_));})

#define asm_clone(FLAGS,CHILD_STACK,PTID,CTID,TLS,RES) ({\
                                                register long _ctid_  asm("r10")= (long)CTID;\
                                                register long _tls_  asm("r8")= (long)CTID;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_clone),"D"((long)FLAGS),"S"((long)CHILD_STACK),"d"((long)PTID),"r"((long)_ctid_),"r"((long)_tls_));})

#define asm_mprotect(START,LENGTH,PROTO,RES) __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_mprotect),"D"((long)START),"S"((long)LENGTH),"d"((long)PROTO));

#define asm_alarm(TIME,RES)  __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_alarm),"D"((long)TIME));

#define asm_chroot(PATH,RES)  __asm__ __volatile__("syscall"\
                                            : "=a" (RES)\
                                            :"0"(__NR_chroot),"D"((long)PATH));

#define asm_mmap(ADDR,LENGTH,PROT,FLAGS,FD,OFFSET,RES) ({\
                                                register long _flag_  asm("r10")= (long)FLAGS;\
                                                register long _fd_  asm("r8")= (long)FD;\
                                                register long _offset_ asm("r9")= (long)OFFSET;\
                                                __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_mmap),"D"((long)ADDR),"S"((long)LENGTH),"d"((long)PROT),"r"((long)_flag_),"r"((long)_fd_),"r"((long)_offset_));})

#define asm_munmap(ADDR,LENGTH,RES) __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(__NR_munmap),"D"((long)ADDR),"S"((long)LENGTH));

#define asm_syscall_test(SYSCALL_ID,RES) __asm__ __volatile__("syscall"\
                                                : "=a" (RES)\
                                                :"0"(SYSCALL_ID));

#endif