#ifndef __arm__
#define __arm__

#include <sys/syscall.h>
#include "unistd_syscall.h"

#define asm_exit(code, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; svc #0;str r0, %2"\
                                                : \
                                                : ""(1),""(code),""(res));
#define asm_exit_group(code, res)   __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; svc #0;str r0, %2"\
                                                : \
                                                : ""(248),""(code),""(res));
                                
#define asm_fork(res) __asm__ __volatile__("ldr r7, =%0; svc #0; str r0, %1"\
                                                : \
                                                : ""(2), ""(res));

#define asm_read(fd, buf, count, res) __asm__ __volatile("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; svc #0; str r0, %4"\
                                                : \
                                                : ""(3), ""(fd), ""(buf), ""(count), ""(res));

#define asm_write(fd, buf, count, res) __asm__ __volatile("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; svc #0; str r0, %4"\
                                                : \
                                                : ""(4), ""(fd), ""(buf), ""(count), ""(res));

#define asm_open(filename, flags, mode, res) __asm__ __volatile("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; svc #0; str r0, %4"\
                                                : \
                                                : ""(5), ""(filename), ""(flags), ""(mode), ""(res));

#define asm_close(fd, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; svc #0;str r0, %2"\
                                                : \
                                                : ""(6),""(fd),""(res));

#define asm_execve(filename, argv, envp, res) __asm__ __volatile("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; svc #0; str r0, %4"\
                                                : \
                                                : ""(11), ""(filename), ""(argv), ""(envp), ""(res));

#define asm_pipe(fildes, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; svc #0;str r0, %2"\
                                                : \
                                                : ""(42),""(fildes),""(res));

#define asm_fcntl(fd, cmd, arg, res)  __asm__ __volatile("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; svc #0; str r0, %4"\
                                                : \
                                                : ""(55), ""(fd), ""(cmd), ""(arg), ""(res));

#define asm_dup2(oldfd, newfd, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; svc #0; str r0, %3"\
                                                : \
                                                : ""(63), ""(oldfd), ""(newfd), ""(res));

#define asm_waitpid(pid, stat, options, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; mov r3, %4;svc #0; str r0, %5"\
                                                : \
                                                : ""(114), ""(pid), ""(stat),""(options),""(0), ""(res));

#define asm_nanosleep(rqtp, rmtp, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; svc #0; str r0, %3"\
                                                : \
                                                : ""(162), ""(rqtp), ""(rmtp), ""(res));


#define asm_socket(af, type, protocol, res)  __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; svc #0; str r0, %4"\
                                                : \
                                                : ""(281), ""(af), ""(type),""(protocol),""(res));

#define asm_bind(fd, sockaddr, addrlen, res)     __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; svc #0; str r0, %4"\
                                                : \
                                                : ""(282), ""(fd), ""(sockaddr),""(addrlen),""(res));

#define asm_connect(fd, sockaddr, addrlen, res)  __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; svc #0; str r0, %4"\
                                                : \
                                                : ""(283), ""(fd), ""(sockaddr),""(addrlen),""(res));

#define asm_listen(fd, max, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; svc #0; str r0, %3"\
                                                : \
                                                : ""(284), ""(fd), ""(max), ""(res));

#define asm_send(fd, buf, len, flags, res)   __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; ldr r3, %4; svc #0; str r0, %5"\
                                                : \
                                                : ""(289), ""(fd), ""(buf),""(len),""(flags), ""(res));
//accept4
#define asm_accept(fd, sockaddr, addrlen , flags, res)  __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; ldr r3, %4; svc #0; str r0, %5"\
                                                : \
                                                : ""(366), ""(fd), ""(sockaddr),""(addrlen),""(flags), ""(res));

#define asm_sendto(fd, buf, len, flags, addr, addr_len, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; ldr r3, %4; ldr r4, %5;ldr r5, %6;svc #0; str r0, %7"\
                                                : \
                                                : ""(366), ""(fd), ""(buf),""(len),""(flags), ""(addr), ""(addr_len), ""(res));

#define asm_kill(pid, sig, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; svc #0; str r0, %3"\
                                                : \
                                                : ""(37), ""(pid), ""(sig), ""(res));
//_newselect
#define asm_select(n, inp, outp, exp, tvp, res)  __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; ldr r3, %4;ldr r4, %5; svc #0; str r0, %6"\
                                                : \
                                                : ""(142), ""(n), ""(inp),""(outp),""(exp), ""(tvp), ""(res));

#define asm_setsockopt(fd, level, optname, optval, optlen, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; ldr r3, %4;ldr r4, %5; svc #0; str r0, %6"\
                                                : \
                                                : ""(294), ""(fd), ""(level),""(optname),""(optval), ""(optlen), ""(res));
                                
#define asm_getsockopt(fd, level, optname, optval, optlen, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; ldr r3, %4;ldr r4, %5; svc #0; str r0, %6"\
                                                : \
                                                : ""(295), ""(fd), ""(level),""(optname),""(optval), ""(optlen), ""(res));

#define asm_clone(clone_flags, newsp, parent_tid, child_tid, tid, res)   __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; ldr r3, %4;ldr r4, %5; svc #0; str r0, %6"\
                                                : \
                                                : ""(120), ""(clone_flags), ""(newsp),""(parent_tid),""(child_tid), ""(tid), ""(res));

#define asm_mprotect(start, len, prot, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; svc #0; str r0, %4"\
                                                : \
                                                : ""(125), ""(start), ""(len),""(prot),""(res));

//implement by setitimer syscall
typedef struct timerval{
    long tv_sec;
    long tv_usec;
}timerval;
typedef struct itimerval{
    timerval it_interval;
    timerval it_value;
}itimerval;
#define asm_alarm(sec, res){ itimerval timer,otimer,*timer_ptr = &timer, *otimer_ptr = &otimer;\
                            timer.it_interval.tv_sec = (sec);\
                            timer.it_interval.tv_usec = 0;\
                            timer.it_value.tv_sec = 0;\
                            timer.it_value.tv_usec = 0;\
                            __asm__ __volatile__("ldr r7, =%0; ldr r0, =%1; ldr r1, %2; svc #0; str r0, %3"\
                                                : \
                                                : ""(104), ""(0), ""(timer_ptr), ""(otimer_ptr));}

#define asm_chroot(path, res)  __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; svc #0;str r0, %2"\
                                                : \
                                                : ""(61),""(path),""(res));

//mmap2
#define asm_mmap(addr, len, prot, flags, fd, pgoff, res)  __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; ldr r3, %4; ldr r4, %5;ldr r5, %6;svc #0; str r0, %7"\
                                                : \
                                                : ""(192), ""(addr), ""(len),""(prot),""(flags), ""(fd), ""(pgoff), ""(res));

#define asm_mmap_one(addr, len, prot, flags, fd, pgoff, res)  __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; ldr r3, %4; ldr r4, %5;ldr r5, %6;svc #0; str r0, %7"\
                                                : \
                                                : ""(192), ""(addr), ""(len),""(prot),""(flags), ""(fd), ""(pgoff), ""(res));

#define asm_munmap(addr, len, res)  __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; svc #0; str r0, %3"\
                                                : \
                                                : ""(91), ""(addr), ""(len), ""(res));

#define asm_syscall_test(syscall_id, res) __asm__ __volatile__("ldr r7, %0; svc #0;str r0, %1"\
                                                : \
                                                : ""(syscall_id),""(res));

#define asm_brk(addr, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1;svc #0;str r0, %2"\
                                                : \
                                                : ""(45),""(addr),""(res));

#define asm_rt_sigaction(sig, new_sigaction, old_sigaction, res)    __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; svc #0; str r0, %4"\
                                                : \
                                                : ""(174), ""(sig), ""(new_sigaction),""(old_sigaction),""(res));

#define asm_shmget(key, size, flag, res)    __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; svc #0; str r0, %4"\
                                                : \
                                                : ""(307), ""(key), ""(size),""(flag),""(res));

#define asm_shmget_one(key, size, flag, res)    __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; svc #0; str r0, %4"\
                                                : \
                                                : ""(307), ""(key), ""(size),""(flag),""(res));

#define asm_shmat(shmid, shmaddr, shmflag, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; svc #0; str r0, %4"\
                                                : \
                                                : ""(305), ""(shmid), ""(shmaddr),""(shmflag),""(res));        

#define asm_shmat_one(shmid, shmaddr, shmflag, res) __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; svc #0; str r0, %4"\
                                                : \
                                                : ""(305), ""(shmid), ""(shmaddr),""(shmflag),""(res));      

#define asm_prctl(option, arg2, arg3, arg4, arg5, res)  __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; ldr r1, %2; ldr r2, %3; ldr r3, %4;ldr r4, %5; svc #0; str r0, %6"\
                                                : \
                                                : ""(172), ""(option), ""(arg2),""(arg3),""(arg4), ""(arg5), ""(res));                                                                                                                         

#define asm_unlink(path, res)   __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; svc #0;str r0, %2"\
                                                : \
                                                : ""(10),""(path),""(res));

#define asm_umask(mask ,res)    __asm__ __volatile__("ldr r7, =%0; ldr r0, %1; svc #0;str r0, %2"\
                                                : \
                                                : ""(60),""(mask),""(res));

#define asm_setsid(res) __asm__ __volatile__("ldr r7, =%0; svc #0;str r0, %1"\
                                                : \
                                                : ""(66),""(res));

#endif