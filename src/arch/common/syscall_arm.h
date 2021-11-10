//
// Created by root on 7/23/20.
//

#pragma GCC push_options
#pragma GCC optimize ("O0")


#ifndef HOOKUTILV3_SYSCALL_H
#define HOOKUTILV3_SYSCALL_H

#include "arch.h"
#include <signal.h>

static unsigned int g_errno;

static long my_open(char* name,long mode,long flag){
    long res = 0;
    asm_open(name,mode,flag,res);
    g_errno = (unsigned int) -res;
    return res;
}
static long my_close(long fd){
    long  res = 0;
    asm_close(fd,res);
    return res;
}

// static long my_thread_create(void (*)(void)){
//     long  res = 0;
//     asm_clone(flags, child_stack, ptid, ctid, tls, res);
//     g_errno = (unsigned int) -res;
// }

static long my_mprotect(void *start, long len, long prot){
    long  res = 0;
    asm_mprotect((long)start,(long)len,(long)prot,res);
    g_errno = (unsigned int) -res;
    return res;
}

static long my_mprotect_one(void *start, long len, long prot){
    long  res = 0;
    asm_mprotect((long)start,(long)len,(long)prot,res);
    g_errno = (unsigned int) -res;
    return res;
}
//
static long my_mmap_one(long addr, long length, int prot, int flags,
                     int fd, off_t offset){
    long  res = 0;
    asm_mmap(addr,(long)length,(long)prot,(long)flags,(long)fd,(long)offset,res);
    g_errno = (unsigned int) -res;
    return res;
}

static long my_mmap(long addr, long length, int prot, int flags,
                     int fd, off_t offset){
    long  res = 0;
    asm_mmap(addr,(long)length,(long)prot,(long)flags,(long)fd,(long)offset,res);
    g_errno = (unsigned int) -res;
    return res;
}

static long my_munmap(void* addr,long length){
    long  res = 0;
    asm_munmap((long)addr,(long)length,res);
    g_errno = (unsigned int) -res;
    return res;
}

static long my_read(int fd,const char* buf,long length){
    long  res = 0;
    asm_read(fd,buf,length,res);
    g_errno = (unsigned int) -res;
    if(res<0)
        return -1;
    return res;
}

static long my_write(int fd,const char* buf,long length){
    long  res = 0;
    asm_write(fd,buf,length,res);
    g_errno = (unsigned int) -res;
    if(res<0)
        return -1;
    return res;
}




static long my_socket(long af,long type,long flag){
    long  res = 0;
    asm_socket(af,type,flag,res);
    asm volatile(".pool");
    g_errno = (unsigned int) -res;
    return res;
}

static long my_connect(long fd,void* addr,long size){
    long  res = 0;
    asm_connect(fd,addr,size,res);
    asm volatile(".pool");
    g_errno = (unsigned int) -res;
    return res;
}

static long my_send(int fd,char* buf,long size,long flag){
    long  res = 0;
    asm_send(fd,buf,size,flag,res);
    g_errno = (unsigned int) -res;
    return res;
}

static long my_setsockopt(long sockfd, long level, long optname, void *optval, long optlen){
    long  res = 0;
    asm_setsockopt(sockfd, level, optname, optval, optlen,res);
    asm volatile(".pool");
    g_errno = (unsigned int) -res;
    return res;
}

static int my_getsockopt (int fd, int level, int optname, void * optval, socklen_t * optlen){
    long  res = 0;
    asm_getsockopt(fd,level,optname,optval,optlen,res);
    asm volatile(".pool");
    g_errno = (unsigned int) -res;
    return res;
}

static long my_sendto(int fd,char* buf,long size,long flag,void* addr,long addr_length){
    long  res = 0;
    asm_sendto(fd,buf,size,flag,addr,addr_length,res);
    asm volatile(".pool");
    g_errno = (unsigned int) -res;
    return res;
}

static long my_select(int nfds,fd_set *readafds,fd_set* writefds,fd_set* exceptfds,struct timeval* timeout){
    long  res = 0;
    asm_select(nfds, readafds, writefds, exceptfds, timeout,res);
    g_errno = (unsigned int) -res;
    return res;
}








static long my_waitpid(int pid,long state_addr,long flag){
    long  res = 0;
    asm_waitpid(pid,state_addr,flag,res);
    g_errno = (unsigned int) -res;
    return res;
}

static long my_exit(int code){
    long  res = 0;
    asm_exit(code,res);
    g_errno = (unsigned int) -res;
    return res;
}

static long my_exit_group(int code){
    long  res = 0;
    asm_exit_group(code,res);
    g_errno = (unsigned int) -res;
    return res;
}

static void my_alarm(int time){
    long  res = 0;
    asm_alarm(time,res);
    g_errno = (unsigned int) -res;
}

static void my_chroot(char* path){
    long  res = 0;
    asm_chroot(path,res);
    g_errno = (unsigned int) -res;
}



static long my_kill(int pid,int sig){
    long  res = 0;
    asm_kill(pid,sig,res);
    g_errno = (unsigned int) -res;
    return res;
}

static long my_execve(char* elf,char** arg,char** env){
    long  res = 0;
    asm_execve((long)elf,(long)arg,(long)env,res);
    g_errno = (unsigned int) -res;
    return res;
}

static long my_dup2(int oldfd,int newfd){
    long  res = 0;
    asm_dup2(oldfd, newfd, res);
    g_errno = (unsigned int) -res;
    return res;
}

static long my_pipe(int* fd){
    long  res = 0;
    asm_pipe(fd,res);
    g_errno = (unsigned int) -res;
    return res;
}



static long my_fork(){
    long  res = 0;
    long  ptid;
    long  ctid;
    long sigchld = SIGCHLD;
    long null = 0;
    //asm_fork(res);
    asm_clone(sigchld,null,null,null,null,res);
    g_errno = (unsigned int) -res;
    return res;
}


static long my_fcntl(int fd,long cmd,long flag){
    long  res = 0;
    asm_fcntl(fd,cmd,flag,res);
    g_errno = (unsigned int) -res;
    return res;
}

static long my_brk(void* addr){
    long  res = 0;
    asm_brk(addr,res);
    g_errno = (unsigned int) -res;
    return res;
}


static long my_rt_sigaction(int sig,void* new_action,void* old_action){
    long  res = 0;
    asm_rt_sigaction(sig,new_action,old_action,res);
    g_errno = (unsigned int) -res;
    return res;
}

static long my_prctl(unsigned long options,unsigned long arg2,unsigned long arg3,unsigned long arg4,unsigned long arg5){
    long  res = 0;
    asm_prctl(options, arg2, arg3, arg4, arg5,res);
    g_errno = (unsigned int) -res;
    return res;
}

static long my_unlink(void* file_name){
    long  res = 0;
    asm_unlink(file_name,res);
    g_errno = (unsigned int) -res;
    return res;
}

static int my_accept(unsigned long sockfd, struct sockaddr *addr,socklen_t *addrlen, unsigned long flags){
    long  res = 0;
    asm_accept(sockfd,addr,addrlen,flags,res);
    asm volatile(".pool");
    g_errno = (unsigned int) -res;
    return res;
}

static int my_listen(unsigned long sockfd, unsigned long backlog){
    long  res = 0;
    asm_listen(sockfd,backlog,res);
    g_errno = (unsigned int) -res;
    return res;
}

static int my_bind(unsigned long sockfd, const struct sockaddr *addr,socklen_t addrlen){
    long  res = 0;
    asm_bind(sockfd,addr,addrlen,res);
    asm volatile(".pool");
    g_errno = (unsigned int) -res;
    return res;
}

static int my_setsid(){
    long  res = 0;
    asm_setsid(res);
    g_errno = (unsigned int) -res;
    return res;
}

static mode_t my_umask(mode_t mask){
    long  res = 0;
    asm_umask(mask,res);
    g_errno = (unsigned int) -res;
    return res;
}

// static int my_access(char *path, int mode){
//     long  res = 0;
//     asm_stat(path, mode, res);
//     g_errno = (unsigned int) -res;
//     return res;
// }


#endif //HOOKUTILV3_SYSCALL_H

#pragma GCC pop_options