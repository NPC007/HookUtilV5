//
// Created by root on 7/23/20.
//

#ifndef HOOKUTILV3_SYSCALL_H
#define HOOKUTILV3_SYSCALL_H

#include "arch.h"
#include <signal.h>



IN_LINE long my_open(char* name,long mode,long flag){
    long res = 0;
    asm_open(name,mode,flag,res);
    return res;
}
IN_LINE long my_close(long fd){
    long res = 0;
    asm_close(fd,res);
    return res;
}

IN_LINE long my_mprotect(void *start, long len, long prot){
    long res = 0;
    asm_mprotect((long)start,(long)len,(long)prot,res);
    return res;
}
//static __attribute__ ((noinline))
IN_LINE long my_mmap(long addr, long length, int prot, int flags,
                     int fd, off_t offset){
    long res = 0;
    asm_mmap(addr,(long)length,(long)prot,(long)flags,(long)fd,(long)offset,res);
    return res;
}

IN_LINE long my_munmap(void* addr,long length){
    long res = 0;
    asm_munmap((long)addr,(long)length,res);
    return res;
}

IN_LINE long my_read(int fd,const char* buf,long length){
    long res = 0;
    asm_read(fd,buf,length,res);
    return res;
}

IN_LINE long my_write(int fd,const char* buf,long length){
    long res = 0;
    asm_write(fd,buf,length,res);
    return res;
}

static long my_socket(long af,long type,long flag){
    long res = 0;
    asm_socket(af,type,flag,res);
    return res;
}

static long my_connect(long fd,void* addr,long size){
    long res = 0;
    asm_connect(fd,addr,size,res);
    return res;
}

static long my_send(int fd,char* buf,long size,long flag){
    long res = 0;
    asm_send(fd,buf,size,flag,res);

    return res;
}

static long my_setsockopt(long sockfd, long level, long optname, void *optval, long optlen){
    long res = 0;
    asm_setsockopt(sockfd, level, optname, optval, optlen,res);
    return res;
}

static long my_sendto(int fd,char* buf,long size,long flag,void* addr,long addr_length){
    long res = 0;
    asm_sendto(fd,buf,size,flag,addr,addr_length,res);
    return res;
}

static long my_select(int nfds,fd_set *readafds,fd_set* writefds,fd_set* exceptfds,struct timeval* timeout){
    long res = 0;
    asm_select(nfds, readafds, writefds, exceptfds, timeout,res);
    return res;
}

IN_LINE long my_waitpid(int pid,long state_addr,long flag){
    long res = 0;
    asm_waitpid(pid,state_addr,flag,res);
    return res;
}

IN_LINE long my_exit(int code){
    long res = 0;
    asm_exit(code,res);
    return res;
}

IN_LINE void my_alarm(int time){
    long res = 0;
    asm_alarm(time,res);
}

IN_LINE void my_chroot(char* path){
    long res = 0;
    asm_chroot(path,res);
}

static int my_getsockopt (int fd, int level, int optname, void * optval, socklen_t * optlen){
    long res = 0;
    asm_getsockopt(fd,level,optname,optval,optlen,res);
    return res;
}

IN_LINE long my_kill(int pid,int sig){
    long res = 0;
    asm_kill(pid,sig,res);
    return res;
}

IN_LINE long my_execve(char* elf,char** arg,char** env){
    long res = 0;
    asm_execve((long)elf,(long)arg,(long)env,res);
    return res;
}

IN_LINE long my_dup2(int oldfd,int newfd){
    long res = 0;
    asm_dup2(oldfd, newfd, res);
    return res;
}

IN_LINE long my_pipe(int* fd){
    long res = 0;
    asm_pipe(fd,res);
    return res;
}



IN_LINE long my_fork(){
    long res = 0;
    long ptid;
    long ctid;
    //asm_fork(res);
    asm_clone(SIGCHLD,NULL,NULL,NULL,NULL,res);
    return res;
}


IN_LINE long my_fcntl(int fd,long cmd,long flag){
    long res = 0;
    asm_fcntl(fd,cmd,flag,res);
    return res;
}





#endif //HOOKUTILV3_SYSCALL_H
