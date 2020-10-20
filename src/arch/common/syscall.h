//
// Created by root on 7/23/20.
//

#ifndef HOOKUTILV3_SYSCALL_H
#define HOOKUTILV3_SYSCALL_H

#include "arch.h"
#include <signal.h>

static unsigned int g_errno;

IN_LINE long my_open(char* name,long mode,long flag){
    long res = 0;
    asm_open(name,mode,flag,res);
    g_errno = (unsigned int) -res;
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
    g_errno = (unsigned int) -res;
    return res;
}
//
IN_LINE long my_mmap(long addr, long length, int prot, int flags,
                     int fd, off_t offset){
    long res = 0;
    asm_mmap(addr,(long)length,(long)prot,(long)flags,(long)fd,(long)offset,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_munmap(void* addr,long length){
    long res = 0;
    asm_munmap((long)addr,(long)length,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_read(int fd,const char* buf,long length){
    long res = 0;
    asm_read(fd,buf,length,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_write(int fd,const char* buf,long length){
    long res = 0;
    asm_write(fd,buf,length,res);
    g_errno = (unsigned int) -res;
    return res;
}




IN_LINE long my_socket(long af,long type,long flag){
    long res = 0;
    asm_socket(af,type,flag,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_connect(long fd,void* addr,long size){
    long res = 0;
    asm_connect(fd,addr,size,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_send(int fd,char* buf,long size,long flag){
    long res = 0;
    asm_send(fd,buf,size,flag,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_setsockopt(long sockfd, long level, long optname, void *optval, long optlen){
    long res = 0;
    asm_setsockopt(sockfd, level, optname, optval, optlen,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE int my_getsockopt (int fd, int level, int optname, void * optval, socklen_t * optlen){
    long res = 0;
    asm_getsockopt(fd,level,optname,optval,optlen,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_sendto(int fd,char* buf,long size,long flag,void* addr,long addr_length){
    long res = 0;
    asm_sendto(fd,buf,size,flag,addr,addr_length,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_select(int nfds,fd_set *readafds,fd_set* writefds,fd_set* exceptfds,struct timeval* timeout){
    long res = 0;
    asm_select(nfds, readafds, writefds, exceptfds, timeout,res);
    g_errno = (unsigned int) -res;
    return res;
}








IN_LINE long my_waitpid(int pid,long state_addr,long flag){
    long res = 0;
    asm_waitpid(pid,state_addr,flag,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_exit(int code){
    long res = 0;
    asm_exit(code,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_exit_group(int code){
    long res = 0;
    asm_exit_group(code,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE void my_alarm(int time){
    long res = 0;
    asm_alarm(time,res);
    g_errno = (unsigned int) -res;
}

IN_LINE void my_chroot(char* path){
    long res = 0;
    asm_chroot(path,res);
    g_errno = (unsigned int) -res;
}



IN_LINE long my_kill(int pid,int sig){
    long res = 0;
    asm_kill(pid,sig,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_execve(char* elf,char** arg,char** env){
    long res = 0;
    asm_execve((long)elf,(long)arg,(long)env,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_dup2(int oldfd,int newfd){
    long res = 0;
    asm_dup2(oldfd, newfd, res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_pipe(int* fd){
    long res = 0;
    asm_pipe(fd,res);
    g_errno = (unsigned int) -res;
    return res;
}



IN_LINE long my_fork(){
    long res = 0;
    long ptid;
    long ctid;
    //asm_fork(res);
    asm_clone(SIGCHLD,NULL,NULL,NULL,NULL,res);
    g_errno = (unsigned int) -res;
    return res;
}


IN_LINE long my_fcntl(int fd,long cmd,long flag){
    long res = 0;
    asm_fcntl(fd,cmd,flag,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_brk(void* addr){
    long res = 0;
    asm_brk(addr,res);
    g_errno = (unsigned int) -res;
    return res;
}


IN_LINE long my_rt_sigaction(int sig,void* new_action,void* old_action){
    long res = 0;
    asm_rt_sigaction(sig,new_action,old_action,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_prctl(unsigned long options,unsigned long arg2,unsigned long arg3,unsigned long arg4,unsigned long arg5){
    long res = 0;
    asm_prctl(options, arg2, arg3, arg4, arg5,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE long my_unlink(void* file_name){
    long res = 0;
    asm_unlink(file_name,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE int my_accept(unsigned long sockfd, struct sockaddr *addr,socklen_t *addrlen, unsigned long flags){
    long res = 0;
    asm_accept(sockfd,addr,addrlen,flags,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE int my_listen(unsigned long sockfd, unsigned long backlog){
    long res = 0;
    asm_listen(sockfd,backlog,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE int my_bind(unsigned long sockfd, const struct sockaddr *addr,socklen_t addrlen){
    long res = 0;
    asm_bind(sockfd,addr,addrlen,res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE int my_setsid(){
    long res = 0;
    asm_setsid(res);
    g_errno = (unsigned int) -res;
    return res;
}

IN_LINE mode_t my_umask(mode_t mask){
    long res = 0;
    asm_umask(mask,res);
    g_errno = (unsigned int) -res;
    return res;
}


#endif //HOOKUTILV3_SYSCALL_H
