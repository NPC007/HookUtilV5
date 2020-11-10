//
// Created by runshine on 10/20/20.
//
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#define DEBUG_LOG(format,...) printf("[THREAD_%d][DEBUG]:"format"\n",getpid(),##__VA_ARGS__)
#define UP_PADDING(X,Y)  ((unsigned long)((((unsigned long)(X))/((unsigned long)(Y))+1)*((unsigned long)(Y))))
#define DOWN_PADDING(X,Y) ((unsigned long)(((unsigned long)(X))-((unsigned long)(X))%((unsigned long)(Y))))

long get_file_size(char* file){
    struct stat statbuf;
    if(stat(file,&statbuf)<0){
        return -1;
    }
    else{
        return statbuf.st_size;
    }
}

char* get_file_content(char* config_file_name){
    FILE *f;
    long len;
    char *data;
    f=fopen(config_file_name,"rb");
    if(f == NULL){
        DEBUG_LOG("unable open file: %s, error: %s\n",config_file_name,strerror(errno));
        exit(-1);
    }
    fseek(f,0,SEEK_END);
    len=ftell(f);
    fseek(f,0,SEEK_SET);
    data=(char*)malloc(len+1);
    memset(data,0,len+1);
    int need_read_bytes = len;
    int ret = 0;
    while(need_read_bytes) {
       ret = fread(data + len - need_read_bytes , 1, need_read_bytes, f);
       if(ret <= 0) {
           DEBUG_LOG("Failed to read file: %s",config_file_name);
           exit(-1);
       }
       need_read_bytes = need_read_bytes - ret;
    }
    fclose(f);
    return data;
}

int usage(char* program) {
    DEBUG_LOG("Usage: %s FILE_PATH SHARE_MEM_ID", program);
    exit(-1);
}

int should_stop = 0;
void sighandler(int sig){
    should_stop = 1;
}
int main(int argc,char* argv[]){
    if(argc!=3)
        usage(argv[0]);
    char* file_name = argv[2];
    int id = atoi(argv[1]);
    if(id < 0){
        DEBUG_LOG("ID:%d is failed",id);
        exit(-1);
    }
    if(access(file_name,0) != 0){
        DEBUG_LOG("access file:%s is failed",file_name);
        exit(-1);
    }
    int file_size = get_file_size(file_name);
    int share_memory_size = UP_PADDING(file_size,0x1000);

    int shmid = shmget((key_t)id,share_memory_size , 0777);
    if(shmid !=-1){
        DEBUG_LOG("SHARE_MEM_ID: %d should not exist before",id);
        shmctl(shmid, IPC_RMID, 0) ;
        exit(-1);
    }
    shmid = shmget((key_t)id,share_memory_size , 0777|IPC_CREAT);
    if(shmid == -1){
        DEBUG_LOG("SHARE_MEM_ID: %d failed to create",id);
        exit(-1);
    }
    void* shm = shmat(shmid, 0, 0);
    if(shm == NULL){
        DEBUG_LOG("SHARE_MEM_ID: %d failed to shmat",id);
        shmctl(shmid, IPC_RMID, 0) ;
        exit(-1);
    }
    void* data = get_file_content(file_name);
    memcpy(shm,data,file_size);
    DEBUG_LOG("create share memory, id: %d, length: %x, uppading_length: %lx, addr: %p",id,file_size, UP_PADDING(file_size,0x1000),shm);
    for(int i=1;i<30;i++)
        signal(i, sighandler);
    //SIGINT

    while(!should_stop){
        sleep(1);
        DEBUG_LOG("SHARE_MEMORY_WORKING");
    }
    shmctl(shmid, IPC_RMID, 0) ;
    return 0;
}