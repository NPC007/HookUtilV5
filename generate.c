#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <elf.h>
#include <errno.h>
#include "hook.h"

#define MAX_SO_FILE_SIZE 1*1024*1024

#define UP_PADDING(X,Y)  ((void*)(((long)X/Y+1)*Y))
#define DOWN_PADDING(X,Y) ((void*)((long)X-(long)X%Y))

typedef struct Config{
    char elf_path[256];
    char patch_path[256];
    char dest_path[256];
    char config_h_path[256];
}Config;

long get_file_size(char* file){
    struct stat statbuf;
    if(stat(file,&statbuf)<0){
        return -1;
    }
    else{
        //printf("file:%s size=%d\n",file,statbuf.st_size);
        return statbuf.st_size;
    }
}

long padding_size(long size){
    return (size%0x1000)?((size/0x1000)+1)*0x1000:size;
}

void write_file_line(int fd,char* line){
    printf("%s\n",line);
    write(fd,line,strlen(line));
    write(fd,"\n",1);
}

void write_marco_define(int fd,char* marco_name,char* marco_value){
    char* buf = malloc(strlen("#define")+strlen(marco_name) + strlen(marco_value)+ 512);
    memcpy(buf,"#define ",strlen("#define ")+1);
    strcat(buf,marco_name);
    strcat(buf," ");
    strcat(buf,marco_value);
    write_file_line(fd,buf);
    free(buf);
}

Config* get_config(){
    Config* config = malloc(sizeof(Config));
    strcpy(config->dest_path,"output_elf");
    strcpy(config->elf_path,"input_elf");
    strcpy(config->patch_path,"libhook.so");
    strcpy(config->config_h_path,"config.h");
}


Elf_Phdr* get_elf_phdr_type(void* elf_base,int type){
    Elf_Ehdr* ehdr= (Elf_Ehdr*)elf_base;
    int j = 0;
    for(int i=0;i<ehdr->e_phnum;i++){
        Elf_Phdr* phdr = (Elf_Phdr*)((char*)ehdr+ehdr->e_phoff+ehdr->e_phentsize*i);
        if(phdr->p_type == type)
            return phdr;
    }
    return NULL;
}

int main(int argc,char* argv){
    Config* config = get_config();
    char* elf = config->elf_path;
    char* config_h = config->config_h_path;
    char buf[32];
    memset(buf,0,32);
    int elf_fd = open(elf,O_RDONLY);
    if(elf_fd == -1){
        printf("unable open elf file, please rename it to input_elf: %s\n",strerror(errno));
        exit(-1);
    }
    int config_h_fd = open(config_h,O_WRONLY|O_CREAT|O_TRUNC);
    int elf_file_size = get_file_size(elf);
    char* elf_file_base = (char*)mmap(0,elf_file_size,PROT_READ,MAP_PRIVATE,elf_fd,0);


    memset(buf,0,32);
    snprintf(buf,32,"0x%lx",_ELF_BASE);
    write_marco_define(config_h_fd,"ELF_BASE",buf);

    memset(buf,0,32);
    snprintf(buf,32,"0x%lx",_ELF_SIZE);
    write_marco_define(config_h_fd,"ELF_SIZE",buf);

    memset(buf,0,32);
    snprintf(buf,32,"0x%lx",_PHDR_PAGE_SIZE);
    write_marco_define(config_h_fd,"PHDR_PAGE_SIZE",buf);

    memset(buf,0,32);
    snprintf(buf,32,"0x%lx",_PARAMS_PAGE_SIZE);
    write_marco_define(config_h_fd,"PARAMS_PAGE_SIZE",buf);

    munmap(elf_file_base,get_file_size(elf));
    close(elf_fd);
    close(config_h_fd);
    free(pt_load_phdr);
}