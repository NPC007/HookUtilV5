#include "file_utils.h"


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

void write_marco_str_define(int fd,char* marco_name,char* marco_value){
    char tmp_buf[256];
    memset(tmp_buf,0,sizeof(tmp_buf));
    snprintf(tmp_buf,255,"\"%s\"",marco_value);
    write_marco_define(fd,marco_name,tmp_buf);
}


void increase_file(char* file,int total_length){
    int current_length = get_file_size(file);
    if(total_length < current_length){
        printf("total_length is less than current_length\n");
        exit(-1);
    }
    FILE *p = fopen(file,"ab+");
    char *buf = malloc(total_length-current_length);
    memset(buf,0,total_length-current_length);
    int need_write = total_length-current_length;
    int rc = 0;
    while(need_write >0) {
        rc = fwrite("\x00", 1, need_write, p);
        need_write = need_write - rc;
    }
    fflush(p);
    fclose(p);
    free(buf);
}

char* get_file_content(char* config_file_name){
    FILE *f;
    long len;
    char *data;
    f=fopen(config_file_name,"rb");
    if(f == NULL){
        printf("unable open file: %s, error: %s\n",config_file_name,strerror(errno));
        exit(-1);
    }
    fseek(f,0,SEEK_END);
    len=ftell(f);
    fseek(f,0,SEEK_SET);
    data=(char*)malloc(len+1);
    memset(data,0,len+1);
    fread(data,1,len,f);
    fclose(f);
    return data;
}

char* get_file_content_length(char* file,int offset,int len){
    FILE *f;
    char *data;
    int ret = 0;
    int last = len;
    f=fopen(file,"rb");
    fseek(f,0,offset);
    data=(char*)malloc(len);
    memset(data,0,len);
    while(last!=0) {
        ret = fread(data, 1, len, f);
        if(ret >= 0 )
            last = last - ret;
        else{
            printf("read file: %s failed\n",file);
        }
    }
    fclose(f);
    return data;
}

void copy_file(char* old_file,char* new_file){
    FILE *op,*inp;
    op=fopen(old_file,"rb");
    inp=fopen(new_file,"wb");
    if(op == NULL || inp == NULL){
        printf("Failed to copy file\n");
        exit(-1);
    }
    char buf[4096];
    int ret = 0;
    char c;
    while((ret = fread(buf,sizeof(char),sizeof(buf),op))!=0)
    {
        fwrite(buf,sizeof(char),ret,inp);
    }
    fclose(op);
    fclose(inp);
}


void open_mmap_check(char* file_name,int mode,int *fd,void** mmap_base,int prot,int flag,long* size){
    *fd = open(file_name,mode);
    if(*fd < 0){
        printf("unable open file: %s, error:%s\n",file_name,strerror(errno));
        exit(-1);
    }
    long file_size = get_file_size(file_name);
    if(file_size %0x1000 !=0)
        file_size = UP_PADDING(file_size,0x1000);
    *(mmap_base) = mmap(NULL,file_size,prot,flag,*fd,0);
    *size = file_size;
    if(*(mmap_base) <= 0){
        printf("unable mmap file: %s, error:%s\n",file_name,strerror(errno));
        exit(-1);
    }
}

void close_and_munmap(char* file_name,int fd,char* base,long *size){
    long file_size = get_file_size(file_name);
    if(file_size %0x1000 !=0)
        file_size = UP_PADDING(file_size,0x1000);
    munmap(base,*size);
    close(fd);
}