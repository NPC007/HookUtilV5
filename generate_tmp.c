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
#include "cJSON.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>


//#define UP_PADDING(X,Y)  ((long)(((long)X/Y+1)*Y))
//#define DOWN_PADDING(X,Y) ((long)((long)X-(long)X%Y))


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

typedef struct
{
    unsigned int count[2];
    unsigned int state[4];
    unsigned char buffer[64];
}MD5_CTX;


#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y ^ (x | ~z))
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))
#define FF(a,b,c,d,x,s,ac) \
{ \
	a += F(b,c,d) + x + ac; \
	a = ROTATE_LEFT(a,s); \
	a += b; \
}
#define GG(a,b,c,d,x,s,ac) \
{ \
	a += G(b,c,d) + x + ac; \
	a = ROTATE_LEFT(a,s); \
	a += b; \
}
#define HH(a,b,c,d,x,s,ac) \
{ \
	a += H(b,c,d) + x + ac; \
	a = ROTATE_LEFT(a,s); \
	a += b; \
}
#define II(a,b,c,d,x,s,ac) \
{ \
	a += I(b,c,d) + x + ac; \
	a = ROTATE_LEFT(a,s); \
	a += b; \
}



static unsigned char PADDING[]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

void MD5Init(MD5_CTX *context)
{
    context->count[0] = 0;
    context->count[1] = 0;
    context->state[0] = 0x12345678;
    context->state[1] = 0xEFDACB89;
    context->state[2] = 0xA8ADDCFE;
    context->state[3] = 0x1A325476;
}


void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len)
{
    unsigned int i = 0,j = 0;
    while(j < len)
    {
        output[j] = input[i] & 0xFF;
        output[j+1] = (input[i] >> 8) & 0xFF;
        output[j+2] = (input[i] >> 16) & 0xFF;
        output[j+3] = (input[i] >> 24) & 0xFF;
        i++;
        j+=4;
    }
}

void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len)
{
    unsigned int i = 0,j = 0;
    while(j < len)
    {
        output[i] = (input[j]) |
                    (input[j+1] << 8) |
                    (input[j+2] << 16) |
                    (input[j+3] << 24);
        i++;
        j+=4;
    }
}

void MD5Transform(unsigned int state[4],unsigned char block[64])
{
    unsigned int a = state[0];
    unsigned int b = state[1];
    unsigned int c = state[2];
    unsigned int d = state[3];
    unsigned int x[64];
    memset((void*)x,0,64);
    MD5Decode(x,block,64);
    FF(a, b, c, d, x[ 0], 7, 0xd76aa478); /* 1 */
    FF(d, a, b, c, x[ 1], 12, 0xe8c7b756); /* 2 */
    FF(c, d, a, b, x[ 2], 17, 0x242070db); /* 3 */
    FF(b, c, d, a, x[ 3], 22, 0xc1bdceee); /* 4 */
    FF(a, b, c, d, x[ 4], 7, 0xf57c0faf); /* 5 */
    FF(d, a, b, c, x[ 5], 12, 0x4787c62a); /* 6 */
    FF(c, d, a, b, x[ 6], 17, 0xa8304613); /* 7 */
    FF(b, c, d, a, x[ 7], 22, 0xfd469501); /* 8 */
    FF(a, b, c, d, x[ 8], 7, 0x698098d8); /* 9 */
    FF(d, a, b, c, x[ 9], 12, 0x8b44f7af); /* 10 */
    FF(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
    FF(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
    FF(a, b, c, d, x[12], 7, 0x6b901122); /* 13 */
    FF(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
    FF(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
    FF(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */

    /* Round 2 */
    GG(a, b, c, d, x[ 1], 5, 0xf61e2562); /* 17 */
    GG(d, a, b, c, x[ 6], 9, 0xc040b340); /* 18 */
    GG(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
    GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa); /* 20 */
    GG(a, b, c, d, x[ 5], 5, 0xd62f105d); /* 21 */
    GG(d, a, b, c, x[10], 9,  0x2441453); /* 22 */
    GG(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
    GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8); /* 24 */
    GG(a, b, c, d, x[ 9], 5, 0x21e1cde6); /* 25 */
    GG(d, a, b, c, x[14], 9, 0xc33707d6); /* 26 */
    GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); /* 27 */
    GG(b, c, d, a, x[ 8], 20, 0x455a14ed); /* 28 */
    GG(a, b, c, d, x[13], 5, 0xa9e3e905); /* 29 */
    GG(d, a, b, c, x[ 2], 9, 0xfcefa3f8); /* 30 */
    GG(c, d, a, b, x[ 7], 14, 0x676f02d9); /* 31 */
    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH(a, b, c, d, x[ 5], 4, 0xfffa3942); /* 33 */
    HH(d, a, b, c, x[ 8], 11, 0x8771f681); /* 34 */
    HH(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
    HH(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
    HH(a, b, c, d, x[ 1], 4, 0xa4beea44); /* 37 */
    HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9); /* 38 */
    HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); /* 39 */
    HH(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
    HH(a, b, c, d, x[13], 4, 0x289b7ec6); /* 41 */
    HH(d, a, b, c, x[ 0], 11, 0xeaa127fa); /* 42 */
    HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); /* 43 */
    HH(b, c, d, a, x[ 6], 23,  0x4881d05); /* 44 */
    HH(a, b, c, d, x[ 9], 4, 0xd9d4d039); /* 45 */
    HH(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
    HH(b, c, d, a, x[ 2], 23, 0xc4ac5665); /* 48 */

    /* Round 4 */
    II(a, b, c, d, x[ 0], 6, 0xf4292244); /* 49 */
    II(d, a, b, c, x[ 7], 10, 0x432aff97); /* 50 */
    II(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
    II(b, c, d, a, x[ 5], 21, 0xfc93a039); /* 52 */
    II(a, b, c, d, x[12], 6, 0x655b59c3); /* 53 */
    II(d, a, b, c, x[ 3], 10, 0x8f0ccc92); /* 54 */
    II(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
    II(b, c, d, a, x[ 1], 21, 0x85845dd1); /* 56 */
    II(a, b, c, d, x[ 8], 6, 0x6fa87e4f); /* 57 */
    II(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
    II(c, d, a, b, x[ 6], 15, 0xa3014314); /* 59 */
    II(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
    II(a, b, c, d, x[ 4], 6, 0xf7537e82); /* 61 */
    II(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
    II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); /* 63 */
    II(b, c, d, a, x[ 9], 21, 0xeb86d391); /* 64 */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void MD5Update(MD5_CTX *context,unsigned char *input,unsigned int inputlen)
{
    unsigned int i = 0,index = 0,partlen = 0;
    index = (context->count[0] >> 3) & 0x3F;
    partlen = 64 - index;
    context->count[0] += inputlen << 3;
    if(context->count[0] < (inputlen << 3))
        context->count[1]++;
    context->count[1] += inputlen >> 29;

    if(inputlen >= partlen)
    {
        memcpy(&context->buffer[index],input,partlen);
        MD5Transform(context->state,context->buffer);
        for(i = partlen;i+64 <= inputlen;i+=64)
            MD5Transform(context->state,&input[i]);
        index = 0;
    }
    else
    {
        i = 0;
    }
    memcpy(&context->buffer[index],&input[i],inputlen-i);
}

void MD5Final(MD5_CTX *context,unsigned char digest[16])
{
    unsigned int index = 0,padlen = 0;
    unsigned char bits[8];
    index = (context->count[0] >> 3) & 0x3F;
    padlen = (index < 56)?(56-index):(120-index);
    MD5Encode(bits,context->count,8);
    MD5Update(context,PADDING,padlen);
    MD5Update(context,bits,8);
    MD5Encode(digest,context->state,16);
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
    f=fopen(file,"rb");
    fseek(f,0,offset);
    data=(char*)malloc(len);
    memset(data,0,len);
    fread(data,1,len,f);
    fclose(f);
    return data;
}

void copy_file(char* old_file,char* new_file){
    int old_file_fd = open(old_file,O_RDONLY);
    int new_file_fd = open(new_file,O_RDWR|O_TRUNC|O_CREAT);
    long old_file_size = get_file_size(old_file);
    ftruncate(new_file_fd,old_file_size);
    char* old_file_base = (char*)mmap(0,old_file_size,PROT_READ,MAP_PRIVATE,old_file_fd,0);
    char* new_file_base = (char*)mmap(0,old_file_size,PROT_READ|PROT_WRITE,MAP_SHARED,new_file_fd,0);
    memcpy(new_file_base,old_file_base,old_file_size);
    munmap(old_file_base,old_file_size);
    munmap(new_file_base,old_file_size);
    close(old_file_fd);
    close(new_file_fd);
    printf("Copy %s --> %s\n",old_file,new_file);
}


void open_mmap_check(char* file_name,int mode,int *fd,void** mmap_base,int prot,int flag,long* size){
    *fd = open(file_name,mode);
    if(*fd < 0){
        printf("unable open file: %s, error:\n",file_name,strerror(errno));
        exit(-1);
    }
    long file_size = get_file_size(file_name);
    if(file_size %0x1000 !=0)
        file_size = UP_PADDING(file_size,0x1000);
    *(mmap_base) = mmap(NULL,file_size,prot,flag,*fd,0);
    *size = file_size;
    if(*(mmap_base) <= 0){
        printf("unable mmap file: %s, error:\n",file_name,strerror(errno));
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

Elf_Shdr* get_elf_section_by_index(long index,Elf_Ehdr* elf_base){
    Elf_Ehdr* ehdr = (Elf_Ehdr*) elf_base;
    Elf_Shdr* shdr = (Elf_Shdr*)((char*)elf_base + ehdr->e_shoff + index*ehdr->e_shentsize);
    return shdr;
}

Elf_Shdr* get_elf_shstrtab(Elf_Ehdr* elf_base){
    Elf_Ehdr* ehdr = (Elf_Ehdr*) elf_base;
    return get_elf_section_by_index(ehdr->e_shstrndx,elf_base);
}

Elf_Shdr* get_elf_section_by_type(int type,Elf_Ehdr* elf_base){
    Elf_Ehdr* ehdr = (Elf_Ehdr*) elf_base;
    int i = 0;
    Elf_Shdr* shstrtab_section = get_elf_shstrtab(elf_base);
    if(shstrtab_section == NULL)
        return NULL;
    char* strtab = (char*)((char*)elf_base + shstrtab_section->sh_offset);
    for(i=0;i<ehdr->e_shnum;i++){
        Elf_Shdr* shdr = (Elf_Shdr*)((char*)elf_base + ehdr->e_shoff + i*ehdr->e_shentsize);
        if(shdr->sh_type == type)
            return shdr;
    }
    return NULL;
}

Elf_Shdr* get_elf_section_by_name(char* section_name,Elf_Ehdr* elf_base){
    Elf_Ehdr* ehdr = (Elf_Ehdr*) elf_base;
    int i = 0;
    Elf_Shdr* shstrtab_section = get_elf_shstrtab(elf_base);
    if(shstrtab_section == NULL)
        return NULL;
    char* strtab = (char*)((char*)elf_base + shstrtab_section->sh_offset);
    for(i=0;i<ehdr->e_shnum;i++){
        Elf_Shdr* shdr = (Elf_Shdr*)((char*)elf_base + ehdr->e_shoff + i*ehdr->e_shentsize);
        if(strcasecmp((char*)&strtab[shdr->sh_name],section_name)==0)
            return shdr;
    }
    return NULL;
}

void get_section_data(Elf_Ehdr* ehdr,char* section_name,void** buf,int* len){
    Elf_Shdr* shdr = get_elf_section_by_name(section_name,ehdr);
    if(shdr == NULL){
        *buf = NULL;
        *len = 0;
        return;
    }
    *buf = (char*)((char*)ehdr + shdr->sh_offset );
    *len = shdr->sh_size;
}

void get_section_data_from_file(char* file,char* section_name,void** buf,int* len){
    int fd;
    char* base;
    long file_size = 0;
    open_mmap_check(file,O_RDONLY,&fd,(void**)&base,PROT_READ,MAP_PRIVATE,&file_size);
    Elf_Shdr* shdr = get_elf_section_by_name(section_name,(Elf_Ehdr*)base);
    if(shdr == NULL){
        *buf = NULL;
        *len = 0;
        return;
    }
    *buf = malloc(shdr->sh_size);
    *len = shdr->sh_size;
    memcpy(*buf,(char*)base + shdr->sh_offset,*len);
    close_and_munmap(file,fd,base,&file_size);
}


unsigned long get_elf_load_base(Elf_Ehdr *ehdr){
    unsigned long min_value = -1;
    Elf_Phdr* pt_load;
    for(int i=0;i<ehdr->e_phnum;i++){
        pt_load = (Elf_Phdr*)((char*)ehdr+ ehdr->e_phoff + ehdr->e_phentsize*i);
        if(pt_load->p_type == PT_LOAD){
            if(min_value == -1)
                min_value = DOWN_PADDING(pt_load->p_vaddr,0x1000);
            else{
                if(min_value >= DOWN_PADDING(pt_load->p_vaddr,0x1000))
                    min_value = DOWN_PADDING(pt_load->p_vaddr,0x1000);
            };
        }
    }
    return min_value;

}

void modify_call_libc_start_main(char* elf_base,long new_function_vaddr,cJSON* config){
    char* libc_start_main_start_call_offset_str = cJSON_GetObjectItem(config,"libc_start_main_start_call_offset")->valuestring;
    char* libc_start_main_start_call_vaddr_str = cJSON_GetObjectItem(config,"libc_start_main_start_call_vaddr")->valuestring;
    long libc_start_main_start_call_offset = 0;
    long libc_start_main_start_call_vaddr = 0;
    puts(libc_start_main_start_call_offset_str);
    puts(libc_start_main_start_call_vaddr_str);
    libc_start_main_start_call_offset = strtol(libc_start_main_start_call_offset_str,NULL,16);
    libc_start_main_start_call_vaddr = strtol(libc_start_main_start_call_vaddr_str,NULL,16);
    if(libc_start_main_start_call_offset == 0 || libc_start_main_start_call_vaddr == 0){
        printf("libc_start_main_start_call_offset or libc_start_main_start_call_vaddr get error, check it\n");
        exit(-1);
    }
    unsigned char* call = (unsigned char*)(elf_base+libc_start_main_start_call_offset);
    char* libc_start_main_addr_type = cJSON_GetObjectItem(config,"libc_start_main_addr_type")->valuestring;
    if(strcmp(libc_start_main_addr_type,"code")==0){
        if((call[0] == 0xE8) || (call[0] == 0x67 && call[1] == 0xE8)){
            if(call[0]==0xE8){
                call[0] = 0xE8;
                *((int*)(&call[1])) = (int)(new_function_vaddr - 5 - libc_start_main_start_call_vaddr) ;
            }else{
                *((int*)(&call[2])) = (int)(new_function_vaddr - 5 - libc_start_main_start_call_vaddr) ;
            }
        }
        else{
            printf("libc_start_main_addr_type check failed, error, call addr bytes:%lx,%lx,%lx,%lx,%lx",call[0],call[1],call[2],call[3],call[4]);
            exit(-1);
        }
    }
    else if(strcmp(libc_start_main_addr_type,"ptr")==0){
        if(call[0] == 0xff && call[1] == 0x15){
            call[0] = 0xE8;
            *((int*)(&call[1])) = (int)(new_function_vaddr - 5 - libc_start_main_start_call_vaddr) ;
        }
        else{
            printf("libc_start_main_addr_type check failed, error, call addr bytes:%lx,%lx,%lx,%lx,%lx,%lx",call[0],call[1],call[2],call[3],call[4],call[5]);
            exit(-1);
        }
    }
    else{
        printf("modify_call_libc_start_main : libc_start_main_addr_type has only two values, one is code, another is ptr\n");
        exit(-1);
    }
}

void add_stage_one_code_to_em_frame(char* libloader_stage_one,char* output_elf,int* first_entry_offset,void** elf_load_base,cJSON* config){
    puts("add_stage_one_code_to_em_frame");
    int libloader_stage_one_fd,output_elf_fd;
    void* libloader_stage_one_base,*output_elf_base;
    long libloader_stage_one_size = 0;
    long output_elf_size = 0;
    open_mmap_check(libloader_stage_one,O_RDONLY,&libloader_stage_one_fd,&libloader_stage_one_base,PROT_READ,MAP_PRIVATE,&libloader_stage_one_size);
    open_mmap_check(output_elf,O_RDWR,&output_elf_fd,&output_elf_base,PROT_READ|PROT_WRITE,MAP_SHARED,&output_elf_size);
    char* buf = NULL;
    int len =0 ;
    get_section_data((Elf_Ehdr*)libloader_stage_one_base,".rodata",(void**)&buf,&len);
    if(buf!=NULL || len!=0){
        printf("libloader_stage_one should not have rodata section, change compile flags:\n");
        exit(-1);
    }
    get_section_data((Elf_Ehdr*)libloader_stage_one_base,".text",(void**)&buf,&len);
    if(buf==NULL || len==0){
        printf("libloader_stage_one should have text section, but we can not find it:\n");
        exit(-1);
    }
    Elf_Shdr* eh_frame_shdr = get_elf_section_by_name(".eh_frame",output_elf_base);
    if(eh_frame_shdr==NULL){
        printf("file:%s have no eh_frame, change first stage code to another place\n",output_elf);
        exit(-1);
    }

    Elf_Shdr* libloader_stage_one_text_section = get_elf_section_by_name(".text",(Elf_Ehdr*)libloader_stage_one_base);

    *elf_load_base = (void*)get_elf_load_base((Elf_Ehdr*)output_elf_base);
    *first_entry_offset = (int)((unsigned long)eh_frame_shdr->sh_addr - (unsigned long)*elf_load_base) + ((Elf_Ehdr*)libloader_stage_one_base)->e_entry - libloader_stage_one_text_section->sh_addr;
    memcpy((char*)output_elf_base+eh_frame_shdr->sh_offset,buf,len);
    modify_call_libc_start_main(output_elf_base,(long) ((char*)*elf_load_base+ *first_entry_offset ),config);
    //((Elf_Ehdr*)output_elf_base)->e_entry =(long) ((char*)*elf_load_base+ *first_entry_offset);
    close_and_munmap(libloader_stage_one,libloader_stage_one_fd,libloader_stage_one_base,&libloader_stage_one_size);
    close_and_munmap(output_elf,output_elf_fd,output_elf_base,&output_elf_size);
}

void _add_segment_desc(char* elf_base,Elf_Phdr* phdr){
    Elf_Ehdr* ehdr = (Elf_Ehdr*)elf_base;
    if(phdr->p_type == PT_PHDR || phdr->p_type == PT_INTERP){
        int i = 0;
        for(;i<ehdr->e_phnum;i++){
            Elf_Phdr* ori_phdr = (Elf_Phdr*)(elf_base + ehdr->e_phoff + i*ehdr->e_phentsize);
            if(ori_phdr->p_type == phdr->p_type){
                memcpy(ori_phdr,phdr,sizeof(Elf_Phdr));
                break;
            }
        }
        if(i==ehdr->e_phnum){
            printf("_add_segment_desc failed, unable to find ori seg, seg type:%d\n",phdr->p_type);
            return;
        }

    }
    else if(phdr->p_type == PT_LOAD) {
        memcpy(elf_base + ehdr->e_phoff + (ehdr->e_phnum * ehdr->e_phentsize), phdr, sizeof(Elf_Phdr));
        ehdr->e_phnum += 1;
    }
    else{
        printf("Unsupport phdr type:%d\n",phdr->p_type);
    }
}

void add_segment(char* elf_file,Elf_Phdr* phdr){
    if(phdr->p_type == PT_PHDR){
        printf("PT_PHDR can not add manual,it will auto done");
        exit(0);
    }
    int elf_file_fd;
    char* elf_file_base;
    long elf_file_size = 0;
    open_mmap_check(elf_file,O_RDWR,&elf_file_fd,(void**)&elf_file_base,PROT_READ|PROT_WRITE,MAP_SHARED,&elf_file_size);
    _add_segment_desc(elf_file_base,phdr);
    close_and_munmap(elf_file,elf_file_fd,elf_file_base,&elf_file_size);
}

char* get_text_section_without_rodata(char* elf_file,int* len){
    int elf_file_fd;
    char* elf_file_base;
    long elf_file_size = 0;
    open_mmap_check(elf_file,O_RDONLY,(int*)&elf_file_fd,(void**)&elf_file_base,PROT_READ,MAP_PRIVATE,&elf_file_size);
    char* code_buf = NULL,*tmp_buf = NULL;
    get_section_data((Elf_Ehdr*)elf_file_base,".rodata",(void**)&tmp_buf,len);
    if(tmp_buf!=NULL || *len!=0){
        printf("libloader_stage_one should not have rodata section, change compile flags:\n");
        exit(-1);
    }
    get_section_data((Elf_Ehdr*)elf_file_base,".text",(void**)&tmp_buf,len);
    if(tmp_buf==NULL || *len==0){
        printf("libloader_stage_one should have text section, but we can not find it:\n");
        exit(-1);
    }
    code_buf = malloc(*len);
    memcpy(code_buf,tmp_buf,*len);
    close_and_munmap(elf_file,elf_file_fd,elf_file_base,&elf_file_size);
    return code_buf;
}

unsigned long get_elf_file_load_base(char* elf_file){
    int elf_file_fd;
    char* elf_file_base;
    long elf_file_size = 0;
    open_mmap_check(elf_file,O_RDONLY,(int*)&elf_file_fd,(void**)&elf_file_base,PROT_READ,MAP_PRIVATE,&elf_file_size);
    return get_elf_load_base((Elf_Ehdr*)elf_file_base);
    close_and_munmap(elf_file,elf_file_fd,elf_file_base,&elf_file_size);
}

void add_stage_one_code_to_new_pt_load(char* libloader_stage_one,char* output_elf,int* first_entry_offset,void** elf_load_base,cJSON* config) {
    puts("add_stage_one_code_to_new_pt_load");
    char *output_elf_base;
    int output_elf_fd;

    int code_len = 0;
    char* code_buf = get_text_section_without_rodata(libloader_stage_one,&code_len);


    int output_file_size = get_file_size(output_elf);
    if(output_file_size%0x1000 != 0) {
        increase_file(output_elf, UP_PADDING(output_file_size, 0x1000));
        output_file_size = UP_PADDING(output_file_size, 0x1000);
    }
    increase_file(output_elf,UP_PADDING(output_file_size+code_len,0x1000));
    unsigned long output_elf_load_base = get_elf_file_load_base(output_elf);

    Elf_Phdr mem_pt_load;
    memset(&mem_pt_load,0,sizeof(Elf_Phdr));
    mem_pt_load.p_type = PT_LOAD;
    mem_pt_load.p_align = 0x1000;
    mem_pt_load.p_filesz = code_len;
    mem_pt_load.p_flags = PF_R | PF_X;
    mem_pt_load.p_memsz = code_len;
    mem_pt_load.p_offset = output_file_size;
    mem_pt_load.p_vaddr = output_elf_load_base+output_file_size;
    mem_pt_load.p_paddr = output_elf_load_base+output_file_size;
    add_segment(output_elf,&mem_pt_load);

    int libloader_stage_one_fd;
    void* libloader_stage_one_base;
    long libloader_stage_one_size = 0;
    long output_elf_size = 0;
    open_mmap_check(libloader_stage_one,O_RDONLY,&libloader_stage_one_fd,&libloader_stage_one_base,PROT_READ,MAP_PRIVATE,&libloader_stage_one_size);

    Elf_Shdr* libloader_stage_one_text_section = get_elf_section_by_name(".text",(Elf_Ehdr*)libloader_stage_one_base);

    open_mmap_check(output_elf,O_RDWR,&output_elf_fd,(void**)&output_elf_base,PROT_READ|PROT_WRITE,MAP_SHARED,&output_elf_size);
    memcpy((char*)output_elf_base+output_file_size,code_buf,code_len);
    *elf_load_base = (void*)get_elf_load_base((Elf_Ehdr*)output_elf_base);
    *first_entry_offset = (int)output_file_size + ((Elf_Ehdr*)libloader_stage_one_base)->e_entry - libloader_stage_one_text_section->sh_addr;
    modify_call_libc_start_main(output_elf_base,(long) ((char*)*elf_load_base+ *first_entry_offset ),config);
    close_and_munmap(output_elf,output_elf_fd,output_elf_base,&output_elf_size);
    close_and_munmap(libloader_stage_one,libloader_stage_one_fd,libloader_stage_one_base,&libloader_stage_one_size);
}

#define MAX_SO_FILE_SIZE 0x1000000
void _padding_elf(char* elf_file_base,char *elf_file){

    int i=0,j=0;
    Elf_Ehdr * ehdr = (Elf_Ehdr *)elf_file_base;
    int* pt_load_phdr = (int*)malloc(sizeof(int)*ehdr->e_phnum);
    int pt_load_phdr_num = 0;
    long _ELF_BASE = 0;
    long _ELF_SIZE = 0;
    long _PHDR_PAGE_SIZE = 0x1000;
    long _PARAMS_PAGE_SIZE = 0x4000;
    printf("Assuming SO Max Size: 0x%x\n\n",MAX_SO_FILE_SIZE);
    Elf_Phdr* phdr;
    for(i=0;i<ehdr->e_phnum;i++){
        phdr = (Elf_Phdr*)((long)ehdr + ehdr->e_phoff + i* ehdr->e_phentsize);
        if(phdr->p_type == PT_LOAD){
            pt_load_phdr[pt_load_phdr_num] = i;
            pt_load_phdr_num ++ ;
        }
    }
    for(i=0;i<pt_load_phdr_num;i++)
        for(j=0;j<pt_load_phdr_num;j++){
            Elf_Phdr* phdr_i = (Elf_Phdr*)((long)ehdr + ehdr->e_phoff + pt_load_phdr[i]* ehdr->e_phentsize);
            Elf_Phdr* phdr_j = (Elf_Phdr*)((long)ehdr + ehdr->e_phoff + pt_load_phdr[j]* ehdr->e_phentsize);
            if(phdr_i->p_vaddr < phdr_j->p_vaddr){
                int temp = pt_load_phdr[i];
                pt_load_phdr[i] = pt_load_phdr[j];
                pt_load_phdr[j] = temp;
            }
        }

    phdr = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + pt_load_phdr[0]* ehdr->e_phentsize);
    printf("sort  by vaddr\n");
    for(i=0;i<pt_load_phdr_num;i++){
        Elf_Phdr* phdr_i = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + pt_load_phdr[i]* ehdr->e_phentsize);
        printf("vaddr:%16lx\tfile_offset:%16lx\tfile_size:%16lx\tmem_size:%16lx\n",(long)phdr_i->p_vaddr,(long)phdr_i->p_offset,(long)phdr_i->p_filesz,(long)phdr_i->p_memsz);
    }
    printf("sort  by vaddr end\n");
    long elf_file_size = get_file_size(elf_file);
    for(i=0;i<pt_load_phdr_num-1;i++){
        Elf_Phdr* phdr_i = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + pt_load_phdr[i]* ehdr->e_phentsize);
        Elf_Phdr* phdr_j = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + pt_load_phdr[i+1]* ehdr->e_phentsize);
        if(DOWN_PADDING(phdr_j->p_vaddr,0x1000)-UP_PADDING(phdr_i->p_vaddr+phdr_i->p_memsz,0x1000)> MAX_SO_FILE_SIZE)
            if(DOWN_PADDING(phdr_j->p_vaddr,0x1000)-UP_PADDING(phdr_i->p_vaddr + padding_size(elf_file_size),0x1000)> MAX_SO_FILE_SIZE){
                _ELF_SIZE = padding_size(elf_file_size);
                printf("find a space between %x and %x, space size is:%lx\n",i,i+1,DOWN_PADDING(phdr_j->p_vaddr,0x1000)-UP_PADDING(phdr_i->p_vaddr+phdr_i->p_memsz,0x1000));
            }
    }
    _ELF_BASE = phdr->p_vaddr - phdr->p_offset;
    if(_ELF_SIZE == 0){
        Elf_Phdr* phdr_first = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + pt_load_phdr[0]* ehdr->e_phentsize);
        Elf_Phdr* phdr_end = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + pt_load_phdr[pt_load_phdr_num-1]* ehdr->e_phentsize);
        _ELF_SIZE = UP_PADDING(phdr_end->p_vaddr + phdr_end->p_memsz,0x1000) - DOWN_PADDING(phdr_first->p_vaddr,0x1000);
        if(_ELF_SIZE<=UP_PADDING(elf_file_size,0x1000))
            _ELF_SIZE = UP_PADDING(elf_file_size,0x1000);
        printf("unable to find any space between pt_load segments, just padding and append to file end\n");
    }
    increase_file(elf_file,_ELF_SIZE);
}

void padding_elf(char *elf_file){
    int elf_file_fd;
    char* elf_file_base;
    elf_file_fd = open(elf_file,O_RDONLY);
    if(elf_file_fd < 0){
        printf("unable open file: %s, error:\n",elf_file,strerror(errno));
        exit(-1);
    }
    long file_size = get_file_size(elf_file);
    if(file_size %0x1000 !=0)
        file_size = UP_PADDING(file_size,0x1000);
    elf_file_base = mmap(NULL,file_size,PROT_READ,MAP_PRIVATE,elf_file_fd,0);
    if(elf_file_base <= 0){
        printf("unable mmap file: %s, error:\n",elf_file,strerror(errno));
        exit(-1);
    }
    _padding_elf(elf_file_base,elf_file);
    munmap(elf_file_base,file_size);
    close(elf_file_fd);
}


void mov_phdr(char* elf_file){
    Elf_Ehdr *ehdr = (Elf_Ehdr*)get_file_content_length(elf_file,0,sizeof(Elf_Ehdr));
    int elf_file_fd;
    char* elf_file_base;
    padding_elf(elf_file);
    if(ehdr->e_phoff % 0x1000 != 0){
        free(ehdr);
        ehdr = NULL;
        increase_file(elf_file,get_file_size(elf_file)+0x1000);
        long elf_file_size = 0;
        open_mmap_check(elf_file,O_RDWR,&elf_file_fd,(void**)&elf_file_base,PROT_READ|PROT_WRITE,MAP_SHARED,&elf_file_size);
        ehdr = (Elf_Ehdr*)elf_file_base;
        memcpy(elf_file_base+get_file_size(elf_file)-0x1000,elf_file_base + ehdr->e_phoff,ehdr->e_phentsize*ehdr->e_phnum);
        ehdr->e_phoff = get_file_size(elf_file)-0x1000;
        Elf_Phdr phdr_pt_load_phdr;
        memset(&phdr_pt_load_phdr,0,sizeof(Elf_Phdr));
        phdr_pt_load_phdr.p_type = PT_LOAD;
        phdr_pt_load_phdr.p_align = 0x1000;
        phdr_pt_load_phdr.p_filesz = 0x1000;
        phdr_pt_load_phdr.p_flags = PF_R | PF_X;
        phdr_pt_load_phdr.p_memsz = 0x1000;
        phdr_pt_load_phdr.p_offset = get_file_size(elf_file)-0x1000;
        Elf_Phdr* first_pt_load_phdr;
        for(int i=0;i<ehdr->e_phnum;i++){
            first_pt_load_phdr = (Elf_Phdr*)(elf_file_base + ehdr->e_phoff +ehdr->e_phentsize*i);
            if(first_pt_load_phdr->p_type == PT_LOAD){
                phdr_pt_load_phdr.p_paddr = first_pt_load_phdr->p_paddr + get_file_size(elf_file)-0x1000;
                phdr_pt_load_phdr.p_vaddr = first_pt_load_phdr->p_vaddr + get_file_size(elf_file)-0x1000;
                break;
            }
        }
        if(phdr_pt_load_phdr.p_paddr == 0){
            printf("Unable to get PT_LOAD segment, must wrong\n");
            return;
        }
        printf("Add PHDR pt_load: vaddr:%16lx\tfile_offset:%16lx\n",(long)phdr_pt_load_phdr.p_paddr,(long)phdr_pt_load_phdr.p_offset);
        _add_segment_desc(elf_file_base,&phdr_pt_load_phdr);
        for(int i=0;i<ehdr->e_phnum;i++){
            Elf_Phdr* phdr_self_phdr = (Elf_Phdr*)(elf_file_base + ehdr->e_phoff + ehdr->e_phentsize*i);
            if(phdr_self_phdr->p_type == PT_PHDR){
                phdr_self_phdr->p_align = 0x1000;
                phdr_self_phdr->p_filesz = 0x1000;
                phdr_self_phdr->p_flags = PF_R | PF_X;
                phdr_self_phdr->p_memsz = 0x1000;
                phdr_self_phdr->p_offset = get_file_size(elf_file)-0x1000;
                phdr_self_phdr->p_paddr = first_pt_load_phdr->p_paddr + get_file_size(elf_file)-0x1000;
                phdr_self_phdr->p_vaddr = first_pt_load_phdr->p_paddr + get_file_size(elf_file)-0x1000;
                break;
            }
        }
        close_and_munmap(elf_file,elf_file_fd,elf_file_base,&elf_file_size);
    }
}

void check_so_file_no_rela_section(Elf_Ehdr* ehdr){
    for(int i=0;i<ehdr->e_phnum;i++) {
        Elf_Phdr *so_phdr = (Elf_Phdr *) ((long)ehdr + ehdr->e_phoff + i * ehdr->e_phentsize);
        if (so_phdr->p_type == PT_DYNAMIC) {
            Elf_Dyn* dyn = (Elf_Dyn*)((long)ehdr + so_phdr->p_offset);
            while (dyn->d_tag!=0){
                if(dyn->d_tag == DT_PLTGOT) {
                    printf("so file check error, should not have DT_PLTGOT\n");
                    exit(-1);
                }
                else if(dyn->d_tag == DT_RELA || dyn->d_tag == DT_REL){
                    printf("so file check error, should not have DT_RELA or DT_REL");
                    exit(-1);
                }
                else {
                    //printf("DT_TYPE: %8d\tDT_VALUE=%8d\n",dyn->d_tag,dyn->d_un.d_ptr);
                    dyn = (Elf_Dyn *) ((long) dyn + sizeof(Elf_Dyn));
                }
            }
        }
    }
}

void check_so_file_no_dynsym_section(Elf_Ehdr* ehdr){
    Elf_Shdr * shdr = get_elf_section_by_name(".dynsym",ehdr);
    if(shdr!=NULL){
        printf("check_so_file_no_dynsym_section failed");
        exit(-1);
    }
}


void check_so_file_no_rodata_section(Elf_Ehdr* ehdr){
    Elf_Shdr * shdr = get_elf_section_by_name(".rodata",ehdr);
    if(shdr!=NULL){
        printf("check_so_file_no_rodata_section failed");
        exit(-1);
    }
}

void check_so_file_no_data_section(Elf_Ehdr* ehdr){
    Elf_Shdr * shdr = get_elf_section_by_name(".data",ehdr);
    if(shdr!=NULL){
        printf("check_so_file_no_data_section failed");
        exit(-1);
    }
}

void check_so_file_no_got_section(Elf_Ehdr *ehdr){
    Elf_Shdr * shdr = get_elf_section_by_name(".got",ehdr);
    if(shdr!=NULL){
        printf("check_so_file_no_got_section failed");
        exit(-1);
    }
}

void check_so_file_no_gotplt_section(Elf_Ehdr *ehdr){
    Elf_Shdr * shdr = get_elf_section_by_name(".gotplt",ehdr);
    if(shdr!=NULL){
        printf("check_so_file_no_gotplt_section failed");
        exit(-1);
    }
}

void check_so_file_no_plt_section(Elf_Ehdr *ehdr){
    Elf_Shdr * shdr = get_elf_section_by_name(".plt",ehdr);
    if(shdr!=NULL){
        printf("check_so_file_no_plt_section failed");
        exit(-1);
    }
}

void check_so_file_no_bss_section(Elf_Ehdr *ehdr){
    Elf_Shdr * shdr = get_elf_section_by_name(".bss",ehdr);
    if(shdr!=NULL){
        printf("check_so_file_no_bss_section failed");
        exit(-1);
    }
}

void check_libloader_stage_three(char* libloader_stage_three){
    int libloader_stage_threefd;
    char* libloader_stage_three_base;
    long libloader_stage_three_size = 0;
    open_mmap_check(libloader_stage_three,O_RDONLY,&libloader_stage_threefd,(void**)&libloader_stage_three_base,PROT_READ,MAP_PRIVATE,&libloader_stage_three_size);
    check_so_file_no_rela_section((Elf_Ehdr*)libloader_stage_three_base);
    close_and_munmap(libloader_stage_three,libloader_stage_threefd,libloader_stage_three_base,&libloader_stage_three_size);
}

void check_libloader_stage_two(char* libloader_stage_two){
    int libloader_stage_twofd;
    char* libloader_stage_two_base;
    long libloader_stage_two_size = 0;
    open_mmap_check(libloader_stage_two,O_RDONLY,&libloader_stage_twofd,(void**)&libloader_stage_two_base,PROT_READ,MAP_PRIVATE,&libloader_stage_two_size);
    printf("check %s\n",libloader_stage_two);
    check_so_file_no_rela_section    ((Elf_Ehdr*)libloader_stage_two_base);
    //check_so_file_no_dynsym_section  ((Elf_Ehdr*)libloader_stage_two_base);
    check_so_file_no_rodata_section  ((Elf_Ehdr*)libloader_stage_two_base);
    check_so_file_no_data_section    ((Elf_Ehdr*)libloader_stage_two_base);
    check_so_file_no_got_section     ((Elf_Ehdr*)libloader_stage_two_base);
    check_so_file_no_gotplt_section  ((Elf_Ehdr*)libloader_stage_two_base);
    check_so_file_no_plt_section     ((Elf_Ehdr*)libloader_stage_two_base);
    check_so_file_no_bss_section     ((Elf_Ehdr*)libloader_stage_two_base);
    close_and_munmap(libloader_stage_two,libloader_stage_twofd,libloader_stage_two_base,&libloader_stage_two_size);
}

void check_libloader_stage_one(char* libloader_stage_one){
    int libloader_stage_onefd;
    char* libloader_stage_one_base;
    long libloader_stage_one_size = 0;
    open_mmap_check(libloader_stage_one,O_RDONLY,&libloader_stage_onefd,(void**)&libloader_stage_one_base,PROT_READ,MAP_PRIVATE,&libloader_stage_one_size);
    printf("check %s\n",libloader_stage_one);
    check_so_file_no_rela_section    ((Elf_Ehdr*)libloader_stage_one_base);
    //check_so_file_no_dynsym_section  ((Elf_Ehdr*)libloader_stage_one_base);
    check_so_file_no_rodata_section  ((Elf_Ehdr*)libloader_stage_one_base);
    check_so_file_no_data_section    ((Elf_Ehdr*)libloader_stage_one_base);
    check_so_file_no_got_section     ((Elf_Ehdr*)libloader_stage_one_base);
    check_so_file_no_gotplt_section  ((Elf_Ehdr*)libloader_stage_one_base);
    check_so_file_no_plt_section     ((Elf_Ehdr*)libloader_stage_one_base);
    check_so_file_no_bss_section     ((Elf_Ehdr*)libloader_stage_one_base);
    close_and_munmap(libloader_stage_one,libloader_stage_onefd,libloader_stage_one_base,&libloader_stage_one_size);
}

void generate_data_file(void* elf_load_base,char* output_elf,char* libloader_stage_two,char* libloader_stage_three,int first_entry_offset,char* shell_passwd,char* analysis_server_ip,char* analysis_server_port,char* sandbox_server_ip,char* sandbox_server_port,char* target){
    char* libloader_stage_two_buf;
    int libloader_stage_two_len;
    int libloader_stage_two_fd;
    char* libloader_stage_two_base;
    check_libloader_stage_two(libloader_stage_two);
    long libloader_stage_two_size = 0;
    open_mmap_check(libloader_stage_two,O_RDONLY,&libloader_stage_two_fd,(void**)&libloader_stage_two_base,PROT_READ,MAP_PRIVATE,&libloader_stage_two_size);
    get_section_data((Elf_Ehdr*)libloader_stage_two_base,".rodata",(void**)&libloader_stage_two_buf,&libloader_stage_two_len);
    if(libloader_stage_two_buf!=NULL || libloader_stage_two_len!=0){
        printf("libloader_stage_two should not have rodata section, change compile flags:\n");
        exit(-1);
    }
    get_section_data((Elf_Ehdr*)libloader_stage_two_base,".text",(void**)&libloader_stage_two_buf,&libloader_stage_two_len);
    if(libloader_stage_two_buf==NULL || libloader_stage_two_len==0){
        printf("libloader_stage_two should have text section, but we can not find it:\n");
        exit(-1);
    }
    Elf_Shdr* libloader_stage_two_text_section = get_elf_section_by_name(".text",(Elf_Ehdr*)libloader_stage_two_base);
    int target_fd = open(target,O_RDWR|O_TRUNC|O_CREAT);
    LOADER_STAGE_TWO two;
    memset(&two,0,sizeof(LOADER_STAGE_TWO));
    two.length = libloader_stage_two_len;
    two.entry_offset = ((Elf_Ehdr*)libloader_stage_two_base)->e_entry - libloader_stage_two_text_section->sh_addr;
    write(target_fd,&two,sizeof(LOADER_STAGE_TWO));
    write(target_fd,libloader_stage_two_buf,libloader_stage_two_len);
    printf("libloader_stage_two TLV structure values:\n");
    printf("\tlength:                     0x%lx\n",two.length);
    printf("\tentry_offset:               0x%lx\n",two.entry_offset);

    LOADER_STAGE_THREE three;
    memset(&three,0,sizeof(LOADER_STAGE_THREE));
    MD5_CTX md5;
    MD5Init(&md5);
    MD5Update(&md5,shell_passwd,strlen(shell_passwd));
    MD5Final(&md5,three.shell_password);


    three.entry_offset = (int)((Elf_Ehdr*)(get_file_content_length(libloader_stage_three,0,sizeof(Elf_Ehdr))))->e_entry;
    three.length = get_file_size(libloader_stage_three);
    three.patch_data_mmap_code_base = (void*)UP_PADDING((char*)elf_load_base+get_file_size(output_elf)+0x10000000,0x1000);
    three.first_entry_offset = first_entry_offset;

    if(analysis_server_ip!=NULL && analysis_server_port!=NULL) {
        inet_aton(analysis_server_ip, &three.analysis_server.sin_addr);
        three.analysis_server.sin_port = htons(atoi(analysis_server_port));
        three.analysis_server.sin_family = AF_INET;
    }

    if(sandbox_server_ip!=NULL && sandbox_server_port!=NULL) {
        inet_aton(sandbox_server_ip, &three.sandbox_server.sin_addr);
        three.sandbox_server.sin_port = htons(atoi(sandbox_server_port));
        three.sandbox_server.sin_family = AF_INET;
    }
    printf("libloader_stage_three TLV structure values:\n");
    printf("\tentry_offset:                     0x%lx\n",three.entry_offset);
    printf("\tlength:                           0x%lx\n",three.length);
    printf("\tfirst_entry_offset:               0x%lx\n",three.first_entry_offset);
    printf("\tanalysis_server_ip:               %s\n",inet_ntoa(three.analysis_server.sin_addr));
    printf("\tanalysis_server_port:             %d\n",htons(three.analysis_server.sin_port));
    printf("\tsandbox_server_ip:                %s\n",inet_ntoa(three.sandbox_server.sin_addr));
    printf("\tsandbox_server_port:              %d\n",htons(three.sandbox_server.sin_port));
    check_libloader_stage_three(libloader_stage_three);
    write(target_fd,&three,sizeof(LOADER_STAGE_THREE));
    char* libloader_stage_three_content = get_file_content(libloader_stage_three);
    write(target_fd,libloader_stage_three_content,get_file_size(libloader_stage_three));
    close_and_munmap(libloader_stage_two,libloader_stage_two_fd,libloader_stage_two_base,&libloader_stage_two_size);
}


void add_content_to_elf_pt_load(char* output_elf,char* content,int length){
    int output_file_size = get_file_size(output_elf);
    if(output_file_size%0x1000!=0){
        output_file_size = UP_PADDING(output_file_size,0x1000);
        increase_file(output_elf,output_file_size);
    }
    increase_file(output_elf,UP_PADDING(output_file_size+length,0x1000));
    unsigned long output_elf_load_base = get_elf_file_load_base(output_elf);
    Elf_Phdr mem_pt_load;
    memset(&mem_pt_load,0,sizeof(Elf_Phdr));
    mem_pt_load.p_type = PT_LOAD;
    mem_pt_load.p_align = 0x1000;
    mem_pt_load.p_filesz = length;
    mem_pt_load.p_flags = PF_R | PF_X | PF_W;
    mem_pt_load.p_memsz = length;
    mem_pt_load.p_offset = output_file_size;
    mem_pt_load.p_vaddr = output_elf_load_base+output_file_size;
    mem_pt_load.p_paddr = output_elf_load_base+output_file_size;
    add_segment(output_elf,&mem_pt_load);
    int output_elf_fd;
    char* output_elf_base;
    long output_elf_size = 0;
    open_mmap_check(output_elf,O_RDWR,&output_elf_fd,(void**)&output_elf_base,PROT_READ|PROT_WRITE,MAP_SHARED,&output_elf_size);
    memcpy((char*)output_elf_base+output_file_size,content,length);
    close_and_munmap(output_elf,output_elf_fd,output_elf_base,&output_elf_size);
}

void add_file_content_to_elf_pt_load(char* output_elf,char* file_name){
    char* content = get_file_content(file_name);
    add_content_to_elf_pt_load(output_elf,content,get_file_size(file_name));
    free(content);
}


//loader_stage_one_position has two values:
//one is em_frame , means add first stage code to em_frame section, you must insure the em_frame is not use and has enough space(usual 300 byte is enough)
//tow is new_pt_load, means we need add a pt_load segment to the elf file, which will increase target file size

//loader_stage_other_position has four values:
//1. file, means load data from file, loader_stage_other_path us use
//2. memory, means data already load to memory, loader_stage_other_mem_addr is use
//3. share_memory, means we can get data from share_memory, loader_stage_other_share_memory_id is use
//4. socket, means we can get data from tcp socket server,

//current we do not look for libc_start_main addr from elf manual, we must special it manual


void usage(char* local){
    printf("usage:\n\t%s 1\t\t:mean stage one\n\t%s 2\t\t:mean stage two\n",local,local);
    exit(-1);
}

int main(int argc,char* argv[]){
    if(argc!=2){
        usage(argv[0]);
    }
    int stage = atoi(argv[1]);
    if(stage!=1 && stage!=2) {
        printf("argument is error, stage: %d\n",stage);
        usage(argv[0]);
    }
    chdir("/tmp");
    char config_file_name[] = {"BBBBBBBBBB"};
    printf("config file: %s\n",config_file_name);
    cJSON* config = cJSON_Parse(get_file_content(config_file_name));
    if(config == NULL){
        printf("%s parse failed\n",config_file_name);
        exit(-1);
    }
    char* config_h = cJSON_GetObjectItem(config,"config.h")->valuestring;
    printf("config.h: %s\n",config_h);
    char* libloader_stage_one = cJSON_GetObjectItem(config,"libloader_stage_one")->valuestring;
    printf("libloader_stage_one: %s\n",libloader_stage_one);
    char* libloader_stage_two = cJSON_GetObjectItem(config,"libloader_stage_two")->valuestring;
    printf("libloader_stage_two: %s\n",libloader_stage_two);
    char* libloader_stage_three = cJSON_GetObjectItem(config,"libloader_stage_three")->valuestring;
    printf("libloader_stage_three: %s\n",libloader_stage_three);

    char* input_elf = cJSON_GetObjectItem(config,"input_elf")->valuestring;
    printf("input_elf: %s\n",input_elf);
    char* output_elf = cJSON_GetObjectItem(config,"output_elf")->valuestring;
    printf("output_elf: %s\n",output_elf);
    copy_file(input_elf,output_elf);
    int config_file_fd = open(config_h,O_RDWR|O_TRUNC|O_CREAT);

    void* elf_load_base = NULL;

    // PIE macro
    {
        Elf_Ehdr* ehdr = (Elf_Ehdr*)get_file_content_length(output_elf,0,sizeof(Elf_Ehdr));
        switch(ehdr->e_type){
            case ET_DYN:
            case ET_REL:
                write_marco_define(config_file_fd,"IS_PIE","1");
                break;
            case ET_EXEC:
                write_marco_define(config_file_fd,"IS_PIE","0");
                break;
            default:
                printf("unknown object type: %d\n",ehdr->e_type);
                exit(-1);
        }
    }
    //LIB_C_START_MAIN_ADDR
    {
        char* libc_start_main_addr_type = cJSON_GetObjectItem(config,"libc_start_main_addr_type")->valuestring;
        if(strcmp(libc_start_main_addr_type,"code")==0)
            write_marco_define(config_file_fd,"LIBC_START_MAIN_ADDR_TYPE","CODE");
        else if(strcmp(libc_start_main_addr_type,"ptr")==0){
            write_marco_define(config_file_fd,"LIBC_START_MAIN_ADDR_TYPE","PTR");
        }
        else{
            printf("libc_start_main_addr_type has only two values, one is code, another is ptr\n");
            exit(-1);
        }
        char* libc_start_main_addr = cJSON_GetObjectItem(config,"libc_start_main_addr")->valuestring;
        write_marco_define(config_file_fd,"LIB_C_START_MAIN_ADDR",libc_start_main_addr);
    }

    int first_entry_offset = 0;
    char* loader_stage_one_position = cJSON_GetObjectItem(config,"loader_stage_one_position")->valuestring;
    if(stage == 2){
        //process stage one
        check_libloader_stage_one(libloader_stage_one);
        if (strcmp("em_frame", loader_stage_one_position) == 0) {
            add_stage_one_code_to_em_frame(libloader_stage_one, output_elf, &first_entry_offset,&elf_load_base,config);
        } else if (strcmp("new_pt_load", loader_stage_one_position) == 0) {
            mov_phdr(output_elf);
            add_stage_one_code_to_new_pt_load(libloader_stage_one, output_elf, &first_entry_offset,&elf_load_base,config);
        } else {
            printf("unsupport loader_stage_one_position: %s\n", loader_stage_one_position);
            exit(-1);
        }
    }

    {
        char buf[256];
        snprintf(buf,255,"0x%lx",first_entry_offset);
        write_marco_define(config_file_fd, "FIRST_ENTRY_OFFSET", buf);
    }

    char* data_file_path = cJSON_GetObjectItem(config,"data_file_path")->valuestring;
    {
//TCP_TIME_OUT
//REDIRECT_HOST
//REDIRECT_PORT
//SHELL_PASSWD
//USE_IO_INLINE_REDIRECT
//USE_LOCAL_FILE_INSTEAD_OF_UDP
//IO_REDIRECT_PATH
//PATCH_DEBUG
        char* tcp_time_out = cJSON_GetObjectItem(config,"tcp_time_out")->valuestring;
        write_marco_define(config_file_fd,"TCP_TIME_OUT",tcp_time_out);

        char* analysis_server_ip = cJSON_GetObjectItem(config,"analysis_server_ip")->valuestring;
        write_marco_str_define(config_file_fd,"REDIRECT_HOST",analysis_server_ip);

        char* analysis_server_port = cJSON_GetObjectItem(config,"analysis_server_port")->valuestring;
        write_marco_define(config_file_fd,"REDIRECT_PORT",analysis_server_port);

        char* shell_password = cJSON_GetObjectItem(config,"shell_password")->valuestring;
        write_marco_str_define(config_file_fd,"SHELL_PASSWD",shell_password);

        char* io_inline_hook = cJSON_GetObjectItem(config,"io_inline_hook")->valuestring;
        write_marco_define(config_file_fd,"USE_IO_INLINE_REDIRECT",io_inline_hook);

        char* local_file_instead_of_udp = cJSON_GetObjectItem(config,"local_file_instead_of_udp")->valuestring;
        write_marco_define(config_file_fd,"USE_LOCAL_FILE_INSTEAD_OF_UDP",local_file_instead_of_udp);

        char* io_local_save_path = cJSON_GetObjectItem(config,"io_local_save_path")->valuestring;
        write_marco_str_define(config_file_fd,"IO_REDIRECT_PATH",io_local_save_path);

        char* debug = cJSON_GetObjectItem(config,"debug")->valuestring;
        write_marco_define(config_file_fd,"PATCH_DEBUG",debug);

        if(stage == 2)
            generate_data_file(elf_load_base,output_elf,libloader_stage_two,libloader_stage_three,first_entry_offset,shell_password,analysis_server_ip,analysis_server_port,NULL,NULL,data_file_path);

    }


    char* loader_stage_other_position = cJSON_GetObjectItem(config,"loader_stage_other_position")->valuestring;
    if(strcmp("file",loader_stage_other_position)==0){
        write_marco_define(config_file_fd,"CONFIG_LOADER_TYPE","LOAD_FROM_FILE");
        char* loader_stage_other_file_path = cJSON_GetObjectItem(config,"loader_stage_other_file_path")->valuestring;
        write_marco_str_define(config_file_fd,"PATCH_DATA_PATH",loader_stage_other_file_path);
        if(stage == 2) {
            char tmp_buf[256];
            snprintf(tmp_buf, 255, "0x%lx", UP_PADDING(((char *) elf_load_base + get_file_size(output_elf)), 0x1000));
            snprintf(tmp_buf, 255, "0x%lx", get_file_size(data_file_path));
            write_marco_define(config_file_fd, "PATCH_DATA_MMAP_FILE_SIZE", tmp_buf);
        }
        else if(stage == 1){
            write_marco_define(config_file_fd, "PATCH_DATA_MMAP_FILE_SIZE", "0");
        }
    }
    else if(strcmp("memory",loader_stage_other_position)==0){
        if(strcmp(loader_stage_one_position,"new_pt_load")!=0){
            printf("when loader_stage_other_position is [memory],loader_stage_one_position must be [new_pt_load]");
            exit(-1);
        }
        write_marco_define(config_file_fd,"CONFIG_LOADER_TYPE","LOAD_FROM_MEM");
        if(stage == 2){
            char tmp_buf[256];
            snprintf(tmp_buf, 255, "0x%lx", get_file_size(data_file_path));
            write_marco_define(config_file_fd, "PATCH_DATA_MMAP_FILE_SIZE", tmp_buf);
            add_file_content_to_elf_pt_load(output_elf,data_file_path);
        }
        else if (stage == 1){
            write_marco_define(config_file_fd, "PATCH_DATA_MMAP_FILE_SIZE", "0");
        }
    }
    else if(strcmp("share_memory",loader_stage_other_position)==0){
        printf("not implement,exit!!!");
        exit(-1);
        write_marco_define(config_file_fd,"CONFIG_LOADER_TYPE","LOAD_FROM_SHARE_MEM");
        char* loader_stage_other_share_memory_id = cJSON_GetObjectItem(config,"loader_stage_other_share_memory_id")->valuestring;
        write_marco_define(config_file_fd,"PATCH_DATA_SHARE_MEM_ID",loader_stage_other_share_memory_id);
    }
    else if(strcmp("socket",loader_stage_other_position)==0){
        printf("not implement,exit!!!");
        exit(-1);
        write_marco_define(config_file_fd,"CONFIG_LOADER_TYPE","LOAD_FROM_SOCKET");
        char* loader_stage_other_socket_server_ip = cJSON_GetObjectItem(config,"loader_stage_other_socket_server_ip")->valuestring;
        char* loader_stage_other_socket_server_port = cJSON_GetObjectItem(config,"loader_stage_other_socket_server_port")->valuestring;
        write_marco_str_define(config_file_fd,"PATCH_DATA_SOCKET_SERVER_IP",loader_stage_other_socket_server_ip);
        write_marco_define(config_file_fd,"PATCH_DATA_SOCKET_SERVER_PORT",loader_stage_other_socket_server_port);
    }
    else{
        printf("unsupport loader_stage_other_position: %s\n",loader_stage_other_position);
        exit(-1);
    }
    close(config_file_fd);
}