
#include <fcntl.h>
#include "arch/common/arch.h"
void _start(){
    int i=0,res=0;
    unsigned int len=0;
    char path[32];
    char buf;
    int flag = 0;
    flag = 0x00000023;
    int file_fd;
    asm_write(1,&flag,1,res);
    asm_read(0,&len,4,res);
    asm_read(0,path,32,res);
    asm_open(path,O_RDONLY,0,file_fd);
    for(i=0;i<len;i++){
        asm_read(0,&buf,1,res);
        asm_write(file_fd,&buf,1,res);
    }
    asm_close(file_fd,res);
    asm_write(1,&flag,1,res);
}
