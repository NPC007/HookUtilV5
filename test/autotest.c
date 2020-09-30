#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

int test_hook_got(){
    puts("test_hook_got normal\n");
    free(malloc(100));
    return 0;
}

int test_hook_elf_addr(){
    printf("test_hook_elf_addr\n");
    return 0;
}

int test_hook_elf_sym(){
    printf("test_hook_elf_sym\n");
    return 0;
}
int test_hook_call_addr(){
    system("id");
    return 0;
}
int test_hook_part_start_end(){
    int a = 111;
    int b = 222;
    int c = a + b;
    puts("test_hook_part_start_end start");
    printf("test_hook_part_start_end %d\n",c);
    return 0;
}

void banner(){
    printf("1 : malloc \n");
    printf("2 : free \n");
    printf("3 : exit \n");
}
int read_int(){
    char buf[8] = {0};
    int ret = -1;
    while(ret==-1) {
        ret = read(0, buf, 2);
    }
    for(int i=0;i<8;i++){
        if(buf[i] == '\n')
            buf[i] = 0;
    }
    return atoi(buf);
}

int main(int argc,char** argv){
    test_hook_got();
    test_hook_elf_addr();
    test_hook_elf_sym();
    test_hook_call_addr();
    test_hook_part_start_end();
    char* buf = NULL;
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
    while(1){
        banner();
        int choice = read_int();
        switch (choice){
            case 1:
                if(buf!=NULL) {
                    free(buf);
                    buf = NULL;
                }
                buf = malloc(8);
                printf("alloc 8 bytes\n");
                break;
            case 2:
                if(buf!=NULL) {
                    free(buf);
                    buf = NULL;
                    printf("free buf\n");
                }
                break;
            case 3:
                buf = malloc(8);
                puts("alloc 8 bytes\n");
                puts("bye");
                fflush(stdout);
                //sleep(2);
                exit(0);
        }
    }
    return 0;
}