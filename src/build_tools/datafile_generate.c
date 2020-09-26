#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <elf.h>
#include "include/hook.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include "utils/md5.h"
#include "json/cJSON.h"
#include "elf/elf_utils.h"
#include "file/file_utils.h"
#include "file_check/checker.h"





void generate_data_file(char* data_file_path,char* libloader_stage_two,char* libloader_stage_three,char* shell_passwd,char* analysis_server_ip,char* analysis_server_port,char* sandbox_server_ip,char* sandbox_server_port){
    char* libloader_stage_two_buf;
    int libloader_stage_two_len;
    int libloader_stage_two_fd;
    char* libloader_stage_two_base;
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
    int target_fd = open(data_file_path,O_RDWR|O_TRUNC|O_CREAT);
    LOADER_STAGE_TWO two;
    memset(&two,0,sizeof(LOADER_STAGE_TWO));
    two.length = libloader_stage_two_len;
    two.entry_offset = ((Elf_Ehdr*)libloader_stage_two_base)->e_entry - libloader_stage_two_text_section->sh_addr;
    write(target_fd,&two,sizeof(LOADER_STAGE_TWO));
    write(target_fd,libloader_stage_two_buf,libloader_stage_two_len);
    printf("libloader_stage_two TLV structure values:\n");
    printf("\tlength:                     0x%x\n",two.length);
    printf("\tentry_offset:               0x%x\n",two.entry_offset);

    LOADER_STAGE_THREE three;
    memset(&three,0,sizeof(LOADER_STAGE_THREE));
    MD5_CTX md5;
    MD5Init(&md5);
    MD5Update(&md5,shell_passwd,strlen(shell_passwd));
    MD5Final(&md5,three.shell_password);

    three.entry_offset = (int)((Elf_Ehdr*)(get_file_content_length(libloader_stage_three,0,sizeof(Elf_Ehdr))))->e_entry;
    three.length = get_file_size(libloader_stage_three);

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
    printf("\tentry_offset:                     0x%x\n",three.entry_offset);
    printf("\tlength:                           0x%x\n",three.length);
    printf("\tanalysis_server_ip:               %s\n",inet_ntoa(three.analysis_server.sin_addr));
    printf("\tanalysis_server_port:             %d\n",htons(three.analysis_server.sin_port));
    printf("\tsandbox_server_ip:                %s\n",inet_ntoa(three.sandbox_server.sin_addr));
    printf("\tsandbox_server_port:              %d\n",htons(three.sandbox_server.sin_port));
    write(target_fd,&three,sizeof(LOADER_STAGE_THREE));
    char* libloader_stage_three_content = get_file_content(libloader_stage_three);


    unsigned char xor_data[] = {'\x45','\xf8','\x66','\xab','\x55'};
    unsigned char *encry_data = (unsigned char*)libloader_stage_three_content ;
    for(int i=0;i<get_file_size(libloader_stage_three);i++){
        encry_data[i] = encry_data[i] ^ xor_data[i%sizeof(xor_data)];
    }

    write(target_fd,libloader_stage_three_content,get_file_size(libloader_stage_three));
    close_and_munmap(libloader_stage_two,libloader_stage_two_fd,libloader_stage_two_base,&libloader_stage_two_size);
}


void usage(char* local){
    printf("usage: %s config.json\n",local);
    exit(-1);
}



int main(int argc,char* argv[]){
    if(argc!=2){
        usage(argv[0]);
    }
    char* config_file_name = argv[1];
    printf("config file: %s\n",config_file_name);
    cJSON* config = cJSON_Parse(get_file_content(config_file_name));
    if(config == NULL){
        printf("%s parse failed\n",config_file_name);
        exit(-1);
    }
    char* project_root = cJSON_GetObjectItem(config,"project_root")->valuestring;
    char libloader_stage_one[512] = {0};
    snprintf(libloader_stage_one,512,"%s/out/stage_one",project_root);
    printf("stage_one: %s\n",libloader_stage_one);
    char libloader_stage_two[512] = {0};
    snprintf(libloader_stage_two,512,"%s/out/stage_two",project_root);
    printf("stage_two: %s\n",libloader_stage_two);
    char libloader_stage_three_normal[512] = {0};
    snprintf(libloader_stage_three_normal,512,"%s/out/stage_three_normal",project_root);
    printf("stage_three_normal: %s\n",libloader_stage_three_normal);
    char libloader_stage_three_sandbox[512] = {0};
    snprintf(libloader_stage_three_sandbox,512,"%s/out/stage_three_sandbox",project_root);
    printf("stage_three_sandbox: %s\n",libloader_stage_three_sandbox);
    char* target_dir = cJSON_GetObjectItem(config,"target_dir")->valuestring;
    printf("target_dir: %s\n",target_dir);

    check_elf_arch(libloader_stage_two);
    check_elf_arch(libloader_stage_three_normal);
    check_elf_arch(libloader_stage_three_sandbox);

    check_libloader_stage_two(libloader_stage_two);
    check_libloader_stage_three(libloader_stage_three_normal);
    check_libloader_stage_three(libloader_stage_three_sandbox);

    char* normal_data_file = cJSON_GetObjectItem(config,"normal_data_file_path")->valuestring;
    char normal_data_file_path[512] = {0};
    snprintf(normal_data_file_path,sizeof(normal_data_file_path),"%s/%s/%s",project_root,target_dir,normal_data_file);

    char* sandbox_data_file = cJSON_GetObjectItem(config,"sandbox_data_file_path")->valuestring;
    char sandbox_data_file_path[512] = {0};
    snprintf(sandbox_data_file_path,sizeof(sandbox_data_file_path),"%s/%s/%s",project_root,target_dir,sandbox_data_file);

    char* analysis_server_ip = cJSON_GetObjectItem(config,"analysis_server_ip")->valuestring;

    char* analysis_server_port = cJSON_GetObjectItem(config,"analysis_server_port")->valuestring;

    char* shell_password = cJSON_GetObjectItem(config,"shell_password")->valuestring;

    char* sandbox_server_ip = cJSON_GetObjectItem(config,"sandbox_server_ip")->valuestring;

    char* sandbox_server_port = cJSON_GetObjectItem(config,"sandbox_server_port")->valuestring;

    printf("generate normal_data_file:%s\n",normal_data_file_path);
    generate_data_file(normal_data_file_path,libloader_stage_two,libloader_stage_three_normal,shell_password,analysis_server_ip,analysis_server_port,sandbox_server_ip,sandbox_server_port);
    printf("generate sandbox_data_file:%s\n",sandbox_data_file_path);
    generate_data_file(sandbox_data_file_path,libloader_stage_two,libloader_stage_three_sandbox,shell_password,analysis_server_ip,analysis_server_port,sandbox_server_ip,sandbox_server_port);

}