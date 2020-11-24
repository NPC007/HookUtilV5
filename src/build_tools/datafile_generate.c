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



void generate_stage_two_parameter(char* elf_path,char* data_file_path){
    int data_file_fd;
    char* data_file_fd_base;
    long data_file_size;
    open_mmap_check(data_file_path,O_RDWR,&data_file_fd,(void**)&data_file_fd_base,PROT_READ|PROT_WRITE,MAP_SHARED,&data_file_size);
    LOADER_STAGE_TWO* two = (LOADER_STAGE_TWO*)data_file_fd_base;
    two->patch_data_length =  data_file_size;
    two->elf_load_base = (void*)get_elf_file_load_base(elf_path);
    close_and_munmap(data_file_path,data_file_fd,data_file_fd_base,&data_file_size);
}



void generate_data_file(char* data_file_path,char* libloader_stage_two,char* libloader_stage_three,char* shell_passwd,char* analysis_server_ip,char* analysis_server_port,char* sandbox_server_ip,char* sandbox_server_port){
    char* libloader_stage_two_buf;
    int libloader_stage_two_len;
    int libloader_stage_two_fd;
    char* libloader_stage_two_base;
    long libloader_stage_two_size = 0;
    open_mmap_check(libloader_stage_two,O_RDONLY,&libloader_stage_two_fd,(void**)&libloader_stage_two_base,PROT_READ,MAP_PRIVATE,&libloader_stage_two_size);
    get_section_data((Elf_Ehdr*)libloader_stage_two_base,".rodata",(void**)&libloader_stage_two_buf,&libloader_stage_two_len);
    if(libloader_stage_two_buf!=NULL || libloader_stage_two_len!=0){
        logger("libloader_stage_two should not have rodata section, change compile flags:\n");
        exit(-1);
    }
    get_section_data((Elf_Ehdr*)libloader_stage_two_base,".text",(void**)&libloader_stage_two_buf,&libloader_stage_two_len);
    if(libloader_stage_two_buf==NULL || libloader_stage_two_len==0){
        logger("libloader_stage_two should have text section, but we can not find it:\n");
        exit(-1);
    }
    Elf_Shdr* libloader_stage_two_text_section = get_elf_section_by_name(".text",(Elf_Ehdr*)libloader_stage_two_base);
    int target_fd = open(data_file_path,O_RDWR|O_TRUNC|O_CREAT,0777);
    LOADER_STAGE_TWO two;
    memset(&two,0,sizeof(LOADER_STAGE_TWO));
    two.length = libloader_stage_two_len;
    two.entry_offset = ((Elf_Ehdr*)libloader_stage_two_base)->e_entry - libloader_stage_two_text_section->sh_addr;
    if(two.entry_offset!=0){
        logger("stage two elf error: _start not in first text bytesm we need it to be first bytes to decrease stage_one bytes\n");
        exit(255);
    }
    write(target_fd,&two,sizeof(LOADER_STAGE_TWO));
    write(target_fd,libloader_stage_two_buf,libloader_stage_two_len);
    logger("libloader_stage_two TLV structure values:\n");
    logger("\tlength:                     0x%x\n",two.length);
    logger("\tentry_offset:               0x%x\n",two.entry_offset);

    LOADER_STAGE_THREE three;
    memset(&three,0,sizeof(LOADER_STAGE_THREE));
    if(shell_passwd!=NULL) {
        MD5_CTX md5;
        MD5Init(&md5);
        MD5Update(&md5, shell_passwd, strlen(shell_passwd));
        MD5Final(&md5, three.shell_password);
    }

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
    logger("libloader_stage_three TLV structure values:\n");
    logger("\tentry_offset:                     0x%x\n",three.entry_offset);
    logger("\tlength:                           0x%x\n",three.length);
    logger("\tanalysis_server_ip:               %s\n",inet_ntoa(three.analysis_server.sin_addr));
    logger("\tanalysis_server_port:             %d\n",htons(three.analysis_server.sin_port));
    logger("\tsandbox_server_ip:                %s\n",inet_ntoa(three.sandbox_server.sin_addr));
    logger("\tsandbox_server_port:              %d\n",htons(three.sandbox_server.sin_port));
    write(target_fd,&three,sizeof(LOADER_STAGE_THREE));
    char* libloader_stage_three_content = get_file_content(libloader_stage_three);


    unsigned char xor_data[] = {'\x45','\xf8','\x66','\xab','\x55'};
    unsigned char *encry_data = (unsigned char*)libloader_stage_three_content ;
    for(int i=0;i<get_file_size(libloader_stage_three);i++){
        encry_data[i] = encry_data[i] ^ xor_data[i%sizeof(xor_data)];
    }

    write(target_fd,libloader_stage_three_content,get_file_size(libloader_stage_three));
    close_and_munmap(libloader_stage_two,libloader_stage_two_fd,libloader_stage_two_base,&libloader_stage_two_size);
    char command[512] = {0};
    snprintf(command,sizeof(command),"chmod 660 %s ",data_file_path);
    system(command);
}


void usage(char* local){
    logger("usage: %s config.json\n",local);
    logger("     : mode is: normal, sandbox\n");
    exit(-1);
}



int main(int argc,char* argv[]){
    if(argc!=3){
        usage(argv[0]);
    }
    char* mode = argv[2];
    if(strcmp(mode,"normal")!= 0 && strcmp(mode,"sandbox")!=0)
        usage(argv[0]);
    char* config_file_name = argv[1];
    logger("config file: %s\n",config_file_name);
    cJSON* config = cJSON_Parse(get_file_content(config_file_name));
    if(config == NULL){
        logger("%s parse failed\n",config_file_name);
        exit(-1);
    }

    char* project_root = cJSON_GetObjectItem(config,"project_root")->valuestring;
    char logger_file[512] = {0};
    snprintf(logger_file,sizeof(logger_file),"%s/out/build.log",project_root);
    init_logger(logger_file,0);
    logger("MODE : %s\n",mode);
    char libloader_stage_one[512] = {0};
    snprintf(libloader_stage_one,512,"%s/out/%s/stage_one",project_root,mode);
    logger("stage_one: %s\n",libloader_stage_one);
    char libloader_stage_two[512] = {0};
    snprintf(libloader_stage_two,512,"%s/out/%s/stage_two",project_root,mode);
    logger("stage_two: %s\n",libloader_stage_two);
    char libloader_stage_three[512] = {0};
    snprintf(libloader_stage_three,512,"%s/out/%s/stage_three",project_root,mode);
    logger("stage_three: %s\n",libloader_stage_three);
    char* input_elf = cJSON_GetObjectItem(config,"input_elf")->valuestring;
    logger("input elf: %s\n",input_elf);

    char* target_dir = cJSON_GetObjectItem(config,"target_dir")->valuestring;
    logger("target_dir: %s\n",target_dir);

    char input_elf_path [512] = {0};
    snprintf(input_elf_path,sizeof(input_elf_path),"%s/%s/%s",project_root,target_dir,input_elf);
    if(access(input_elf_path,R_OK)!= 0 ){
        logger("Input ELF not exist : %s\n",input_elf_path);
        exit(-1);
    }

    check_elf_arch(libloader_stage_two);
    check_elf_arch(libloader_stage_three);

    check_libloader_stage_two(libloader_stage_two);
    check_libloader_stage_three(libloader_stage_three);

    if(strcmp(mode,"normal") == 0){
        char* normal_data_file = cJSON_GetObjectItem(config,"data_file_path")->valuestring;
        char normal_data_file_path[512] = {0};
        snprintf(normal_data_file_path,sizeof(normal_data_file_path),"%s/%s/%s/%s",project_root,target_dir,mode,normal_data_file);

        char* analysis_server_ip = cJSON_GetObjectItem(config,"analysis_server_ip")->valuestring;

        char* analysis_server_port = cJSON_GetObjectItem(config,"analysis_server_port")->valuestring;

        char* shell_password = cJSON_GetObjectItem(config,"shell_password")->valuestring;

        logger("generate normal_data_file:%s\n",normal_data_file_path);
        generate_data_file(normal_data_file_path,libloader_stage_two,libloader_stage_three,shell_password,analysis_server_ip,analysis_server_port,NULL,NULL);
        generate_stage_two_parameter(input_elf_path,normal_data_file_path);
    }
    else if(strcmp(mode,"sandbox") == 0){
        char* sandbox_data_file = cJSON_GetObjectItem(config,"data_file_path")->valuestring;
        char sandbox_data_file_path[512] = {0};
        snprintf(sandbox_data_file_path,sizeof(sandbox_data_file_path),"%s/%s/%s/%s",project_root,target_dir,mode,sandbox_data_file);
        char* sandbox_server_ip = cJSON_GetObjectItem(config,"sandbox_server_ip")->valuestring;

        char* sandbox_server_port = cJSON_GetObjectItem(config,"sandbox_server_port")->valuestring;
        logger("generate sandbox_data_file:%s\n",sandbox_data_file_path);
        generate_data_file(sandbox_data_file_path,libloader_stage_two,libloader_stage_three,NULL,NULL,NULL,sandbox_server_ip,sandbox_server_port);
        generate_stage_two_parameter(input_elf_path,sandbox_data_file_path);
    }



}