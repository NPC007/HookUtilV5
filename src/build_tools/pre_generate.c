#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <elf.h>
#include <errno.h>
#include "include/hook.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils/common.h"
#include "utils/md5.h"
#include "json/cJSON.h"
#include "elf/elf_utils.h"
#include "file/file_utils.h"
#include "file_check/checker.h"



void check_eh_frame_section_executable(Elf_Ehdr* ehdr){
    Elf_Shdr* eh_frame_shdr = get_elf_section_by_name(".eh_frame",(Elf_Ehdr*)ehdr);
    if(eh_frame_shdr==NULL){
        logger("check_eh_frame_section_executable failed, no find ef_frame section, you should consider place stage_one to other position\n");
        exit(-1);
    }
    for(int i=0;i<ehdr->e_phnum;i++){
        Elf_Phdr* pt_load = (Elf_Phdr*)((char*)ehdr+ ehdr->e_phoff + ehdr->e_phentsize*i);
        if(pt_load->p_type == PT_LOAD){
            if((pt_load->p_flags & PF_X )!=0){
                if(pt_load->p_vaddr <= eh_frame_shdr->sh_addr  && eh_frame_shdr->sh_addr <= pt_load->p_vaddr + pt_load->p_memsz){
                    logger("check_eh_frame_section_executable success, ef_frame is executable\n");
                    return;
                }
            }
        }
    }
    logger("check_eh_frame_section_executable failed, ef_frame is not executable, you should consider place stage_one to other position\n");
    exit(-1);
}


void check_elf_file_and_config_compatible(char* elf_path,cJSON* config){
    char* elf_base;
    int elf_file_fd;
    long elf_file_size;
    open_mmap_check(elf_path,O_RDONLY,&elf_file_fd,(void**)&elf_base,PROT_READ,MAP_PRIVATE,&elf_file_size);
    char* loader_stage_one_position = cJSON_GetObjectItem(config,"loader_stage_one_position")->valuestring;
    if (strcmp("eh_frame", loader_stage_one_position) == 0) {
        check_eh_frame_section_executable((Elf_Ehdr*)elf_base);
    }
    close_and_munmap(elf_path,elf_file_fd,elf_base,&elf_file_size);
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
    if(check_file_exist(project_root)<0)
    {
        printf("project_root not exist:%s \n",project_root);
        exit(-1);
    }
    char logger_file[512] = {0};
    snprintf(logger_file,sizeof(logger_file),"%s/out/build.log",project_root);
    init_logger(logger_file,1);
    char debug_config_h[512] = {0};
    char sandbox_config_h[512] = {0};
    char normal_config_h[512] = {0};
    snprintf(debug_config_h,512,"%s/src/auto_generate/debug_config.h",project_root);
    logger("debug_config.h: %s\n",debug_config_h);
    snprintf(normal_config_h,512,"%s/src/auto_generate/normal_config.h",project_root);
    logger("normal_config.h: %s\n",normal_config_h);
    snprintf(sandbox_config_h,512,"%s/src/auto_generate/sandbox_config.h",project_root);
    logger("sandbox_config.h: %s\n",sandbox_config_h);
    char* input_elf = cJSON_GetObjectItem(config,"input_elf")->valuestring;
    logger("input elf: %s\n",input_elf);
    char* target_dir = cJSON_GetObjectItem(config,"target_dir")->valuestring;
    char input_elf_path [512] = {0};
    snprintf(input_elf_path,sizeof(input_elf_path),"%s/%s/%s",project_root,target_dir,input_elf);
    if(access(input_elf_path,R_OK)!= 0 ){
        logger("Input ELF not exist : %s\n",input_elf_path);
        exit(-1);
    }
    // Process debug_config.h
    check_elf_file_and_config_compatible(input_elf_path,config);
    {
        logger("###########################################process debug_config.h#######################################\n");
        int debug_config_file_fd = open(debug_config_h,O_RDWR|O_TRUNC|O_CREAT);
#if PATCH_DEBUG_CONFIG == 1
        write_marco_define(debug_config_file_fd, "PATCH_DEBUG", "1");
#elif PATCH_DEBUG_CONFIG == 0
        write_marco_define(debug_config_file_fd, "PATCH_DEBUG", "0");
#else
#error("PATCH_DEBUG Not Defined")
#endif

        close(debug_config_file_fd);
    }
    //Process normal_config.h
    {
        logger("###########################################process normal_config.h######################################\n");
        int normal_config_file_fd = open(normal_config_h,O_RDWR|O_TRUNC|O_CREAT);

        char* tcp_time_out = cJSON_GetObjectItem(config,"tcp_time_out")->valuestring;
        write_marco_define(normal_config_file_fd,"TCP_TIME_OUT",tcp_time_out);

        char* analysis_server_ip = cJSON_GetObjectItem(config,"analysis_server_ip")->valuestring;
        write_marco_str_define(normal_config_file_fd,"REDIRECT_HOST",analysis_server_ip);

        char* analysis_server_port = cJSON_GetObjectItem(config,"analysis_server_port")->valuestring;
        write_marco_define(normal_config_file_fd,"REDIRECT_PORT",analysis_server_port);

        char* shell_password = cJSON_GetObjectItem(config,"shell_password")->valuestring;
        write_marco_str_define(normal_config_file_fd,"SHELL_PASSWD",shell_password);

        char* local_file_instead_of_udp = cJSON_GetObjectItem(config,"local_file_instead_of_udp")->valuestring;
        write_marco_define(normal_config_file_fd,"USE_LOCAL_FILE_INSTEAD_OF_UDP",local_file_instead_of_udp);

        char* io_local_save_path = cJSON_GetObjectItem(config,"io_local_save_path")->valuestring;
        write_marco_str_define(normal_config_file_fd,"IO_REDIRECT_PATH",io_local_save_path);

        char* io_inline_hook = cJSON_GetObjectItem(config,"io_inline_hook")->valuestring;
        write_marco_define(normal_config_file_fd,"USE_IO_INLINE_REDIRECT",io_inline_hook);

        close(normal_config_file_fd);
    }
    //Process sanbox_config.h
    {
        logger("###########################################process sandbox_config.h######################################\n");
        int sandbox_config_file_fd = open(sandbox_config_h,O_RDWR|O_TRUNC|O_CREAT);

        char* tcp_time_out = cJSON_GetObjectItem(config,"tcp_time_out")->valuestring;
        write_marco_define(sandbox_config_file_fd,"TCP_TIME_OUT",tcp_time_out);

        char* analysis_server_ip = cJSON_GetObjectItem(config,"sandbox_server_ip")->valuestring;
        write_marco_str_define(sandbox_config_file_fd,"SANDBOX_HOST",analysis_server_ip);

        char* analysis_server_port = cJSON_GetObjectItem(config,"sandbox_server_port")->valuestring;
        write_marco_define(sandbox_config_file_fd,"SANDBOX_PORT",analysis_server_port);


        close(sandbox_config_file_fd);
    }

    puts("pre generate done");

}