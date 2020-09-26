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
    char debug_config_h[512] = {0};
    char sandbox_config_h[512] = {0};
    char normal_config_h[512] = {0};
    snprintf(debug_config_h,512,"%s/src/auto_generate/debug_config.h",project_root);
    printf("debug_config.h: %s\n",debug_config_h);
    snprintf(normal_config_h,512,"%s/src/auto_generate/normal_config.h",project_root);
    printf("normal_config.h: %s\n",normal_config_h);
    snprintf(sandbox_config_h,512,"%s/src/auto_generate/sandbox_config.h",project_root);
    printf("sandbox_config.h: %s\n",sandbox_config_h);
    char* input_elf = cJSON_GetObjectItem(config,"input_elf")->valuestring;
    printf("input elf: %s\n",input_elf);
    char* target_dir = cJSON_GetObjectItem(config,"target_dir")->valuestring;
    char input_elf_path [512] = {0};
    snprintf(input_elf_path,sizeof(input_elf_path),"%s/%s/%s",project_root,target_dir,input_elf);
    if(access(input_elf_path,R_OK)!= 0 ){
        printf("Input ELF not exist : %s\n",input_elf_path);
        exit(-1);
    }
    // Process debug_config.h
    {
        printf("###########################################process debug_config.h#######################################\n");
        int debug_config_file_fd = open(debug_config_h,O_RDWR|O_TRUNC|O_CREAT);
        char *debug = cJSON_GetObjectItem(config, "debug")->valuestring;
        if (strncasecmp(debug, "1",sizeof("1")) == 0 || strncasecmp(debug, "true",sizeof("true")) == 0) {
            write_marco_define(debug_config_file_fd, "PATCH_DEBUG", "1");
        } else {
            write_marco_define(debug_config_file_fd, "PATCH_DEBUG", "0");
        }
        close(debug_config_file_fd);
    }
    //Process normal_config.h
    {
        printf("###########################################process normal_config.h######################################\n");
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
        printf("###########################################process sandbox_config.h######################################\n");
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