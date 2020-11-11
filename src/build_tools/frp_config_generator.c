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
    printf("usage: %s config.json mode\n",local);
    printf("     : mode is normal,sandbox\n");
    exit(-1);
}

int main(int argc,char* argv[]){
    if(argc!=3){
        usage(argv[0]);
    }
    char* config_file_name = argv[1];
    char* mode = argv[2];
    if(strcmp(mode,"normal")!= 0 && strcmp(mode,"sandbox")!=0)
        usage(argv[0]);
    printf("config file: %s\n",config_file_name);
    cJSON* config = cJSON_Parse(get_file_content(config_file_name));
    if(config == NULL){
        printf("%s parse failed, Error: %s\n",config_file_name,cJSON_GetErrorPtr());
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
    init_logger(logger_file,0);
    logger("MODE : %s\n",mode);

    char  frp_server_config_name[512] = {0};
    snprintf(frp_server_config_name,sizeof(frp_server_config_name),"%s/out/frp_config/frp_%s_server.ini",project_root,mode);
    char frp_client_config_name[512] = {0};
    snprintf(frp_client_config_name,sizeof(frp_client_config_name),"%s/out/frp_config/frp_%s_client.ini",project_root,mode);

    FILE* frp_server_config = fopen(frp_server_config_name,"w");
    if(frp_server_config == NULL){
        logger("file : %s open failed\n",frp_server_config_name);
        exit(-1);
    }
    FILE* frp_client_config = fopen(frp_client_config,"w");
    if(frp_client_config == NULL){
        logger("file : %s open failed\n",frp_client_config_name);
        exit(-1);
    }
    {
        char* analysis_server_ip = cJSON_GetObjectItem(config,"analysis_server_ip")->valuestring;
        char* analysis_server_port = cJSON_GetObjectItem(config,"analysis_server_port")->valuestring;
    }

    {
        char* sandbox_server_ip = cJSON_GetObjectItem(config,"sandbox_server_ip")->valuestring;
        char* sandbox_server_port = cJSON_GetObjectItem(config,"sandbox_server_port")->valuestring;
    }

    fclose(frp_server_config);
    fclose(frp_client_config);
    puts("frp_generator generate done");
}