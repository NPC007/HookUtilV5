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
            }else{
                if(pt_load->p_vaddr <= eh_frame_shdr->sh_addr  && eh_frame_shdr->sh_addr <= pt_load->p_vaddr + pt_load->p_memsz){
                    logger("check_eh_frame_section_executable failed, ef_frame is not executable, we can mark it executeable\n");
                    pt_load->p_flags = pt_load->p_flags | PF_X;
                    return;
                }
            }
        }
    }
    logger("check_eh_frame_section_executable failed, ef_frame is not executable, you should consider place stage_one to other position\n");
    exit(-1);
}

long g_init_addr;
long g_size;
void check_init_arr(Elf_Ehdr* ehdr){
    Elf_Shdr* init_arr = get_elf_section_by_name(".init_array",(Elf_Ehdr*)ehdr);
    printf("init_arr: %x\n",init_arr->sh_addr);
    g_init_addr = init_arr->sh_addr;
    g_size = init_arr->sh_size;
}

void check_elf_file_and_config_compatible(char* elf_path,cJSON* config){
    char* elf_base;
    int elf_file_fd;
    long elf_file_size;
    open_mmap_check(elf_path,O_RDWR,&elf_file_fd,(void**)&elf_base,PROT_READ|PROT_WRITE,MAP_SHARED,&elf_file_size);
    char* loader_stage_one_position = cJSON_GetObjectItem(config,"loader_stage_one_position")->valuestring;
    if (strcmp("eh_frame", loader_stage_one_position) == 0) {
        check_eh_frame_section_executable((Elf_Ehdr*)elf_base);
    }
    check_init_arr((Elf_Ehdr*)elf_base);
    close_and_munmap(elf_path,elf_file_fd,elf_base,&elf_file_size);
}



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
    if(strcmp(mode,"normal") == 0)
        init_logger(logger_file,1);
    else
        init_logger(logger_file,0);
    logger("MODE : %s\n",mode);
    char debug_config_h[512] = {0};
    char config_h[512] = {0};
    snprintf(debug_config_h,512,"%s/src/auto_generate/%s/debug_config.h",project_root,mode);
    logger("debug_config.h: %s\n",debug_config_h);
    snprintf(config_h,512,"%s/src/auto_generate/%s/config.h",project_root,mode);
    logger("config.h: %s\n",config_h);
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
        int debug_config_file_fd = open(debug_config_h,O_RDWR|O_TRUNC|O_CREAT,0777);
        if(debug_config_file_fd == -1){
            logger("failed to open file: %s, errno: %s",debug_config_h,strerror(errno));
            exit(-1);
        }
#if PATCH_DEBUG_CONFIG == 1
        write_marco_define(debug_config_file_fd, "PATCH_DEBUG", "1");
#elif PATCH_DEBUG_CONFIG == 0
        write_marco_define(debug_config_file_fd, "PATCH_DEBUG", "0");
#else
#error("PATCH_DEBUG Not Defined")
#endif


        // PIE macro
        Elf_Ehdr* ehdr = (Elf_Ehdr*)get_file_content_length(input_elf_path,0,sizeof(Elf_Ehdr));

#ifdef __x86_64__
        if(ehdr->e_machine != EM_X86_64){
            logger("Arch not same, something wrong\n");
            exit(-1);
        }
#elif __i386__
        if(ehdr->e_machine != EM_386){
            logger("Arch not same, something wrong\n");
            exit(-1);
        }
#endif


        switch(ehdr->e_type){
            case ET_DYN:
            case ET_REL:
                write_marco_define(debug_config_file_fd,"IS_PIE","1");
                break;
            case ET_EXEC:
                write_marco_define(debug_config_file_fd,"IS_PIE","0");
                break;
            default:
                logger("unknown object type: %d\n",ehdr->e_type);
                exit(-1);
        }
    {
        char buf[0x100];
        sprintf(buf, "0x%x",g_init_addr);
        write_marco_define(debug_config_file_fd,"INIT_ARR_ADDR",buf);
        sprintf(buf,"0x%x",g_size);
        write_marco_define(debug_config_file_fd,"INIT_SIZE",buf);
    }

        close(debug_config_file_fd);
    }




    if(strcmp(mode,"normal") == 0) {
        {
            logger("###########################################process config.h######################################\n");
            int config_file_fd = open(config_h, O_RDWR | O_TRUNC | O_CREAT, 0777);

            char *tcp_time_out = cJSON_GetObjectItem(config, "tcp_time_out")->valuestring;
            write_marco_define(config_file_fd, "TCP_TIME_OUT", tcp_time_out);

            char *analysis_server_ip = cJSON_GetObjectItem(config, "analysis_server_ip")->valuestring;
            write_marco_str_define(config_file_fd, "REDIRECT_HOST", analysis_server_ip);

            char *analysis_server_port = cJSON_GetObjectItem(config, "analysis_server_port")->valuestring;
            write_marco_define(config_file_fd, "REDIRECT_PORT", analysis_server_port);

            char *shell_password = cJSON_GetObjectItem(config, "shell_password")->valuestring;
            write_marco_str_define(config_file_fd, "SHELL_PASSWD", shell_password);

            char *local_file_instead_of_udp = cJSON_GetObjectItem(config, "local_file_instead_of_udp")->valuestring;
            write_marco_define(config_file_fd, "USE_LOCAL_FILE_INSTEAD_OF_UDP", local_file_instead_of_udp);

            char *io_local_save_path = cJSON_GetObjectItem(config, "io_local_save_path")->valuestring;
            write_marco_str_define(config_file_fd, "IO_REDIRECT_PATH", io_local_save_path);

            char *io_inline_hook = cJSON_GetObjectItem(config, "io_inline_hook")->valuestring;
            write_marco_define(config_file_fd, "USE_IO_INLINE_REDIRECT", io_inline_hook);

            int is_v5 = cJSON_GetObjectItem(config, "v5");
            if(is_v5){
                write_marco_define(config_file_fd, "USE_V5", "");
            }

            if (cJSON_GetObjectItem(config, "shell_code_defense") == NULL) {
                logger("shell_code_defense is not set\n");
                exit(-1);
            }
            char *shell_code_defense = cJSON_GetObjectItem(config, "shell_code_defense")->valuestring;
            int shell_code_defense_value = atoi(shell_code_defense);
            if (shell_code_defense_value > 0) {
                write_marco_define(config_file_fd, "SHELL_CODE_DEFENSE", "1");
            } else {
                write_marco_define(config_file_fd, "SHELL_CODE_DEFENSE", "0");
            }
            close(config_file_fd);
        }
    } else if (strcmp(mode, "sandbox") == 0) {
        {
            logger("###########################################process sandbox_config.h######################################\n");
            int config_file_fd = open(config_h, O_RDWR | O_TRUNC | O_CREAT,0777);

            char *tcp_time_out = cJSON_GetObjectItem(config, "tcp_time_out")->valuestring;
            write_marco_define(config_file_fd, "TCP_TIME_OUT", tcp_time_out);

            char *analysis_server_ip = cJSON_GetObjectItem(config, "sandbox_server_ip")->valuestring;
            write_marco_str_define(config_file_fd, "SANDBOX_HOST", analysis_server_ip);

            char *analysis_server_port = cJSON_GetObjectItem(config, "sandbox_server_port")->valuestring;
            write_marco_define(config_file_fd, "SANDBOX_PORT", analysis_server_port);

            if (cJSON_GetObjectItem(config, "shell_code_defense") == NULL) {
                logger("shell_code_defense is not set\n");
                exit(-1);
            }
            char *shell_code_defense = cJSON_GetObjectItem(config, "shell_code_defense")->valuestring;
            int shell_code_defense_value = atoi(shell_code_defense);
            if (shell_code_defense_value > 0) {
                write_marco_define(config_file_fd, "SHELL_CODE_DEFENSE", "1");
            } else {
                write_marco_define(config_file_fd, "SHELL_CODE_DEFENSE", "0");
            }
            close(config_file_fd);
        }
    }
    puts("pre generate done");
}