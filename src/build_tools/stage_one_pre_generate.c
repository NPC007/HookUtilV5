//
// Created by root on 9/26/20.
//

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
#include <capstone/capstone.h>

#include "utils/common.h"
#include "utils/md5.h"
#include "json/cJSON.h"
#include "elf/elf_utils.h"
#include "file/file_utils.h"
#include "file_check/checker.h"




//loader_stage_one_position has two values:
//one is em_frame , means add first stage code to em_frame section, you must insure the em_frame is not use and has enough space(usual 300 byte is enough)
//tow is new_pt_load, means we need add a pt_load segment to the elf file, which will increase target file size

//loader_stage_other_position has four values:
//1. file, means load data from file, loader_stage_other_path us use
//2. memory, means data already load to memory, loader_stage_other_mem_addr is use
//3. share_memory, means we can get data from share_memory, loader_stage_other_share_memory_id is use
//4. socket, means we can get data from tcp socket server,

//current we do not look for libc_start_main addr from elf manual, we must special it manual

int capstone_open(char* output_elf_base,csh *handle){
    switch(((Elf_Ehdr*)output_elf_base)->e_machine){
        case EM_386:
            if (cs_open(CS_ARCH_X86, CS_MODE_32, handle) != CS_ERR_OK)
                return -1;
            break;
        case EM_X86_64:
            if (cs_open(CS_ARCH_X86, CS_MODE_64, handle) != CS_ERR_OK)
                return -1;
            break;
        case EM_ARM:
            return -1;
        case EM_AARCH64:
            return -1;
        default:
            return -1;
    }
    return 0;

}
int capstone_close(csh *handle){
    cs_close(handle);
}

void usage(char* local){
    logger("usage: %s config.json\n",local);
    exit(-1);
}
typedef enum _RELRO_STATE{
    NONE_RELRO,
    PARTIAL_RELRO,
    FULL_RELRO
}RELRO_STATE;

RELRO_STATE get_elf_relro_state(Elf_Ehdr* ehdr){
    Elf_Phdr* phdr = get_elf_phdr_type(ehdr,PT_GNU_RELRO);
    if(phdr == NULL) {
        logger("Elf is NONE_RELRO");
        return NONE_RELRO;
    }
    Elf_Dyn* dyn = get_elf_dyn_by_type(ehdr,DT_FLAGS);
    if(dyn == NULL) {
        logger("Elf is PARTIAL_RELRO");
        return PARTIAL_RELRO;
    }
    if( (dyn->d_un.d_val & DF_BIND_NOW)!=0 ) {
        logger("Elf is FULL_RELRO");
        return FULL_RELRO;
    }
    else {
        logger("Elf is PARTIAL_RELRO");
        return PARTIAL_RELRO;
    }
}

void process_start_function(char* output_elf,cJSON* config){
    int output_elf_fd;
    char* output_elf_base = NULL;
    long output_elf_size = 0;
    open_mmap_check(output_elf,O_RDONLY,&output_elf_fd,(void**)&output_elf_base,PROT_READ,MAP_SHARED,&output_elf_size);
    unsigned long start_function_vaddr =  ((Elf_Ehdr*)output_elf_base)->e_entry;
    unsigned long start_function_offset = get_offset_by_vaddr(start_function_vaddr,(Elf_Ehdr*)output_elf_base);
    char* start_function = (output_elf_base) + start_function_offset;
    csh handle;
    cs_insn *insn;
    capstone_open(output_elf_base,&handle);
    int total_diassember_size = 100;
    unsigned char* call = NULL;
    while(total_diassember_size > 0) {
        int count = cs_disasm(handle, start_function,total_diassember_size,start_function_vaddr,1,&insn);
        if(count != 1){
            logger("disassember start function failed, v_addr: %p, offset: %p\n",(void*)start_function_vaddr,(void*)start_function_vaddr);
            exit(-1);
        }
        logger("0x%lx:\t%s\t\t%s\n", (long unsigned int)insn[0].address, insn[0].mnemonic,insn[0].op_str);
        if(strncasecmp(insn[0].mnemonic,"CALL",5) ==0 || strncasecmp(insn[0].mnemonic,"BLX",4) ==0|| strncasecmp(insn[0].mnemonic,"BL",3) == 0){
            switch(((Elf_Ehdr*)output_elf_base)->e_machine){
                case EM_386:
                    if(insn[0].bytes[0] == 0xE8 || (insn[0].bytes[0] == 0x67 && insn[0].bytes[1] == 0xE8 )){
                        unsigned long libc_start_main_addr = insn[0].address + insn[0].size + (long) (*(int*)(insn[0].bytes[0] == 0x67 ? (int*)&(insn[0].bytes[2]):(int*)&(insn[0].bytes[1])));
                        call = (unsigned char*)(output_elf_base + get_offset_by_vaddr(libc_start_main_addr,(Elf_Ehdr*)output_elf_base));

                    }else if(insn[0].bytes[0] == 0xff && insn[0].bytes[1] == 0x15){
                        unsigned long libc_start_main_addr = (unsigned long) *((int*)(&(insn[0].bytes[2])));
                        call = (unsigned char*)(output_elf_base + get_offset_by_vaddr(libc_start_main_addr,(Elf_Ehdr*)output_elf_base));
                    }
                    else{
                        logger("unknown x86 call instructions");
                        exit(-1);
                    }
                    break;
                case EM_X86_64:
                    if(insn[0].bytes[0] == 0xE8 || (insn[0].bytes[0] == 0x67 && insn[0].bytes[1] == 0xE8 )){
                        unsigned long libc_start_main_addr = insn[0].address + insn[0].size + (long) (*(int*)(insn[0].bytes[0] == 0x67 ? (int*)&(insn[0].bytes[2]):(int*)&(insn[0].bytes[1])));
                        call = (unsigned char*)(output_elf_base + get_offset_by_vaddr(libc_start_main_addr,(Elf_Ehdr*)output_elf_base));

                    }else if(insn[0].bytes[0] == 0xff && insn[0].bytes[1] == 0x15){
                        unsigned long libc_start_main_addr = insn[0].address + insn[0].size + (unsigned long) *((int*)(&(insn[0].bytes[2])));
                        call = (unsigned char*)(output_elf_base + get_offset_by_vaddr(libc_start_main_addr,(Elf_Ehdr*)output_elf_base));
                    }
                    else{
                        logger("unknown x86 call instructions");
                        exit(-1);
                    }
                    break;
                case EM_ARM:
                    logger("unsupport arm");
                    exit(-1);
                case EM_AARCH64:
                    logger("unsupport aarch64");
                    exit(-1);
                default:
                    logger("unsupport other");
                    exit(-1);
            }
            if(call[0] == 0x8B && call[2] == 0x24 && call[3] == 0xc3){
                logger("find __x86.get_pc_thunk\n");
            }
            else {
                logger("find start call libc_start_main\n");
                break;
            }
        }
        start_function += insn[0].size;
        total_diassember_size -= insn[0].size;
        start_function_vaddr += insn[0].size;
        cs_free(insn,1);
    }
    if(total_diassember_size <=0 ){
        logger("unable find call , something wrong in find_start_offset\n");
        exit(-1);
    }
    char buf[64] = {0};
    switch(((Elf_Ehdr*)output_elf_base)->e_machine){
        case EM_386:
            if(insn[0].bytes[0] == 0xE8 || (insn[0].bytes[0] == 0x67 && insn[0].bytes[1] == 0xE8 )){
                unsigned long libc_start_main_addr = insn[0].address + insn[0].size + (long) (*(int*)(insn[0].bytes[0] == 0x67 ? (int*)&(insn[0].bytes[2]):(int*)&(insn[0].bytes[1])));
                unsigned long libc_start_main_start_call_vaddr = insn[0].address;
                unsigned long libc_start_main_start_call_offset = get_offset_by_vaddr(libc_start_main_start_call_vaddr,(Elf_Ehdr*)output_elf_base);
                cJSON_AddStringToObject(config,"libc_start_main_addr_type","code");
                sprintf(buf,"%p",(void*)libc_start_main_addr);
                cJSON_AddStringToObject(config,"libc_start_main_addr",buf);
                sprintf(buf,"%p",(void*)libc_start_main_start_call_offset);
                cJSON_AddStringToObject(config,"libc_start_main_start_call_offset",buf);
                sprintf(buf,"%p",(void*)libc_start_main_start_call_vaddr);
                cJSON_AddStringToObject(config,"libc_start_main_start_call_vaddr",buf);
                logger("identify libc_start_main_addr_type : code\n");
                logger("identify libc_start_main_addr              : %p\n",(void*)libc_start_main_addr);
                logger("identify libc_start_main_start_call_offset : %p\n",(void*)libc_start_main_start_call_offset);
                logger("identify libc_start_main_start_call_vaddr  : %p\n",(void*)libc_start_main_start_call_vaddr);

            }else if(insn[0].bytes[0] == 0xff && insn[0].bytes[1] == 0x15){
                unsigned long libc_start_main_addr = (unsigned long) *((int*)(&(insn[0].bytes[2])));
                unsigned long libc_start_main_start_call_vaddr = insn[0].address;
                unsigned long libc_start_main_start_call_offset = get_offset_by_vaddr(libc_start_main_start_call_vaddr,(Elf_Ehdr*)output_elf_base);
                cJSON_AddStringToObject(config,"libc_start_main_addr_type","ptr");
                sprintf(buf,"%p",(void*)libc_start_main_addr);
                cJSON_AddStringToObject(config,"libc_start_main_addr",buf);
                sprintf(buf,"%p",(void*)libc_start_main_start_call_offset);
                cJSON_AddStringToObject(config,"libc_start_main_start_call_offset",buf);
                sprintf(buf,"%p",(void*)libc_start_main_start_call_vaddr);
                cJSON_AddStringToObject(config,"libc_start_main_start_call_vaddr",buf);
                logger("identify libc_start_main_addr_type : ptr\n");
                logger("identify libc_start_main_addr              : %p\n",(void*)libc_start_main_addr);
                logger("identify libc_start_main_start_call_offset : %p\n",(void*)libc_start_main_start_call_offset);
                logger("identify libc_start_main_start_call_vaddr  : %p\n",(void*)libc_start_main_start_call_vaddr);
            }
            else{
                logger("unknown x86 call instructions");
                exit(-1);
            }
            break;

        case EM_X86_64:
            if(insn[0].bytes[0] == 0xE8 || (insn[0].bytes[0] == 0x67 && insn[0].bytes[1] == 0xE8 )){
                unsigned long libc_start_main_addr = insn[0].address + insn[0].size + (long) (*(int*)(insn[0].bytes[0] == 0x67 ? (int*)&(insn[0].bytes[2]):(int*)&(insn[0].bytes[1])));
                unsigned long libc_start_main_start_call_vaddr = insn[0].address;
                unsigned long libc_start_main_start_call_offset = get_offset_by_vaddr(libc_start_main_start_call_vaddr,(Elf_Ehdr*)output_elf_base);
                cJSON_AddStringToObject(config,"libc_start_main_addr_type","code");
                sprintf(buf,"%p",(void*)libc_start_main_addr);
                cJSON_AddStringToObject(config,"libc_start_main_addr",buf);
                sprintf(buf,"%p",(void*)libc_start_main_start_call_offset);
                cJSON_AddStringToObject(config,"libc_start_main_start_call_offset",buf);
                sprintf(buf,"%p",(void*)libc_start_main_start_call_vaddr);
                cJSON_AddStringToObject(config,"libc_start_main_start_call_vaddr",buf);
                logger("identify libc_start_main_addr_type : code\n");
                logger("identify libc_start_main_addr              : %p\n",(void*)libc_start_main_addr);
                logger("identify libc_start_main_start_call_offset : %p\n",(void*)libc_start_main_start_call_offset);
                logger("identify libc_start_main_start_call_vaddr  : %p\n",(void*)libc_start_main_start_call_vaddr);

            }else if(insn[0].bytes[0] == 0xff && insn[0].bytes[1] == 0x15){
                unsigned long libc_start_main_addr = (unsigned long) *((int*)(&(insn[0].bytes[2]))) +  insn[0].address + insn[0].size;
                unsigned long libc_start_main_start_call_vaddr = insn[0].address;
                unsigned long libc_start_main_start_call_offset = get_offset_by_vaddr(libc_start_main_start_call_vaddr,(Elf_Ehdr*)output_elf_base);
                cJSON_AddStringToObject(config,"libc_start_main_addr_type","ptr");
                sprintf(buf,"%p",(void*)libc_start_main_addr);
                cJSON_AddStringToObject(config,"libc_start_main_addr",buf);
                sprintf(buf,"%p",(void*)libc_start_main_start_call_offset);
                cJSON_AddStringToObject(config,"libc_start_main_start_call_offset",buf);
                sprintf(buf,"%p",(void*)libc_start_main_start_call_vaddr);
                cJSON_AddStringToObject(config,"libc_start_main_start_call_vaddr",buf);
                logger("identify libc_start_main_addr_type : ptr\n");
                logger("identify libc_start_main_addr              : %p\n",(void*)libc_start_main_addr);
                logger("identify libc_start_main_start_call_offset : %p\n",(void*)libc_start_main_start_call_offset);
                logger("identify libc_start_main_start_call_vaddr  : %p\n",(void*)libc_start_main_start_call_vaddr);
            }
            else{
                logger("unknown x86 call instructions");
                exit(-1);
            }

            break;
        case EM_ARM:
            logger("unsupport arm");
            exit(-1);
        case EM_AARCH64:
            logger("unsupport aarch64");
            exit(-1);
        default:
            logger("unsupport other");
            exit(-1);
    }
    cs_free(insn,1);
    capstone_close(&handle);
    close_and_munmap(output_elf,output_elf_fd,output_elf_base,&output_elf_size);
}


void process_first_entry_offset(char* input_elf,cJSON* config,int stage_one_normal_config_fd,int stage_one_sandbox_config_fd,int *phdr_has_moved){
    int input_elf_fd;
    char* input_elf_base;
    long input_elf_size;
    int first_entry_offset = 0;
    open_mmap_check(input_elf,O_RDONLY,&input_elf_fd,(void**)&input_elf_base,PROT_READ,MAP_SHARED,&input_elf_size);

    char* loader_stage_one_position = cJSON_GetObjectItem(config,"loader_stage_one_position")->valuestring;
    {
        if (strcmp("eh_frame", loader_stage_one_position) == 0) {
            Elf_Shdr* eh_frame_shdr = get_elf_section_by_name(".eh_frame",(Elf_Ehdr*)input_elf_base);
            if(eh_frame_shdr==NULL){
                logger("file:%s have no eh_frame, change first stage code to another place\n",input_elf);
                exit(-1);
            }
            unsigned long elf_load_base = get_elf_load_base((Elf_Ehdr*)input_elf_base);
            first_entry_offset =(int)((unsigned long)eh_frame_shdr->sh_addr - (unsigned long)elf_load_base);
        } else if (strcmp("new_pt_load", loader_stage_one_position) == 0) {
            mov_phdr(input_elf);
            *phdr_has_moved = 1;
            first_entry_offset = get_file_size(input_elf);
            //asseming stage_one size is smaller than 4K
            increase_file(input_elf,get_file_size(input_elf) + 0x1000);
        } else {
            logger("unsupport loader_stage_one_position: %s\n", loader_stage_one_position);
            exit(-1);
        }
    }

    {
        char buf[256];
        snprintf(buf,255,"0x%x",first_entry_offset);
        write_marco_define(stage_one_normal_config_fd, "FIRST_ENTRY_OFFSET", buf);
        write_marco_define(stage_one_sandbox_config_fd, "FIRST_ENTRY_OFFSET", buf);
    }
    close_and_munmap(input_elf,input_elf_fd,input_elf_base,&input_elf_size);
}


int main(int argc,char* argv[]){
    if(argc!=2){
        usage(argv[0]);
    }
    int phdr_has_moved = 0;
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
    char* target_dir = cJSON_GetObjectItem(config,"target_dir")->valuestring;
    char stage_one_normal_config_h[512] = {0};
    snprintf(stage_one_normal_config_h,512,"%s/src/auto_generate/stage_one_normal_config.h",project_root);
    logger("stage_one_normal_config.h: %s\n",stage_one_normal_config_h);
    char stage_one_sandbox_config_h[512] = {0};
    snprintf(stage_one_sandbox_config_h,512,"%s/src/auto_generate/stage_one_sandbox_config.h",project_root);
    logger("stage_one_sandbox_config_h: %s\n",stage_one_sandbox_config_h);


    char* normal_data_file = cJSON_GetObjectItem(config,"normal_data_file_path")->valuestring;
    char normal_data_file_path[512] = {0};
    snprintf(normal_data_file_path,sizeof(normal_data_file_path),"%s/%s/%s",project_root,target_dir,normal_data_file);

    char* sandbox_data_file = cJSON_GetObjectItem(config,"sandbox_data_file_path")->valuestring;
    char sandbox_data_file_path[512] = {0};
    snprintf(sandbox_data_file_path,sizeof(sandbox_data_file_path),"%s/%s/%s",project_root,target_dir,sandbox_data_file);
    logger("normal_data_file:%s\n",normal_data_file_path);
    logger("sandbox_data_file:%s\n",sandbox_data_file_path);

    char* input_elf = cJSON_GetObjectItem(config,"input_elf")->valuestring;
    char input_elf_path [512] = {0};
    snprintf(input_elf_path,sizeof(input_elf_path),"%s/%s/%s",project_root,target_dir,input_elf);
    if(access(input_elf_path,R_OK)!= 0 ){
        logger("Input ELF not exist : %s\n",input_elf_path);
        exit(-1);
    }
    logger("input_elf: %s\n",input_elf_path);
    char* tmp_input_file = "/tmp/input_file_tmp";
    copy_file(input_elf_path,tmp_input_file);
    int stage_one_normal_config_fd = open(stage_one_normal_config_h,O_RDWR|O_TRUNC|O_CREAT);
    int stage_one_sandbox_config_fd = open(stage_one_sandbox_config_h,O_RDWR|O_TRUNC|O_CREAT);
    void* elf_load_base = NULL;

    // PIE macro
    {
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
                write_marco_define(stage_one_normal_config_fd,"IS_PIE","1");
                write_marco_define(stage_one_sandbox_config_fd,"IS_PIE","1");
                break;
            case ET_EXEC:
                write_marco_define(stage_one_normal_config_fd,"IS_PIE","0");
                write_marco_define(stage_one_sandbox_config_fd,"IS_PIE","0");
                break;
            default:
                logger("unknown object type: %d\n",ehdr->e_type);
                exit(-1);
        }
    }
    process_start_function(tmp_input_file,config);
    {
        char* libc_start_main_addr_type = cJSON_GetObjectItem(config,"libc_start_main_addr_type")->valuestring;
        if(strcmp(libc_start_main_addr_type,"code")==0) {
            write_marco_define(stage_one_normal_config_fd, "LIBC_START_MAIN_ADDR_TYPE", "CODE");
            write_marco_define(stage_one_sandbox_config_fd, "LIBC_START_MAIN_ADDR_TYPE", "CODE");
        }
        else if(strcmp(libc_start_main_addr_type,"ptr")==0){
            write_marco_define(stage_one_normal_config_fd,"LIBC_START_MAIN_ADDR_TYPE","PTR");
            write_marco_define(stage_one_sandbox_config_fd,"LIBC_START_MAIN_ADDR_TYPE","PTR");
        }
        else{
            logger("libc_start_main_addr_type has only two values, one is code, another is ptr\n");
            exit(-1);
        }
        char* libc_start_main_addr = cJSON_GetObjectItem(config,"libc_start_main_addr")->valuestring;
        write_marco_define(stage_one_normal_config_fd,"LIB_C_START_MAIN_ADDR",libc_start_main_addr);
        write_marco_define(stage_one_sandbox_config_fd,"LIB_C_START_MAIN_ADDR",libc_start_main_addr);
    }

    process_first_entry_offset(tmp_input_file,config,stage_one_normal_config_fd,stage_one_sandbox_config_fd,&phdr_has_moved);



    char* loader_stage_other_position = cJSON_GetObjectItem(config,"loader_stage_other_position")->valuestring;
    if(strcmp("file",loader_stage_other_position)==0){
        write_marco_define(stage_one_normal_config_fd,"CONFIG_LOADER_TYPE","LOAD_FROM_FILE");
        write_marco_define(stage_one_sandbox_config_fd,"CONFIG_LOADER_TYPE","LOAD_FROM_FILE");
        char* loader_stage_other_file_path = cJSON_GetObjectItem(config,"loader_stage_other_file_path")->valuestring;
        write_marco_str_define(stage_one_normal_config_fd,"PATCH_DATA_PATH",loader_stage_other_file_path);
        write_marco_str_define(stage_one_sandbox_config_fd,"PATCH_DATA_PATH",loader_stage_other_file_path);
        char tmp_buf[256];
        snprintf(tmp_buf, 255, "0x%lx", get_file_size(normal_data_file_path));
        write_marco_define(stage_one_normal_config_fd, "PATCH_DATA_MMAP_FILE_SIZE", tmp_buf);
        snprintf(tmp_buf, 255, "0x%lx", get_file_size(sandbox_data_file_path));
        write_marco_define(stage_one_sandbox_config_fd, "PATCH_DATA_MMAP_FILE_SIZE", tmp_buf);

    }
    else if(strcmp("memory",loader_stage_other_position)==0){
        if(!phdr_has_moved)
            mov_phdr(tmp_input_file);
        write_marco_define(stage_one_normal_config_fd,"CONFIG_LOADER_TYPE","LOAD_FROM_MEM");
        write_marco_define(stage_one_sandbox_config_fd,"CONFIG_LOADER_TYPE","LOAD_FROM_MEM");
        char tmp_buf[256];
        snprintf(tmp_buf, 255, "0x%lx", get_file_size(normal_data_file_path));
        write_marco_define(stage_one_normal_config_fd, "PATCH_DATA_MMAP_FILE_SIZE", tmp_buf);
        snprintf(tmp_buf, 255, "0x%lx", get_file_size(sandbox_data_file_path));
        write_marco_define(stage_one_sandbox_config_fd, "PATCH_DATA_MMAP_FILE_SIZE", tmp_buf);

        int output_file_size = get_file_size(tmp_input_file);
        if(output_file_size%0x1000!=0){
            output_file_size = UP_PADDING(output_file_size,0x1000);
            increase_file(tmp_input_file,output_file_size);
        }
        unsigned long output_elf_load_base = get_elf_file_load_base(tmp_input_file);
        unsigned long loader_stage_other_vaddr = output_elf_load_base+output_file_size;
        snprintf(tmp_buf, 255, "0x%lx", loader_stage_other_vaddr);
        write_marco_define(stage_one_normal_config_fd, "PATCH_DATA_MMAP_FILE_VADDR", tmp_buf);
        write_marco_define(stage_one_sandbox_config_fd, "PATCH_DATA_MMAP_FILE_VADDR", tmp_buf);
    }
    else if(strcmp("share_memory",loader_stage_other_position)==0){
        logger("not implement,exit!!!");
        exit(-1);
        write_marco_define(stage_one_normal_config_fd,"CONFIG_LOADER_TYPE","LOAD_FROM_SHARE_MEM");
        write_marco_define(stage_one_sandbox_config_fd,"CONFIG_LOADER_TYPE","LOAD_FROM_SHARE_MEM");
        char* loader_stage_other_share_memory_id = cJSON_GetObjectItem(config,"loader_stage_other_share_memory_id")->valuestring;
        write_marco_define(stage_one_normal_config_fd,"PATCH_DATA_SHARE_MEM_ID",loader_stage_other_share_memory_id);
        write_marco_define(stage_one_sandbox_config_fd,"CONFIG_LOADER_TYPE","LOAD_FROM_SHARE_MEM");
    }
    else if(strcmp("socket",loader_stage_other_position)==0){
        write_marco_define(stage_one_normal_config_fd,"CONFIG_LOADER_TYPE","LOAD_FROM_SOCKET");
        write_marco_define(stage_one_sandbox_config_fd,"CONFIG_LOADER_TYPE","LOAD_FROM_SOCKET");
        char* loader_stage_other_socket_server_ip = cJSON_GetObjectItem(config,"loader_stage_other_socket_server_ip")->valuestring;
        char* loader_stage_other_socket_server_port = cJSON_GetObjectItem(config,"loader_stage_other_socket_server_port")->valuestring;
        char loader_stage_other_socket_server_ip_str[256];
        char loader_stage_other_socket_server_port_str[256];
        struct sockaddr_in addr;
        inet_aton(loader_stage_other_socket_server_ip,&addr.sin_addr);
        int port = htons(atoi(loader_stage_other_socket_server_port));
        sprintf(loader_stage_other_socket_server_ip_str,"%u",addr.sin_addr.s_addr);
        sprintf(loader_stage_other_socket_server_port_str,"%u",port);
        write_marco_define(stage_one_normal_config_fd,"PATCH_DATA_SOCKET_SERVER_IP",loader_stage_other_socket_server_ip_str);
        write_marco_define(stage_one_sandbox_config_fd,"PATCH_DATA_SOCKET_SERVER_IP",loader_stage_other_socket_server_ip_str);
        write_marco_define(stage_one_normal_config_fd,"PATCH_DATA_SOCKET_SERVER_PORT",loader_stage_other_socket_server_port_str);
        write_marco_define(stage_one_sandbox_config_fd,"PATCH_DATA_SOCKET_SERVER_PORT",loader_stage_other_socket_server_port_str);
        char tmp_buf[256];
        snprintf(tmp_buf, 255, "0x%lx", get_file_size(normal_data_file_path));
        write_marco_define(stage_one_normal_config_fd, "PATCH_DATA_MMAP_FILE_SIZE", tmp_buf);
        snprintf(tmp_buf, 255, "0x%lx", get_file_size(sandbox_data_file_path));
        write_marco_define(stage_one_sandbox_config_fd, "PATCH_DATA_MMAP_FILE_SIZE", tmp_buf);
    }
    else{
        logger("unsupport loader_stage_other_position: %s\n",loader_stage_other_position);
        exit(-1);
    }
    close(stage_one_normal_config_fd);
    close(stage_one_sandbox_config_fd);
}