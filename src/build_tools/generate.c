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

//#define UP_PADDING(X,Y)  ((long)(((long)X/Y+1)*Y))
//#define DOWN_PADDING(X,Y) ((long)((long)X-(long)X%Y))

void modify_entry_point(char *elf_base, long new_function_vaddr,cJSON* config){
    logger("enter modify entry point: new_function_vaddr=0x%p\n", new_function_vaddr);
    long ori_entry_vaddr = ((Elf_Ehdr*)elf_base)->e_entry;
    ((Elf_Ehdr*)elf_base)->e_entry = new_function_vaddr;
}

void modify_mov_scu_init(char* elf_base,long new_function_vaddr,cJSON* config){
    logger("enter modify scu: new_function_vaddr=0x%p\n", new_function_vaddr);
    char* scu_init_mov_offset_str = cJSON_GetObjectItem(config, "scu_init_mov_offset")->valuestring;
    char* scu_init_mov_vaddr_str = cJSON_GetObjectItem(config, "scu_init_mov_vaddr")->valuestring;
    long scu_init_mov_offset = 0;
    long scu_init_mov_vaddr = 0;
    puts(scu_init_mov_offset_str);
    puts(scu_init_mov_vaddr_str);
    scu_init_mov_offset = strtol(scu_init_mov_offset_str, NULL, 16);
    scu_init_mov_vaddr = strtol(scu_init_mov_vaddr_str, NULL, 16);
    if(scu_init_mov_offset == 0 || scu_init_mov_vaddr == 0){
        logger("scu init mov offset or addr get error, check it");
        exit(-1);
    }
    unsigned char* mov = (unsigned char*)(elf_base+scu_init_mov_offset);
    switch(((Elf_Ehdr*)elf_base)->e_machine){
    case EM_386://x32 nopie其实是改的push，后面测的时候才注意到，就不改名了
        logger("x32 modify enter\n");
        if(mov[0] == 0x8d){
            logger("scu_init x32 mov modify\n");
            // mov[1] = 0x80;
            char *scu_init_ebx_str = cJSON_GetObjectItem(config, "scu_init_ebx")->valuestring;
            long scu_init_ebx = 0;
            scu_init_ebx = strtol(scu_init_ebx_str, NULL, 16);
            if(is_pie(elf_base))
                *((int*)(&mov[2])) = (int)(new_function_vaddr - scu_init_ebx);
            // else
            //     *((int*)(&mov[1])) = (int)(new_function_vaddr);
            logger("modify x32 mov\n");
        }else if(mov[0] == 0x68){
            logger("scu_init x32 mov modify push!!!!!!\n");
            // mov[1] = 0x80;
            if(!is_pie(elf_base))
                *((int*)(&mov[1])) = (int)(new_function_vaddr);
            logger("modify x32 push\n");
        }
        break;
    case EM_X86_64:
        logger("enter into x64 case mov[0]=%x\n",mov[0]);
        if(mov[0] == 0x48 || mov[0] == 0x4c){
            if(is_pie(elf_base))
                *((int*)(&mov[3])) = (int)(new_function_vaddr - 7 - scu_init_mov_vaddr);
            else
                *((int*)(&mov[3])) = (int)(new_function_vaddr);

            logger("modify x64 mov\n");
        }
        break;
    
    default:
        break;
    }
    logger("modify mov scu init end\n");
}


void modify_call_libc_start_main(char* elf_base,long new_function_vaddr,cJSON* config){
    logger("modify_call_libc_start_main\n");
    char* libc_start_main_start_call_offset_str = cJSON_GetObjectItem(config,"libc_start_main_start_call_offset")->valuestring;
    char* libc_start_main_start_call_vaddr_str = cJSON_GetObjectItem(config,"libc_start_main_start_call_vaddr")->valuestring;
    long libc_start_main_start_call_offset = 0;
    long libc_start_main_start_call_vaddr = 0;
    puts(libc_start_main_start_call_offset_str);
    puts(libc_start_main_start_call_vaddr_str);
    libc_start_main_start_call_offset = strtol(libc_start_main_start_call_offset_str,NULL,16);
    libc_start_main_start_call_vaddr = strtol(libc_start_main_start_call_vaddr_str,NULL,16);
    if(libc_start_main_start_call_offset == 0 || libc_start_main_start_call_vaddr == 0){
        logger("libc_start_main_start_call_offset or libc_start_main_start_call_vaddr get error, check it\n");
        exit(-1);
    }
    unsigned char* call = (unsigned char*)(elf_base+libc_start_main_start_call_offset);
    char* libc_start_main_addr_type = cJSON_GetObjectItem(config,"libc_start_main_addr_type")->valuestring;
    if(strcmp(libc_start_main_addr_type,"code")==0){
        switch(((Elf_Ehdr*)elf_base)->e_machine){
            case EM_386:
            case EM_X86_64:
                if((call[0] == 0xE8) || (call[0] == 0x67 && call[1] == 0xE8)){
                    if(call[0]==0xE8){
                        call[0] = 0xE8;
                        *((int*)(&call[1])) = (int)(new_function_vaddr - 5 - libc_start_main_start_call_vaddr) ;
                    }else{
                        *((int*)(&call[2])) = (int)(new_function_vaddr - 6 - libc_start_main_start_call_vaddr) ;
                    }
                }
                else{
                    logger("libc_start_main_addr_type check failed, error, call addr bytes:%x,%x,%x,%x,%x",call[0],call[1],call[2],call[3],call[4]);
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



    }
    else if(strcmp(libc_start_main_addr_type,"ptr")==0){

        switch(((Elf_Ehdr*)elf_base)->e_machine){
            case EM_386:
                if(call[0] == 0xff && call[1] == 0x15){
                    call[0] = 0xE8;
                    *((int*)(&call[1])) = (int)(libc_start_main_start_call_vaddr) ;
                }
                else{
                    logger("libc_start_main_addr_type check failed, error, call addr bytes:%x,%x,%x,%x,%x,%x",call[0],call[1],call[2],call[3],call[4],call[5]);
                    exit(-1);
                }
                break;
            case EM_X86_64:
                if(call[0] == 0xff && call[1] == 0x15){
                    call[0] = 0xE8;
                    *((int*)(&call[1])) = (int)(new_function_vaddr - 5 - libc_start_main_start_call_vaddr) ;
                }
                else{
                    logger("libc_start_main_addr_type check failed, error, call addr bytes:%x,%x,%x,%x,%x,%x",call[0],call[1],call[2],call[3],call[4],call[5]);
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
    }
    else{
        logger("modify_call_libc_start_main : libc_start_main_addr_type has only two values, one is code, another is ptr\n");
        exit(-1);
    }
}

void add_stage_one_code_to_eh_frame(char* libloader_stage_one,char* output_elf,int* first_entry_offset,void** elf_load_base,cJSON* config){
    puts("add_stage_one_code_to_eh_frame");
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
        logger("libloader_stage_one should not have rodata section, change compile flags:\n");
        exit(-1);
    }
    get_section_data((Elf_Ehdr*)libloader_stage_one_base,".text",(void**)&buf,&len);
    if(buf==NULL || len==0){
        logger("libloader_stage_one should have text section, but we can not find it:\n");
        exit(-1);
    }
    Elf_Shdr* eh_frame_shdr = get_elf_section_by_name(".eh_frame",output_elf_base);
    if(eh_frame_shdr==NULL){
        logger("file:%s have no eh_frame, change first stage code to another place\n",output_elf);
        exit(-1);
    }
    if(eh_frame_shdr->sh_size < len){
        logger("file:%s eh_frame section is too small, change first stage code to another place\n",output_elf);
        exit(-1);
    }

    Elf_Shdr* libloader_stage_one_text_section = get_elf_section_by_name(".text",(Elf_Ehdr*)libloader_stage_one_base);

    *elf_load_base = (void*)get_elf_load_base((Elf_Ehdr*)output_elf_base);
    *first_entry_offset = (int)((unsigned long)eh_frame_shdr->sh_addr - (unsigned long)*elf_load_base) + ((Elf_Ehdr*)libloader_stage_one_base)->e_entry - libloader_stage_one_text_section->sh_addr;
    memcpy((char*)output_elf_base+eh_frame_shdr->sh_offset,buf,len);
    logger("copy end\n");
    cJSON *tmp = cJSON_GetObjectItem(config, "libc_start_main_addr_type");
    if(tmp) logger("%s\n",tmp->valuestring);

    //logger("%s\n",cJSON_GetObjectItem(config, "scu_init_mov_vaddr")->valuestring);
    /*
    if(cJSON_GetObjectItem(config, "libc_start_main_addr_type")){
        modify_call_libc_start_main(output_elf_base,(long) ((char*)*elf_load_base+ *first_entry_offset ),config);
    }else if(cJSON_GetObjectItem(config, "scu_init_mov_vaddr")){
        modify_mov_scu_init(output_elf_base, (long)((char*)*elf_load_base+ *first_entry_offset), config);
    }else if(cJSON_GetObjectItem(config, "entry_point")){
        modify_entry_point(output_elf_base, (long)((char*)*elf_load_base+ *first_entry_offset), config);
    }
    */

    //((Elf_Ehdr*)output_elf_base)->e_entry =(long) ((char*)*elf_load_base+ *first_entry_offset);
    close_and_munmap(libloader_stage_one,libloader_stage_one_fd,libloader_stage_one_base,&libloader_stage_one_size);
    close_and_munmap(output_elf,output_elf_fd,output_elf_base,&output_elf_size);
    logger("mod end\n");
}

void add_stage_one_code_to_text(char* libloader_stage_one,char* output_elf,int* first_entry_offset,void** elf_load_base,cJSON* config){
    puts("add_stage_one_code_to_text\n");
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
        logger("libloader_stage_one should not have rodata section, change compile flags:\n");
        exit(-1);
    }
    get_section_data((Elf_Ehdr*)libloader_stage_one_base,".text",(void**)&buf,&len);
    if(buf==NULL || len==0){
        logger("libloader_stage_one should have text section, but we can not find it:\n");
        exit(-1);
    }

    Elf_Shdr* libloader_stage_one_text_section = get_elf_section_by_name(".text",(Elf_Ehdr*)libloader_stage_one_base);

    *elf_load_base = (void*)get_elf_load_base((Elf_Ehdr*)output_elf_base);
    *first_entry_offset = (int)(strtol(cJSON_GetObjectItem(config, "text_addr")->valuestring, NULL, 16) - (unsigned long)*elf_load_base) + ((Elf_Ehdr*)libloader_stage_one_base)->e_entry - libloader_stage_one_text_section->sh_addr;
    logger("first_entry_offset");
    memcpy((char*)output_elf_base + *first_entry_offset,buf,len);
    logger("copy end\n");

    //logger("%s\n",cJSON_GetObjectItem(config, "scu_init_mov_vaddr")->valuestring);
    if(cJSON_GetObjectItem(config, "libc_start_main_addr_type")){
        modify_call_libc_start_main(output_elf_base,(long) ((char*)*elf_load_base+ *first_entry_offset ),config);
    }else if(cJSON_GetObjectItem(config, "scu_init_mov_vaddr")){
        modify_mov_scu_init(output_elf_base, (long)((char*)*elf_load_base+ *first_entry_offset), config);
    }

    //((Elf_Ehdr*)output_elf_base)->e_entry =(long) ((char*)*elf_load_base+ *first_entry_offset);
    close_and_munmap(libloader_stage_one,libloader_stage_one_fd,libloader_stage_one_base,&libloader_stage_one_size);
    close_and_munmap(output_elf,output_elf_fd,output_elf_base,&output_elf_size);
    logger("mod end\n");
}



char* get_text_section_without_rodata(char* elf_file,int* len){
    int elf_file_fd;
    char* elf_file_base;
    long elf_file_size = 0;
    open_mmap_check(elf_file,O_RDONLY,(int*)&elf_file_fd,(void**)&elf_file_base,PROT_READ,MAP_PRIVATE,&elf_file_size);
    char* code_buf = NULL,*tmp_buf = NULL;
    get_section_data((Elf_Ehdr*)elf_file_base,".rodata",(void**)&tmp_buf,len);
    if(tmp_buf!=NULL || *len!=0){
        logger("libloader_stage_one should not have rodata section, change compile flags:\n");
        exit(-1);
    }
    get_section_data((Elf_Ehdr*)elf_file_base,".text",(void**)&tmp_buf,len);
    if(tmp_buf==NULL || *len==0){
        logger("libloader_stage_one should have text section, but we can not find it:\n");
        exit(-1);
    }
    code_buf = malloc(*len);
    memcpy(code_buf,tmp_buf,*len);
    close_and_munmap(elf_file,elf_file_fd,elf_file_base,&elf_file_size);
    return code_buf;
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



unsigned long add_content_to_elf_pt_load(char* output_elf,char* content,int length){
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
    return output_elf_load_base+output_file_size;
}


unsigned long add_file_content_to_elf_pt_load(char* output_elf,char* file_name){
    char* content = get_file_content(file_name);
    unsigned long file_contecnt_vaddr = add_content_to_elf_pt_load(output_elf,content,get_file_size(file_name));
    free(content);
    return file_contecnt_vaddr;
}


//loader_stage_one_position has two values:
//one is eh_frame , means add first stage code to eh_frame section, you must insure the eh_frame is not use and has enough space(usual 300 byte is enough)
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
    logger("     : mode is: normal, sandbox\n");
    exit(-1);
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
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    int total_diassember_size = 100;
    unsigned char* call = NULL;
    unsigned char* mov = NULL;
    int time = 0;
    cJSON *v5 = cJSON_GetObjectItem(config, "v5");
    char *v5_method = v5->valuestring;
    int is_v5 = v5 ? 1 : 0;

    int count = cs_disasm(handle, start_function, total_diassember_size, start_function_vaddr, 0, &insn);
    int i = 0;
    for(i=0;i<count;i++){
        logger("0x%lx:\t%s\t\t%s\n", (long unsigned int)insn[i].address, insn[i].mnemonic,insn[i].op_str);
        if(is_v5 && !strncmp(v5_method, "libc_csu", 8)){
            cs_insn ins = insn[i];
            switch(((Elf_Ehdr*)output_elf_base)->e_machine){
                case EM_386:
                //pie开启的时候会call一个拿eip，不开启时候x32直接push地址
                    if(is_pie(output_elf_base)){
                        if(!strncasecmp(ins.mnemonic, "CALL", 5)){
                            logger("find one call : %s",ins.mnemonic);
                            goto out;
                        }
                    }else{
                        if(!strncasecmp(ins.mnemonic, "MOV", 4)){
                            logger("find one mov : %s",ins.mnemonic);
                            goto out;
                        }
                    }

                    break;
                case EM_X86_64:
                    if(!strncasecmp(ins.mnemonic, "MOV", 4) || !strncasecmp(ins.mnemonic, "LEA", 4)){
                        logger("find mov or lea: %s\n",ins.mnemonic);
                        time ++;
                        if(time == 4){
                            logger("find scu init mov %x %x\n",insn[i].bytes[0],insn[i].bytes[1]);
                            goto out;
                        }
                        cs_detail *detail = ins.detail;
                        if (detail->x86.op_count)
                            printf("\tNumber of operands: %u\n", detail->x86.op_count);
                        if (detail->x86.op_count == 2 && detail->x86.operands[1].type == X86_OP_MEM){
                            logger("disp: 0x%x\n",detail->x86.operands[1].mem.disp);
                        }
                        //cs_detail *detail = ins.detail;
                        //if(detail->x86.operands[0].type==X86_OP_MEM)logger("%x",detail->x86.operands[0].mem.disp);
                    }
                    break;
            }
        }else if(is_v5 && !strncmp(v5_method, "entry_point", 11)){
            //get at func start,just out
            goto out;
        }else{
            if(strncasecmp(insn[i].mnemonic,"CALL",5) ==0 || strncasecmp(insn[i].mnemonic,"BLX",4) ==0|| strncasecmp(insn[i].mnemonic,"BL",3) == 0){
                switch(((Elf_Ehdr*)output_elf_base)->e_machine){
                    case EM_386:
                        if(insn[i].bytes[0] == 0xE8 || (insn[i].bytes[0] == 0x67 && insn[i].bytes[1] == 0xE8 )){
                            unsigned long libc_start_main_addr = insn[i].address + insn[i].size + (long) (*(int*)(insn[i].bytes[0] == 0x67 ? (int*)&(insn[i].bytes[2]):(int*)&(insn[i].bytes[1])));
                            call = (unsigned char*)(output_elf_base + get_offset_by_vaddr(libc_start_main_addr,(Elf_Ehdr*)output_elf_base));

                        }else if(insn[i].bytes[0] == 0xff && insn[i].bytes[1] == 0x15){
                            unsigned long libc_start_main_addr = (unsigned long) *((int*)(&(insn[i].bytes[2])));
                            call = (unsigned char*)(output_elf_base + get_offset_by_vaddr(libc_start_main_addr,(Elf_Ehdr*)output_elf_base));
                        }
                        else{
                            logger("unknown x86 call instructions");
                            exit(-1);
                        }
                        break;
                    case EM_X86_64:
                        if(insn[i].bytes[0] == 0xE8 || (insn[i].bytes[0] == 0x67 && insn[i].bytes[1] == 0xE8 )){
                            unsigned long libc_start_main_addr = insn[i].address + insn[i].size + (long) (*(int*)(insn[i].bytes[0] == 0x67 ? (int*)&(insn[i].bytes[2]):(int*)&(insn[i].bytes[1])));
                            call = (unsigned char*)(output_elf_base + get_offset_by_vaddr(libc_start_main_addr,(Elf_Ehdr*)output_elf_base));

                        }else if(insn[i].bytes[0] == 0xff && insn[i].bytes[1] == 0x15){
                            unsigned long libc_start_main_addr = insn[i].address + insn[i].size +  (unsigned long) *((int*)(&(insn[i].bytes[2])));
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
        }
    }
    out:
    if(total_diassember_size <=0 ){
        logger("unable find call , something wrong in find_start_offset\n");
        exit(-1);
    }
    logger("out : mov[0]=%x\n", insn[i].bytes[0]);
    char buf[64] = {0};
    switch(((Elf_Ehdr*)output_elf_base)->e_machine){
        case EM_386:
            if(insn[i].bytes[0] == 0xe8 && is_v5 && !strncmp(v5_method, "libc_csu", 8) && is_pie(output_elf_base)){
                unsigned long eip = insn[i].address + insn[i].size;
                unsigned long ebx = insn[i+1].detail->x86.operands[1].imm + eip;
                time = 0;
                int j;
                for(j =i+1;j<count;j++){//从call开始搜索第二个mov/lea
                    if(!strncasecmp(insn[j].mnemonic, "LEA", 4) || !strncasecmp(insn[j].mnemonic, "MOV", 4)){
                        time ++;
                        if(time == 2){
                            logger("mov eax , scu_init get 0x%x\n", insn[j].address);
                            break;
                        }
                    }
                }
                unsigned long scu_init_addr = insn[j].detail->x86.operands[1].mem.disp + ebx;
                unsigned long scu_init_mov_vaddr = insn[j].address;
                unsigned long scu_init_mov_offset = get_offset_by_vaddr(scu_init_mov_vaddr, (Elf_Ehdr*)output_elf_base);
                sprintf(buf,"%p",(void*)scu_init_addr);
                cJSON_AddStringToObject(config, "scu_init_addr", buf);
                sprintf(buf,"%p",(void*)scu_init_mov_vaddr);
                cJSON_AddStringToObject(config, "scu_init_mov_vaddr", buf);
                sprintf(buf,"%p",(void*)scu_init_mov_offset);
                cJSON_AddStringToObject(config, "scu_init_mov_offset", buf);
                sprintf(buf,"%p",(void*)ebx);
                cJSON_AddStringToObject(config, "scu_init_ebx", buf);

                logger("identify scu_init_ebx:         %p\n",ebx);
                logger("identify scu_init_addr:       %p\n",scu_init_addr);
                logger("identify scu_init_mov_vaddr:  %p\n",scu_init_mov_vaddr);
                logger("identify scu_init_mov_offset: %p\n",scu_init_mov_offset);
                break;
            }else if(insn[i].bytes[0] == 0x89 && is_v5 && !strncmp(v5_method, "libc_csu", 8) && !is_pie(output_elf_base)){
                time = 0;
                int j;
                for(j = i+1;j<count;j++){//从mov开始搜索第五个push
                    if(!strncasecmp(insn[j].mnemonic, "PUSH", 5)){
                        time ++;
                        if(time == 5){
                            logger("push scu_init adrress get 0x%x\n", insn[j].address);
                            break;
                        }
                    }
                }
                unsigned long scu_init_mov_vaddr = insn[j].address;
                unsigned long scu_init_mov_offset = get_offset_by_vaddr(scu_init_mov_vaddr, (Elf_Ehdr*)output_elf_base);
                
                sprintf(buf,"%p",(void*)scu_init_mov_vaddr);
                cJSON_AddStringToObject(config, "scu_init_mov_vaddr", buf);
                sprintf(buf,"%p",(void*)scu_init_mov_offset);
                cJSON_AddStringToObject(config, "scu_init_mov_offset", buf);

                logger("identify scu_init_mov_vaddr:  %p\n",scu_init_mov_vaddr);
                logger("identify scu_init_mov_offset: %p\n",scu_init_mov_offset);
                break;
            }else if(is_v5 && !strncmp(v5_method, "entry_point", 11)){
                //just write anything about entry_pot
                cJSON_AddBoolToObject(config,"entry_point","lometsj");
                break;
            }


            if(insn[i].bytes[0] == 0xE8 || (insn[i].bytes[0] == 0x67 && insn[i].bytes[1] == 0xE8 )){
                unsigned long libc_start_main_addr = insn[i].address + insn[i].size + (long) (*(int*)(insn[i].bytes[0] == 0x67 ? (int*)&(insn[i].bytes[2]):(int*)&(insn[i].bytes[1])));
                unsigned long libc_start_main_start_call_vaddr = insn[i].address;
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

            }else if(insn[i].bytes[0] == 0xff && insn[i].bytes[1] == 0x15){
                unsigned long libc_start_main_addr = (unsigned long) *((int*)(&(insn[i].bytes[2])));
                unsigned long libc_start_main_start_call_vaddr = insn[i].address;
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
            }else{
                logger("unknown x86 call instructions");
                exit(-1);
            }
            break;

        case EM_X86_64:
            if(insn[i].bytes[0] == 0xE8 || (insn[i].bytes[0] == 0x67 && insn[i].bytes[1] == 0xE8 )){
                unsigned long libc_start_main_addr = insn[i].address + insn[i].size + (long) (*(int*)(insn[i].bytes[0] == 0x67 ? (int*)&(insn[i].bytes[2]):(int*)&(insn[i].bytes[1])));
                unsigned long libc_start_main_start_call_vaddr = insn[i].address;
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

            }else if(insn[i].bytes[0] == 0xff && insn[i].bytes[1] == 0x15){
                unsigned long libc_start_main_addr = (unsigned long) *((int*)(&(insn[i].bytes[2]))) +  insn[i].address + insn[i].size;
                unsigned long libc_start_main_start_call_vaddr = insn[i].address;
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
            }else if(insn[i].bytes[0] == 0x48){
                unsigned long rip = insn[i].address + insn[i].size;
                unsigned long disp = insn[i].detail->x86.operands[1].mem.disp;
                unsigned long scu_init_addr = rip + disp;
                unsigned long scu_init_mov_vaddr = insn[i].address;
                unsigned long scu_init_mov_offset = get_offset_by_vaddr(scu_init_mov_vaddr, (Elf_Ehdr*)output_elf_base);
                sprintf(buf,"%p",(void*)scu_init_addr);
                cJSON_AddStringToObject(config, "scu_init_addr", buf);
                sprintf(buf,"%p",(void*)scu_init_mov_vaddr);
                cJSON_AddStringToObject(config, "scu_init_mov_vaddr", buf);
                sprintf(buf,"%p",(void*)scu_init_mov_offset);
                cJSON_AddStringToObject(config, "scu_init_mov_offset", buf);
                logger("identify scu_init_addr:       %p\n",scu_init_addr);
                logger("identify scu_init_mov_vaddr:  %p\n",scu_init_mov_vaddr);
                logger("identify scu_init_mov_offset: %p\n",scu_init_mov_offset);
                
            }else if(is_v5 && !strncmp(v5_method, "entry_point", 11)){
                cJSON_AddBoolToObject(config,"entry_point","lometsj");

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


int main(int argc,char* argv[]){
    if(argc!=3){
        usage(argv[0]);
    }
    int phdr_has_moved = 0;
    char* mode = argv[2];
    if(strcmp(mode,"normal")!= 0 && strcmp(mode,"sandbox")!=0)
        usage(argv[0]);
    //chdir("/tmp");
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
    logger("config file: %s\n",config_file_name);

    logger("MODE : %s\n",mode);
    char* target_dir = cJSON_GetObjectItem(config,"target_dir")->valuestring;

    char* data_file = cJSON_GetObjectItem(config,"data_file_path")->valuestring;
    char data_file_path[512] = {0};
    snprintf(data_file_path,sizeof(data_file_path),"%s/%s/%s/%s",project_root,target_dir,mode,data_file);

    logger("data_file:%s\n",data_file_path);

    char* input_elf = cJSON_GetObjectItem(config,"input_elf")->valuestring;
    char input_elf_path [512] = {0};
    snprintf(input_elf_path,sizeof(input_elf_path),"%s/%s/%s",project_root,target_dir,input_elf);
    if(access(input_elf_path,R_OK)!= 0 ){
        logger("Input ELF not exist : %s\n",input_elf_path);
        exit(-1);
    }
    logger("input_elf: %s\n",input_elf_path);
    char output_elf_path [512] = {0};
    snprintf(output_elf_path,sizeof(output_elf_path),"%s/%s/%s/%s_%s",project_root,target_dir,mode,input_elf,mode);

    char stage_one[512] = {0};

    snprintf(stage_one,512,"%s/out/%s/stage_one",project_root,mode);
    logger("stage_one: %s\n",stage_one);

    check_libloader_stage_one(stage_one);
    copy_file(input_elf_path,output_elf_path);
    void* elf_load_base = NULL;
    int first_entry_offset = 0;
    process_start_function(output_elf_path,config);
    char* loader_stage_one_position = cJSON_GetObjectItem(config,"loader_stage_one_position")->valuestring;
    {
        if (strcmp("eh_frame", loader_stage_one_position) == 0) {
            add_stage_one_code_to_eh_frame(stage_one, output_elf_path, &first_entry_offset,&elf_load_base,config);
        } else if (strcmp("new_pt_load", loader_stage_one_position) == 0) {
            mov_phdr(output_elf_path);
            phdr_has_moved = 1;
            add_stage_one_code_to_new_pt_load(stage_one, output_elf_path, &first_entry_offset,&elf_load_base,config);
        } else if (strcmp("text", loader_stage_one_position) == 0){
            add_stage_one_code_to_text(stage_one, output_elf_path, &first_entry_offset,&elf_load_base,config);
        }
        else {
            logger("unsupport loader_stage_one_position: %s\n", loader_stage_one_position);
            exit(-1);
        }
    }

    char* loader_stage_other_position = cJSON_GetObjectItem(config,"loader_stage_other_position")->valuestring;
    if(strcmp("file",loader_stage_other_position)==0){
        //Nothing Need to do
    }
    else if(strcmp("memory",loader_stage_other_position)==0){
        if(!phdr_has_moved) {
            mov_phdr(output_elf_path);
        }
        add_file_content_to_elf_pt_load(output_elf_path,data_file_path);
    }
    else if(strcmp("share_memory",loader_stage_other_position)==0){
        //Nothing Need to do
    }
    else if(strcmp("socket",loader_stage_other_position)==0){
        //Nothing Need to do
    }
    else{
        logger("unsupport loader_stage_other_position: %s\n",loader_stage_other_position);
        exit(-1);
    }
    char tmp_buf[530];
    snprintf(tmp_buf,sizeof(tmp_buf),"chmod +x %s",output_elf_path);
    system(tmp_buf);
    logger("generate done\n");
    logger("-------------------------------------------------------------------------------------------------------------\n");
}
