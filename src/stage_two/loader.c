#include <stddef.h>
#include "errno.h"
#include <elf.h>
#include <stdarg.h>
#include "include/hook.h"

#include "debug_config.h"
#include "utils/common.h"


#if PATCH_DEBUG
#define DEBUG_LOG(STR)  do{char data[] = {STR "\n"};my_write_stdout(data);}while(0)
#else
#define DEBUG_LOG(format,...)
#endif


void _start(LIBC_START_MAIN_ARG,LOADER_STAGE_TWO* two_base){
    DEBUG_LOG("stage_two_start");
    Elf_Ehdr* ehdr = (Elf_Ehdr*)((char*)two_base+sizeof(LOADER_STAGE_TWO)+two_base->length + sizeof(LOADER_STAGE_THREE));
    LOADER_STAGE_THREE* three_base = (LOADER_STAGE_THREE*)((char*)two_base+sizeof(LOADER_STAGE_TWO)+two_base->length);
    three_base->patch_data_mmap_file_base = (void*)two_base;
    //todo elf_load_base should find an empty space, not just add 0x1000100
    char* stage_three_load_base = (char*)three_base->patch_data_mmap_file_base + 0x10001000 ;
    if(sizeof(void*)==8){
        stage_three_load_base = (char*)0x56780000;
    } else if(sizeof(void*)==4){
        stage_three_load_base = (char*)0x56780000;
    }

    unsigned char xor_data[] = {'\x45','\xf8','\x66','\xab','\x55'};
    unsigned char *encry_data = (unsigned char*)three_base + sizeof(LOADER_STAGE_THREE);
    for(int i=0;i<two_base->patch_data_length - sizeof(LOADER_STAGE_TWO) - two_base->length - sizeof(LOADER_STAGE_THREE);i++){
        encry_data[i] = encry_data[i] ^ xor_data[i%sizeof(xor_data)];
    }
    three_base->patch_data_mmap_code_base = stage_three_load_base;
    three_base->elf_load_base = two_base->elf_load_base;
    three_base->patch_data_length = two_base->patch_data_length;

    if( ((unsigned long)three_base->patch_data_mmap_code_base)%0x1000 != 0 ){
        DEBUG_LOG("patch_data_mmap_code_base is not 4K algin");
        return;
    }
    if( ((unsigned long)three_base->elf_load_base)%0x1000 != 0 ){
        DEBUG_LOG("elf_load_base is not 4K algin");
        return;
    }

#if PATCH_DEBUG== 1
    three_base->enable_debug = 1;
#endif
    long map_size = 0;
    long ret = 0;
    Elf_Phdr* phdr = NULL;
    int flag = 0;
    char* base_addr = (char*)ehdr;
    for(int i=0;i<ehdr->e_phnum;i++){
        flag = 0;
        phdr = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + ehdr->e_phentsize*i);
        if(phdr->p_type == PT_LOAD){
            if(phdr->p_flags & 0x1)
                flag |= PROT_EXEC;
            if(phdr->p_flags & 0x2)
                flag |= PROT_WRITE;
            if(phdr->p_flags & 0x4)
                flag |= PROT_READ;
            if((phdr->p_vaddr + phdr->p_memsz)%0x1000 == 0)
                map_size = phdr->p_vaddr + phdr->p_memsz  - DOWN_PADDING(phdr->p_vaddr,0x1000);
            else
                map_size = UP_PADDING(phdr->p_vaddr + phdr->p_memsz, 0x1000) - DOWN_PADDING(phdr->p_vaddr, 0x1000);
            ret = my_mmap( DOWN_PADDING(stage_three_load_base + phdr->p_vaddr,0x1000), map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if(ret < 0)
                return;
            my_memcpy((stage_three_load_base + phdr->p_vaddr), (base_addr + phdr->p_offset), phdr->p_filesz);
            ret = my_mprotect((void*)(DOWN_PADDING((long)stage_three_load_base + phdr->p_vaddr,0x1000)),map_size,flag);
            if(ret < 0)
                return;
        }
    }
    DEBUG_LOG("stage_two_end");
    void(*patch_entry)(LIBC_START_MAIN_ARG_PROTO,void*) = (void(*)(LIBC_START_MAIN_ARG_PROTO,void*))((char*)stage_three_load_base + three_base->entry_offset);
    patch_entry(LIBC_START_MAIN_ARG_VALUE,(void*)three_base);
}