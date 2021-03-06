#include <stddef.h>
#include "errno.h"
#include <elf.h>
#include <stdarg.h>
#include "include/hook.h"

#include "debug_config.h"
#include "arch/common/arch.h"
#include "stage_one_config.h"
#ifdef __arm__
#include "arch/common/syscall_arm.h"
#else
#include "arch/common/syscall.h"
#endif





// #if PATCH_DEBUG== 1
// #define DEBUG_LOG(format,...) my_debug_0("[DEBUG]:"format"\n",##__VA_ARGS__)

// #endif
#define DEBUG_LOG(format,...)
// #else
// #define DEBUG_LOG(format,...)
// #endif

/*
 * we must put _start at datafile first 4k size, because we use _start to get datafile mmap base;
 */


void _start(){

    unsigned long stack_base;

    DEBUG_LOG("stage_two_start");
    asm volatile("mov %%esp, %0":"=m"(stack_base)::);
    LOADER_STAGE_TWO* two_base = (LOADER_STAGE_TWO*)DOWN_PADDING((unsigned long)_start,0x1000);
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

#if(IS_PIE == 0)


#elif(IS_PIE == 1)
    unsigned long tmp_addr = (unsigned long)__builtin_return_address(0);
    two_base ->elf_load_base = (void*)DOWN_PADDING((tmp_addr - (unsigned long)(two_base ->elf_load_base)),0x1000);
    // two_base ->elf_load_base = rip - FIRST_ENTRY_OFFSET;
    DEBUG_LOG("load_base: 0x%x\n",two_base->elf_load_base);
#else
    #error "Unknown IS_PIE"
#endif


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

#if(PATCH_DEBUG == 1)
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
            #ifdef __arm__
            my_mmap_one( DOWN_PADDING(stage_three_load_base + phdr->p_vaddr,0x1000), map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            #else
            asm_mmap( DOWN_PADDING(stage_three_load_base + phdr->p_vaddr,0x1000), map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,ret);
            #endif
            if(ret < 0)
                return;
            for(int i=0;i<phdr->p_filesz;i++){
                ((char*)(stage_three_load_base + phdr->p_vaddr))[i] = ((char*)(base_addr + phdr->p_offset))[i];
            }
            #ifdef __arm__
            my_mprotect_one((void*)(DOWN_PADDING((long)stage_three_load_base + phdr->p_vaddr,0x1000)),map_size,flag);
            #else
            asm_mprotect((void*)(DOWN_PADDING((long)stage_three_load_base + phdr->p_vaddr,0x1000)),map_size,flag,ret);
            #endif
            if(ret < 0)
                return;
        }
    }
    DEBUG_LOG("stage_two_end");
    void(*patch_entry)(unsigned long,void*) = (void(*)(unsigned long, void*))((char*)stage_three_load_base + three_base->entry_offset);
    int ARGC=0;
    // while(UBP_AV[ARGC]!=NULL)
    //     ARGC ++;
    patch_entry(stack_base, (void*)three_base);
}

#if PATCH_DEBUG
/*int my_strlen(const char *src){
    int i = 0;
    while(src[i]!='\0')
        i++;
    return i;
}
void my_write_stdout(const char* str){
    long res;
    asm_write(1,str,my_strlen(str),res);
}*/
#else


#endif