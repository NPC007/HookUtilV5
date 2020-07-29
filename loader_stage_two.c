#include "hook.h"
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include "errno.h"
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <elf.h>

#include "utils/common.h"





void _start(LIBC_START_MAIN_ARG,void* first_instruction,LOADER_STAGE_TWO* two_base){
    DEBUG_LOG("stage_two_start");
    Elf_Ehdr* ehdr = (Elf_Ehdr*)((char*)two_base+sizeof(LOADER_STAGE_TWO)+two_base->length + sizeof(LOADER_STAGE_THREE));
    LOADER_STAGE_THREE* three_base = (LOADER_STAGE_THREE*)((char*)two_base+sizeof(LOADER_STAGE_TWO)+two_base->length);
    three_base->patch_data_mmap_file_base = (void*)two_base;
    //todo elf_load_base should find an empty space, not just add 0x1000100
    char* elf_load_base = (char*)three_base->patch_data_mmap_file_base + 0x10001000 ;

    unsigned char xor_data[] = {'\x45','\xf8','\x66','\xab','\x55'};
    unsigned char *encry_data = (unsigned char*)three_base + sizeof(LOADER_STAGE_THREE);
    for(int i=0;i<PATCH_DATA_MMAP_FILE_SIZE - sizeof(LOADER_STAGE_TWO) - two_base->length - sizeof(LOADER_STAGE_THREE);i++){
        encry_data[i] = encry_data[i] ^ xor_data[i%sizeof(xor_data)];
    }

    three_base->patch_data_mmap_code_base = elf_load_base;
    long map_size = 0;
    long ret = 0;
    Elf_Phdr* phdr = NULL;
    for(int i=0;i<ehdr->e_phnum;i++){
        phdr = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + ehdr->e_phentsize*i);
        if(phdr->p_type == PT_LOAD){
            int flag = 0;
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
            /*if(elf_load_base == NULL) {
                elf_load_base = (char*)my_mmap(0,map_size , PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if(elf_load_base == NULL || elf_load_base == (char*)-1)
                    return;
                elf_load_base = elf_load_base - DOWN_PADDING(phdr->p_vaddr,0x1000);
                three_base->patch_data_mmap_code_base = elf_load_base;
            }
            else*/
                {
                ret = my_mmap( DOWN_PADDING(elf_load_base + phdr->p_vaddr,0x1000), map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if(ret < 0)
                    return;
            }
            my_memcpy((elf_load_base + phdr->p_vaddr), ((char*)ehdr) + phdr->p_offset,phdr->p_filesz);
            ret = my_mprotect((void*)(DOWN_PADDING((long)elf_load_base + phdr->p_vaddr,0x1000)),map_size,flag);
            if(ret < 0)
                return;
        }
    }
    DEBUG_LOG("stage_two_end");
    void(*patch_entry)(LIBC_START_MAIN_ARG_PROTO,void*,void*) = (void(*)(LIBC_START_MAIN_ARG_PROTO,void*,void*))((char*)elf_load_base + three_base->entry_offset);
    patch_entry(LIBC_START_MAIN_ARG_VALUE,first_instruction,(void*)three_base);
}