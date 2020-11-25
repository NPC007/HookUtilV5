#include "checker.h"
#include "../file/file_utils.h"
#include "../elf/elf_utils.h"

void check_so_file_no_rela_section(Elf_Ehdr* ehdr,char* file_name){
    for(int i=0;i<ehdr->e_phnum;i++) {
        Elf_Phdr *so_phdr = (Elf_Phdr *) ((long)ehdr + ehdr->e_phoff + i * ehdr->e_phentsize);
        if (so_phdr->p_type == PT_DYNAMIC) {
            Elf_Dyn* dyn = (Elf_Dyn*)((long)ehdr + so_phdr->p_offset);
            while (dyn->d_tag!=0){
                if(dyn->d_tag == DT_PLTGOT) {
                    logger("so file check error, should not have DT_PLTGOT : %s\n",file_name);
                    exit(-1);
                }
                else if(dyn->d_tag == DT_RELA || dyn->d_tag == DT_REL){
                    logger("so file check error, should not have DT_RELA or DT_REL: %s\n",file_name);
                    exit(-1);
                }
                else {
                    //logger("DT_TYPE: %8d\tDT_VALUE=%8d\n",dyn->d_tag,dyn->d_un.d_ptr);
                    dyn = (Elf_Dyn *) ((long) dyn + sizeof(Elf_Dyn));
                }
            }
        }
    }
}

void check_so_file_no_dynsym_section(Elf_Ehdr* ehdr){
    Elf_Shdr * shdr = get_elf_section_by_name(".dynsym",ehdr);
    if(shdr!=NULL){
        logger("check_so_file_no_dynsym_section failed\n");
        exit(-1);
    }
}


void check_so_file_no_rodata_section(Elf_Ehdr* ehdr){
    Elf_Shdr * shdr = get_elf_section_by_name(".rodata",ehdr);
    if(shdr!=NULL){
        logger("check_so_file_no_rodata_section failed\n");
        exit(-1);
    }
}

void check_so_file_no_data_section(Elf_Ehdr* ehdr){
    Elf_Shdr * shdr = get_elf_section_by_name(".data",ehdr);
    if(shdr!=NULL){
        logger("check_so_file_no_data_section failed\n");
        exit(-1);
    }
}

void check_so_file_no_got_section(Elf_Ehdr *ehdr){
    Elf_Shdr * shdr = get_elf_section_by_name(".got",ehdr);
    if(shdr!=NULL){
        logger("check_so_file_no_got_section failed\n");
        exit(-1);
    }
}

void check_so_file_no_gotplt_section(Elf_Ehdr *ehdr){
    Elf_Shdr * shdr = get_elf_section_by_name(".gotplt",ehdr);
    if(shdr!=NULL){
        logger("check_so_file_no_gotplt_section failed\n");
        exit(-1);
    }
}

void check_so_file_no_plt_section(Elf_Ehdr *ehdr){
    Elf_Shdr * shdr = get_elf_section_by_name(".plt",ehdr);
    if(shdr!=NULL){
        logger("check_so_file_no_plt_section failed\n");
        exit(-1);
    }
}

void check_so_file_no_bss_section(Elf_Ehdr *ehdr){
    Elf_Shdr * shdr = get_elf_section_by_name(".bss",ehdr);
    if(shdr!=NULL){
        logger("check_so_file_no_bss_section failed\n");
        exit(-1);
    }
}

void check_so_file_is_pie_execute_file(Elf_Ehdr *ehdr){
    if(get_elf_load_base(ehdr)!=0){
        logger("check_so_file_is_pie_execute_file failed, loader should be PIE compiled\n");
        exit(-1);
    }
}



void check_libloader_stage_three(char* libloader_stage_three){
    int libloader_stage_threefd;
    char* libloader_stage_three_base;
    long libloader_stage_three_size = 0;
    open_mmap_check(libloader_stage_three,O_RDONLY,&libloader_stage_threefd,(void**)&libloader_stage_three_base,PROT_READ,MAP_PRIVATE,&libloader_stage_three_size);
    check_so_file_no_rela_section((Elf_Ehdr*)libloader_stage_three_base,libloader_stage_three);
    check_so_file_is_pie_execute_file((Elf_Ehdr*)libloader_stage_three_base);
    close_and_munmap(libloader_stage_three,libloader_stage_threefd,libloader_stage_three_base,&libloader_stage_three_size);
}

void check_libloader_stage_two(char* libloader_stage_two){
    int libloader_stage_twofd;
    char* libloader_stage_two_base;
    long libloader_stage_two_size = 0;
    open_mmap_check(libloader_stage_two,O_RDONLY,&libloader_stage_twofd,(void**)&libloader_stage_two_base,PROT_READ,MAP_PRIVATE,&libloader_stage_two_size);
    logger("check %s start\n",libloader_stage_two);
    check_so_file_is_pie_execute_file((Elf_Ehdr*)libloader_stage_two_base);
    check_so_file_no_rela_section    ((Elf_Ehdr*)libloader_stage_two_base,libloader_stage_two);

    //check_so_file_no_dynsym_section  ((Elf_Ehdr*)libloader_stage_two_base);
    check_so_file_no_rodata_section  ((Elf_Ehdr*)libloader_stage_two_base);
    check_so_file_no_data_section    ((Elf_Ehdr*)libloader_stage_two_base);
    //check_so_file_no_got_section     ((Elf_Ehdr*)libloader_stage_two_base);
    check_so_file_no_gotplt_section  ((Elf_Ehdr*)libloader_stage_two_base);
    check_so_file_no_plt_section     ((Elf_Ehdr*)libloader_stage_two_base);
    check_so_file_no_bss_section     ((Elf_Ehdr*)libloader_stage_two_base);
    close_and_munmap(libloader_stage_two,libloader_stage_twofd,libloader_stage_two_base,&libloader_stage_two_size);
    logger("check %s end\n",libloader_stage_two);
}

void check_libloader_stage_one(char* libloader_stage_one){
    int libloader_stage_onefd;
    char* libloader_stage_one_base;
    long libloader_stage_one_size = 0;
    open_mmap_check(libloader_stage_one,O_RDONLY,&libloader_stage_onefd,(void**)&libloader_stage_one_base,PROT_READ,MAP_PRIVATE,&libloader_stage_one_size);
    logger("check %s start\n",libloader_stage_one);
    Elf_Shdr *text_section = get_elf_section_by_name(".text",(Elf_Ehdr*)libloader_stage_one_base);
    if(text_section == NULL){
        logger("stage_one failed to get text section");
        exit(-1);
    }
    if(text_section->sh_size >= 0x1000){
        logger("stage_one .text size must small than 0x1000");
        exit(-1);
    }
    check_so_file_is_pie_execute_file((Elf_Ehdr*)libloader_stage_one_base);
    check_so_file_no_rela_section    ((Elf_Ehdr*)libloader_stage_one_base,libloader_stage_one);
    //check_so_file_no_dynsym_section  ((Elf_Ehdr*)libloader_stage_one_base);
    check_so_file_no_rodata_section  ((Elf_Ehdr*)libloader_stage_one_base);
    check_so_file_no_data_section    ((Elf_Ehdr*)libloader_stage_one_base);
    switch(((Elf_Ehdr*)libloader_stage_one_base)->e_machine) {
        case EM_386:
            logger("when target is i386, ignore got check");
            break;
        default:
            check_so_file_no_got_section     ((Elf_Ehdr*)libloader_stage_one_base);
            break;
    }

    check_so_file_no_gotplt_section  ((Elf_Ehdr*)libloader_stage_one_base);
    check_so_file_no_plt_section     ((Elf_Ehdr*)libloader_stage_one_base);
    check_so_file_no_bss_section     ((Elf_Ehdr*)libloader_stage_one_base);
    close_and_munmap(libloader_stage_one,libloader_stage_onefd,libloader_stage_one_base,&libloader_stage_one_size);
    logger("check %s end\n",libloader_stage_one);
}
