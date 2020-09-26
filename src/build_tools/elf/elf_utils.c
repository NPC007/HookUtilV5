#include "elf_utils.h"
#include "../file/file_utils.h"

Elf_Phdr* get_elf_phdr_type(void* elf_base,int type){
    Elf_Ehdr* ehdr= (Elf_Ehdr*)elf_base;
    int j = 0;
    for(int i=0;i<ehdr->e_phnum;i++){
        Elf_Phdr* phdr = (Elf_Phdr*)((char*)ehdr+ehdr->e_phoff+ehdr->e_phentsize*i);
        if(phdr->p_type == type)
            return phdr;
    }
    return NULL;
}


Elf_Shdr* get_elf_section_by_index(long index,Elf_Ehdr* elf_base){
    Elf_Ehdr* ehdr = (Elf_Ehdr*) elf_base;
    Elf_Shdr* shdr = (Elf_Shdr*)((char*)elf_base + ehdr->e_shoff + index*ehdr->e_shentsize);
    return shdr;
}

Elf_Shdr* get_elf_shstrtab(Elf_Ehdr* elf_base){
    Elf_Ehdr* ehdr = (Elf_Ehdr*) elf_base;
    return get_elf_section_by_index(ehdr->e_shstrndx,elf_base);
}

Elf_Shdr* get_elf_section_by_type(int type,Elf_Ehdr* elf_base){
    Elf_Ehdr* ehdr = (Elf_Ehdr*) elf_base;
    int i = 0;
    Elf_Shdr* shstrtab_section = get_elf_shstrtab(elf_base);
    if(shstrtab_section == NULL)
        return NULL;
    char* strtab = (char*)((char*)elf_base + shstrtab_section->sh_offset);
    for(i=0;i<ehdr->e_shnum;i++){
        Elf_Shdr* shdr = (Elf_Shdr*)((char*)elf_base + ehdr->e_shoff + i*ehdr->e_shentsize);
        if(shdr->sh_type == type)
            return shdr;
    }
    return NULL;
}

Elf_Shdr* get_elf_section_by_name(char* section_name,Elf_Ehdr* elf_base){
    Elf_Ehdr* ehdr = (Elf_Ehdr*) elf_base;
    int i = 0;
    Elf_Shdr* shstrtab_section = get_elf_shstrtab(elf_base);
    if(shstrtab_section == NULL)
        return NULL;
    char* strtab = (char*)((char*)elf_base + shstrtab_section->sh_offset);
    for(i=0;i<ehdr->e_shnum;i++){
        Elf_Shdr* shdr = (Elf_Shdr*)((char*)elf_base + ehdr->e_shoff + i*ehdr->e_shentsize);
        if(strcasecmp((char*)&strtab[shdr->sh_name],section_name)==0)
            return shdr;
    }
    return NULL;
}

unsigned long get_offset_by_vaddr(unsigned long v_addr,Elf_Ehdr* elf_base){
    Elf_Ehdr *ehdr = elf_base;
    Elf_Phdr* pt_load;
    for(int i=0;i<ehdr->e_phnum;i++){
        pt_load = (Elf_Phdr*)((char*)ehdr+ ehdr->e_phoff + ehdr->e_phentsize*i);
        if(pt_load->p_type == PT_LOAD){
            if ((pt_load->p_vaddr <= v_addr) && (v_addr <= pt_load->p_vaddr + pt_load->p_filesz) )
                //printf("Convert Virtual Addr to File Offset: %p -> %p \n",(void*)v_addr ,(void*)(pt_load->p_offset + (v_addr - pt_load->p_vaddr)));
                return  pt_load->p_offset + (v_addr - pt_load->p_vaddr);
        }
    }
    printf("Convert Virtual Addr to File Offset failed\n");
    exit(0);
}

void get_section_data(Elf_Ehdr* ehdr,char* section_name,void** buf,int* len){
    Elf_Shdr* shdr = get_elf_section_by_name(section_name,ehdr);
    if(shdr == NULL){
        *buf = NULL;
        *len = 0;
        return;
    }
    *buf = (char*)((char*)ehdr + shdr->sh_offset );
    *len = shdr->sh_size;
}

void get_section_data_from_file(char* file,char* section_name,void** buf,int* len){
    int fd;
    char* base;
    long file_size = 0;
    open_mmap_check(file,O_RDONLY,&fd,(void**)&base,PROT_READ,MAP_PRIVATE,&file_size);
    Elf_Shdr* shdr = get_elf_section_by_name(section_name,(Elf_Ehdr*)base);
    if(shdr == NULL){
        *buf = NULL;
        *len = 0;
        return;
    }
    *buf = malloc(shdr->sh_size);
    *len = shdr->sh_size;
    memcpy(*buf,(char*)base + shdr->sh_offset,*len);
    close_and_munmap(file,fd,base,&file_size);
}


unsigned long get_elf_load_base(Elf_Ehdr *ehdr){
    unsigned long min_value = -1;
    Elf_Phdr* pt_load;
    for(int i=0;i<ehdr->e_phnum;i++){
        pt_load = (Elf_Phdr*)((char*)ehdr+ ehdr->e_phoff + ehdr->e_phentsize*i);
        if(pt_load->p_type == PT_LOAD){
            if(min_value == -1)
                min_value = DOWN_PADDING(pt_load->p_vaddr,0x1000);
            else{
                if(min_value >= DOWN_PADDING(pt_load->p_vaddr,0x1000))
                    min_value = DOWN_PADDING(pt_load->p_vaddr,0x1000);
            };
        }
    }
    return min_value;
}
unsigned long get_elf_file_load_base(char* elf_file){
    int elf_file_fd;
    char* elf_file_base;
    long elf_file_size = 0;
    open_mmap_check(elf_file,O_RDONLY,(int*)&elf_file_fd,(void**)&elf_file_base,PROT_READ,MAP_PRIVATE,&elf_file_size);
    return get_elf_load_base((Elf_Ehdr*)elf_file_base);
    close_and_munmap(elf_file,elf_file_fd,elf_file_base,&elf_file_size);
}

void _add_segment_desc(char* elf_base,Elf_Phdr* phdr){
    Elf_Ehdr* ehdr = (Elf_Ehdr*)elf_base;
    if(phdr->p_type == PT_PHDR || phdr->p_type == PT_INTERP){
        int i = 0;
        for(;i<ehdr->e_phnum;i++){
            Elf_Phdr* ori_phdr = (Elf_Phdr*)(elf_base + ehdr->e_phoff + i*ehdr->e_phentsize);
            if(ori_phdr->p_type == phdr->p_type){
                memcpy(ori_phdr,phdr,sizeof(Elf_Phdr));
                break;
            }
        }
        if(i==ehdr->e_phnum){
            printf("_add_segment_desc failed, unable to find ori seg, seg type:%d\n",phdr->p_type);
            return;
        }

    }
    else if(phdr->p_type == PT_LOAD) {
        memcpy(elf_base + ehdr->e_phoff + (ehdr->e_phnum * ehdr->e_phentsize), phdr, sizeof(Elf_Phdr));
        ehdr->e_phnum += 1;
    }
    else{
        printf("Unsupport phdr type:%d\n",phdr->p_type);
    }
}

void add_segment(char* elf_file,Elf_Phdr* phdr){
    if(phdr->p_type == PT_PHDR){
        printf("PT_PHDR can not add manual,it will auto done");
        exit(0);
    }
    int elf_file_fd;
    char* elf_file_base;
    long elf_file_size = 0;
    open_mmap_check(elf_file,O_RDWR,&elf_file_fd,(void**)&elf_file_base,PROT_READ|PROT_WRITE,MAP_SHARED,&elf_file_size);
    _add_segment_desc(elf_file_base,phdr);
    close_and_munmap(elf_file,elf_file_fd,elf_file_base,&elf_file_size);
}


#define MAX_SO_FILE_SIZE 0x1000000
void _padding_elf(char* elf_file_base,char *elf_file){

    int i=0,j=0;
    Elf_Ehdr * ehdr = (Elf_Ehdr *)elf_file_base;
    int* pt_load_phdr = (int*)malloc(sizeof(int)*ehdr->e_phnum);
    int pt_load_phdr_num = 0;
    long _ELF_BASE = 0;
    long _ELF_SIZE = 0;
    long _PHDR_PAGE_SIZE = 0x1000;
    long _PARAMS_PAGE_SIZE = 0x4000;
    printf("Assuming SO Max Size: 0x%x\n\n",MAX_SO_FILE_SIZE);
    Elf_Phdr* phdr;
    for(i=0;i<ehdr->e_phnum;i++){
        phdr = (Elf_Phdr*)((long)ehdr + ehdr->e_phoff + i* ehdr->e_phentsize);
        if(phdr->p_type == PT_LOAD){
            pt_load_phdr[pt_load_phdr_num] = i;
            pt_load_phdr_num ++ ;
        }
    }
    for(i=0;i<pt_load_phdr_num;i++)
        for(j=0;j<pt_load_phdr_num;j++){
            Elf_Phdr* phdr_i = (Elf_Phdr*)((long)ehdr + ehdr->e_phoff + pt_load_phdr[i]* ehdr->e_phentsize);
            Elf_Phdr* phdr_j = (Elf_Phdr*)((long)ehdr + ehdr->e_phoff + pt_load_phdr[j]* ehdr->e_phentsize);
            if(phdr_i->p_vaddr < phdr_j->p_vaddr){
                int temp = pt_load_phdr[i];
                pt_load_phdr[i] = pt_load_phdr[j];
                pt_load_phdr[j] = temp;
            }
        }

    phdr = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + pt_load_phdr[0]* ehdr->e_phentsize);
    printf("sort  by vaddr\n");
    for(i=0;i<pt_load_phdr_num;i++){
        Elf_Phdr* phdr_i = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + pt_load_phdr[i]* ehdr->e_phentsize);
        printf("vaddr:%16lx\tfile_offset:%16lx\tfile_size:%16lx\tmem_size:%16lx\n",(long)phdr_i->p_vaddr,(long)phdr_i->p_offset,(long)phdr_i->p_filesz,(long)phdr_i->p_memsz);
    }
    printf("sort  by vaddr end\n");
    long elf_file_size = get_file_size(elf_file);
    for(i=0;i<pt_load_phdr_num-1;i++){
        Elf_Phdr* phdr_i = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + pt_load_phdr[i]* ehdr->e_phentsize);
        Elf_Phdr* phdr_j = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + pt_load_phdr[i+1]* ehdr->e_phentsize);
        if(DOWN_PADDING(phdr_j->p_vaddr,0x1000)-UP_PADDING(phdr_i->p_vaddr+phdr_i->p_memsz,0x1000)> MAX_SO_FILE_SIZE)
            if(DOWN_PADDING(phdr_j->p_vaddr,0x1000)-UP_PADDING(phdr_i->p_vaddr + padding_size(elf_file_size),0x1000)> MAX_SO_FILE_SIZE){
                _ELF_SIZE = padding_size(elf_file_size);
                printf("find a space between %x and %x, space size is:%lx\n",i,i+1,DOWN_PADDING(phdr_j->p_vaddr,0x1000)-UP_PADDING(phdr_i->p_vaddr+phdr_i->p_memsz,0x1000));
            }
    }
    _ELF_BASE = phdr->p_vaddr - phdr->p_offset;
    if(_ELF_SIZE == 0){
        Elf_Phdr* phdr_first = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + pt_load_phdr[0]* ehdr->e_phentsize);
        Elf_Phdr* phdr_end = (Elf_Phdr*)((char*)ehdr + ehdr->e_phoff + pt_load_phdr[pt_load_phdr_num-1]* ehdr->e_phentsize);
        _ELF_SIZE = UP_PADDING(phdr_end->p_vaddr + phdr_end->p_memsz,0x1000) - DOWN_PADDING(phdr_first->p_vaddr,0x1000);
        if(_ELF_SIZE<=UP_PADDING(elf_file_size,0x1000))
            _ELF_SIZE = UP_PADDING(elf_file_size,0x1000);
        printf("unable to find any space between pt_load segments, just padding and append to file end\n");
    }
    increase_file(elf_file,_ELF_SIZE);
}

void padding_elf(char *elf_file){
    int elf_file_fd;
    char* elf_file_base;
    elf_file_fd = open(elf_file,O_RDONLY);
    if(elf_file_fd < 0){
        printf("unable open file: %s, error:%s\n",elf_file,strerror(errno));
        exit(-1);
    }
    long file_size = get_file_size(elf_file);
    if(file_size %0x1000 !=0)
        file_size = UP_PADDING(file_size,0x1000);
    elf_file_base = mmap(NULL,file_size,PROT_READ,MAP_PRIVATE,elf_file_fd,0);
    if(elf_file_base <= 0){
        printf("unable mmap file: %s, error:%s\n",elf_file,strerror(errno));
        exit(-1);
    }
    _padding_elf(elf_file_base,elf_file);
    munmap(elf_file_base,file_size);
    close(elf_file_fd);
}


void mov_phdr(char* elf_file){
    Elf_Ehdr *ehdr = (Elf_Ehdr*)get_file_content_length(elf_file,0,sizeof(Elf_Ehdr));
    int elf_file_fd;
    char* elf_file_base;
    padding_elf(elf_file);
    if(ehdr->e_phoff % 0x1000 != 0){
        free(ehdr);
        ehdr = NULL;
        increase_file(elf_file,get_file_size(elf_file)+0x1000);
        long elf_file_size = 0;
        open_mmap_check(elf_file,O_RDWR,&elf_file_fd,(void**)&elf_file_base,PROT_READ|PROT_WRITE,MAP_SHARED,&elf_file_size);
        ehdr = (Elf_Ehdr*)elf_file_base;
        memcpy(elf_file_base+get_file_size(elf_file)-0x1000,elf_file_base + ehdr->e_phoff,ehdr->e_phentsize*ehdr->e_phnum);
        ehdr->e_phoff = get_file_size(elf_file)-0x1000;
        Elf_Phdr phdr_pt_load_phdr;
        memset(&phdr_pt_load_phdr,0,sizeof(Elf_Phdr));
        phdr_pt_load_phdr.p_type = PT_LOAD;
        phdr_pt_load_phdr.p_align = 0x1000;
        phdr_pt_load_phdr.p_filesz = 0x1000;
        phdr_pt_load_phdr.p_flags = PF_R | PF_X;
        phdr_pt_load_phdr.p_memsz = 0x1000;
        phdr_pt_load_phdr.p_offset = get_file_size(elf_file)-0x1000;
        Elf_Phdr* first_pt_load_phdr;
        for(int i=0;i<ehdr->e_phnum;i++){
            first_pt_load_phdr = (Elf_Phdr*)(elf_file_base + ehdr->e_phoff +ehdr->e_phentsize*i);
            if(first_pt_load_phdr->p_type == PT_LOAD){
                phdr_pt_load_phdr.p_paddr = first_pt_load_phdr->p_paddr + get_file_size(elf_file)-0x1000;
                phdr_pt_load_phdr.p_vaddr = first_pt_load_phdr->p_vaddr + get_file_size(elf_file)-0x1000;
                break;
            }
        }
        if(phdr_pt_load_phdr.p_paddr == 0){
            printf("Unable to get PT_LOAD segment, must wrong\n");
            return;
        }
        printf("Add PHDR pt_load: vaddr:%16lx\tfile_offset:%16lx\n",(long)phdr_pt_load_phdr.p_paddr,(long)phdr_pt_load_phdr.p_offset);
        _add_segment_desc(elf_file_base,&phdr_pt_load_phdr);
        for(int i=0;i<ehdr->e_phnum;i++){
            Elf_Phdr* phdr_self_phdr = (Elf_Phdr*)(elf_file_base + ehdr->e_phoff + ehdr->e_phentsize*i);
            if(phdr_self_phdr->p_type == PT_PHDR){
                phdr_self_phdr->p_align = 0x1000;
                phdr_self_phdr->p_filesz = 0x1000;
                phdr_self_phdr->p_flags = PF_R | PF_X;
                phdr_self_phdr->p_memsz = 0x1000;
                phdr_self_phdr->p_offset = get_file_size(elf_file)-0x1000;
                phdr_self_phdr->p_paddr = first_pt_load_phdr->p_paddr + get_file_size(elf_file)-0x1000;
                phdr_self_phdr->p_vaddr = first_pt_load_phdr->p_paddr + get_file_size(elf_file)-0x1000;
                break;
            }
        }
        close_and_munmap(elf_file,elf_file_fd,elf_file_base,&elf_file_size);
    }
}

void check_elf_arch(char* file_name){
    Elf_Ehdr* ehdr = (Elf_Ehdr*)get_file_content_length(file_name,0,sizeof(Elf_Ehdr));
#ifdef __x86_64__
    if(ehdr->e_machine != EM_X86_64){
            printf("Arch not same, something wrong\n");
            exit(-1);
        }
#elif __i386__
    if(ehdr->e_machine != EM_386){
        printf("Arch not same, something wrong\n");
        exit(-1);
    }
#endif
}