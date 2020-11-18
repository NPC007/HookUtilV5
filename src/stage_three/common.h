#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdarg.h>
#include "errno.h"
#include <sys/select.h>
#include <elf.h>

#include "debug_config.h"

#include "include/hook.h"
#include "utils/md5.h"
#include "arch/common/syscall.h"
#include "utils/common.h"
#include "signal.h"
#include "utils/seccomp.h"

#define SHELL_LOG(format,...) my_debug_0("[DEBUG][SHELL]:"format"\n",##__VA_ARGS__)
#define DEBUG_LOG(format,...) my_debug_0("[DEBUG]:"format"\n",##__VA_ARGS__)

#if(PATCH_DEBUG == 1)
#define IN_LINE static

#else
#define IN_LINE static inline __attribute__((always_inline))
#endif




static char  SYSCALL_ALL_STR [][0x40] = {SYSCALL_ALL} ;





#define UN_KNOWN_ERROR_CODE 0xFF99FF99

#define MAX_PATCH_NUM 0x100

enum CODE_SLOT_TYPE{
    SLOT_GOT= 1,
    SLOT_FUNCTION,
    SLOT_CALL
};

typedef struct PATCH_CODE_SLOT{
    void* patch_addr;
    enum CODE_SLOT_TYPE slot_type;
    int hook_code_len;
    unsigned char hook_code[0x20];
    int code_slot_len;
    unsigned char code_slot[0x20];
    int old_code_save_len;
    unsigned char old_code_save[0x20];
}PATCH_CODE_SLOT;

static PATCH_CODE_SLOT* g_patch_code_slot;
static int g_patch_code_index;
static char* g_elf_base = 0;
static char g_elf_path[512] ;
static LOADER_STAGE_THREE g_loader_param;

enum SYSCALL_STATUS_ENUM{
    SYSCALL_NOT_INIT,
    SYSCALL_ENABLE,
    SYSCALL_DISABLE
};
static enum SYSCALL_STATUS_ENUM __syscall_enable_table[0x200];


#include "utils/snprintf_s.h"

static void my_debug_0(const char *format, ...){
    char buf[4096] = {0};
    if(g_loader_param.enable_debug) {
        va_list args;       //定义一个va_list类型的变量，用来储存单个参数
        va_start(args, format); //使args指向可变参数的第一个参数
        vsnprintf_s(buf,sizeof(buf),sizeof(buf),format,args);
        my_write_stdout(buf);
        va_end(args);
    }
}

static void shell_log(const char *format, ...){
    char buf[4096] = {0};
    if(1) {
        va_list args;       //定义一个va_list类型的变量，用来储存单个参数
        va_start(args, format); //使args指向可变参数的第一个参数
        vsnprintf_s(buf,sizeof(buf),sizeof(buf),format,args);
        my_write_stdout(buf);
        va_end(args);
    }
}







IN_LINE char* get_elf_base(){
    return g_elf_base;
}

IN_LINE PATCH_CODE_SLOT* search_patch_code_slot(void* key){
    int i = 0;
    if(g_patch_code_index < MAX_PATCH_NUM && g_patch_code_slot!=NULL){
        for(i=0;i<g_patch_code_index;i++){
            if(g_patch_code_slot[i].patch_addr == key)
                return &g_patch_code_slot[i];
        }
        return &g_patch_code_slot[g_patch_code_index++];
    }
    return NULL;
}

IN_LINE PATCH_CODE_SLOT* alloc_patch_code_slot(void* key){
    int i = 0;
    if(g_patch_code_index < MAX_PATCH_NUM && g_patch_code_slot!=NULL){
        for(i=0;i<g_patch_code_index;i++){
            if(g_patch_code_slot[i].patch_addr == key)
                return &g_patch_code_slot[i];
        }
        return &g_patch_code_slot[g_patch_code_index++];
    }
    return NULL;
}

IN_LINE void dealloc_patch_code_slot(){
    int i = 0;
    if(g_patch_code_index < MAX_PATCH_NUM && g_patch_code_slot!=NULL &&  g_patch_code_index>0){
        g_patch_code_index -- ;
    }
}
IN_LINE int is_pie(char* elf_base){
    Elf_Ehdr * ehdr = (Elf_Ehdr*) elf_base;
    if(ehdr->e_type == ET_EXEC)
        return 0;
    else if(ehdr->e_type == ET_DYN)
        return 1;
    return -1;
}


IN_LINE char* ELF_ADDR_ADD(char* elf_base,long p_vaddr){
    if(is_pie(elf_base))
        return elf_base + p_vaddr;
    else
        return (char*)p_vaddr;
}

IN_LINE int check_elf_magic(void* elf_base){
    int ret = ((*(char*)elf_base)=='\x7f' &&(*((char*)elf_base+1))=='E' && (*((char*)elf_base+2))=='L' && (*((char*)elf_base+3))=='F')?0:-1;
    return ret;
}

IN_LINE Elf_Dyn* get_elf_dyn_by_type(void* elf_base,int type){
    Elf_Ehdr* ehdr= (Elf_Ehdr*)elf_base;
    if(check_elf_magic(elf_base) == -1)
        return NULL;
    int j = 0;
    for(int i=0;i<ehdr->e_phnum;i++){
        Elf_Phdr* phdr = (Elf_Phdr*)((char*)ehdr+ehdr->e_phoff+ehdr->e_phentsize*i);
        switch (phdr->p_type)
        {
            case PT_DYNAMIC:
                j = 0;
                while(1){
                    Elf_Dyn* dyn = (Elf_Dyn*)(ELF_ADDR_ADD(elf_base,(long)phdr->p_vaddr+j*sizeof(Elf_Dyn)));
                    if(dyn->d_tag == type){
                        return dyn;
                    }
                    if(dyn->d_tag == 0)
                        break;
                    j++;
                }
                break;
            case PT_LOAD:
                break;
            default:
                break;
        }
    }
    return NULL;
}

IN_LINE void* get_elf_linkmap_from_plt_got(void* elf_base){
    Elf_Ehdr* ehdr= (Elf_Ehdr*)elf_base;
    if(check_elf_magic(elf_base) == -1)
        return NULL;
    int j = 0;
    for(int i=0;i<ehdr->e_phnum;i++){
        Elf_Phdr* phdr = (Elf_Phdr*)((char*)ehdr+ehdr->e_phoff+ehdr->e_phentsize*i);
        switch (phdr->p_type)
        {
            case PT_DYNAMIC:
                j = 0;
                while(1){
                    Elf_Dyn* dyn = (Elf_Dyn*)(ELF_ADDR_ADD(elf_base,(long)phdr->p_vaddr+j*sizeof(Elf_Dyn)));
                    if(dyn->d_tag == DT_PLTGOT){
                        if(dyn->d_un.d_ptr == 0)
                            return NULL;
                        if(dyn->d_un.d_ptr < 0x400000 )
                            return NULL;
                        struct link_map ** link = (struct link_map** )(dyn->d_un.d_ptr + sizeof(long));

                        if(link == NULL)
                            return NULL;
                        return *link;
                    }
                    if(dyn->d_tag == 0)
                        break;
                    j++;
                }
                break;
            case PT_LOAD:
                break;
            default:
                break;
        }
    }
    return NULL;
}

IN_LINE void* get_elf_linkmap_from_dt_debug(void* elf_base) {
    Elf_Dyn* dyn = get_elf_dyn_by_type(elf_base,DT_DEBUG);
    if(dyn == NULL)
        return NULL;
    struct r_debug* debug =  (struct r_debug*)dyn->d_un.d_val;
    if(debug == NULL)
        return NULL;
    return debug->r_map;
}

IN_LINE unsigned long dl_new_hash(const char *s)
{
    unsigned long h = 5381;
    unsigned char c;
    for (c = *s; c != '\0'; c = *++s)
        h = h * 33 + c;
    return h & 0xffffffff;
}

IN_LINE Elf_Sym *find_symbol_in_lib_fast(char *symbols,char * elf_base){
    unsigned int new_hash, h2;
    unsigned int hb1, hb2;
    unsigned int nbuckets, symndx, nmaskwords, shift2;
    unsigned long n;
    long addr;
    long bitmask_addr,hashbuckets_addr, hashvalues_addr;
    Elf_Dyn* dt_gnu_hash = get_elf_dyn_by_type(elf_base,DT_GNU_HASH);
    long sym_addr, hash_addr;
    long dynsym_addr,dynstr_addr;
    ElfW(Sym) sym;
    if(dt_gnu_hash == NULL)
        return NULL;
    if(get_elf_dyn_by_type(elf_base,DT_SYMTAB) == NULL)
        return NULL;
    if(get_elf_dyn_by_type(elf_base,DT_STRTAB) == NULL)
        return NULL;
    if(get_elf_dyn_by_type(elf_base,DT_GNU_HASH) == NULL)
        return NULL;
    if(dt_gnu_hash->d_un.d_val == 0 ){
        return NULL;
    }
    //bugs for linux_gate and vdso
    if(dt_gnu_hash->d_un.d_val<=FAKE_MIN_ADDR)
        return NULL;
    nbuckets = *(int*)(dt_gnu_hash->d_un.d_val);
    symndx = *(int*)(dt_gnu_hash->d_un.d_val + sizeof(unsigned int));
    nmaskwords = *(int*)(dt_gnu_hash->d_un.d_val + 2*sizeof(unsigned int));
    shift2 = *(int*)(dt_gnu_hash->d_un.d_val + 3*sizeof(unsigned int));
    bitmask_addr = (long)dt_gnu_hash->d_un.d_val + 4*sizeof(unsigned int);
    hashbuckets_addr = bitmask_addr + nmaskwords * sizeof(long);
    hashvalues_addr = hashbuckets_addr + nbuckets*sizeof(unsigned int);

    dynstr_addr = (long)get_elf_dyn_by_type(elf_base,DT_STRTAB)->d_un.d_val;
    dynsym_addr = (long)get_elf_dyn_by_type(elf_base,DT_SYMTAB)->d_un.d_val;
    new_hash = dl_new_hash(symbols);
    hb1 = new_hash & (__ELF_NATIVE_CLASS - 1);
    hb2 = (new_hash >> shift2) & (__ELF_NATIVE_CLASS - 1);
    n = (new_hash / __ELF_NATIVE_CLASS) & (nmaskwords - 1);
    /*
#if __ELF_NATIVE_CLASS == 64
        n = (new_hash >> 6) & (nmaskwords - 1);
#elif __ELF_NATIVE_CLASS == 32
        n = (new_hash >> 5) & (nmaskwords - 1);
#else
#error "unknown __ELF_NATIVE_CLASS"
#endif
     */
    addr = bitmask_addr + n * sizeof(long);
    long bitmask_word = *(long*)addr;
    if (((bitmask_word >> hb1) & (bitmask_word >> hb2) & 1) == 0)
        return NULL;
    addr = hashbuckets_addr + (new_hash % nbuckets) * sizeof(Elf_Symndx);
    //addr = hashbuckets_addr + (unsigned int)(divmod(new_hash ,nbuckets) * sizeof(Elf_Symndx));
    Elf_Symndx _symndx = *(Elf_Symndx*)addr;
    if (_symndx == 0)
        return NULL;
    sym_addr = dynsym_addr + _symndx * sizeof(ElfW(Sym));
    hash_addr = hashvalues_addr + (_symndx - symndx) * sizeof(unsigned int);
    do
    {
        h2 = *(unsigned int*)hash_addr;
        /*1. hash value same */
        if (((h2 ^ new_hash) >> 1) == 0)
        {
            sym_addr = dynsym_addr + ((symndx + (hash_addr - hashvalues_addr) / sizeof(Elf32_Word)) * sizeof(ElfW(Sym)));
            //sym_addr = dynsym_addr + ((symndx + (hash_addr - hashvalues_addr) >> 2) * sizeof(ElfW(Sym)));
            /*read ElfW(Sym) */
            my_memcpy((char*)&sym,(char*)sym_addr,sizeof(ElfW(Sym)));
            addr = dynstr_addr + sym.st_name;

            if (((char*)addr)[0]!='\x00' && (!my_strcmp((char*)addr, symbols)))
            {
                return (Elf_Sym*)sym_addr;
            }
        }
        hash_addr += sizeof(unsigned int);
    } while ((h2 & 1u) == 0); // search in same bucket
    return NULL;
}


IN_LINE void* find_symbol_in_lib_slow(char *symbols,char * elf_base){
    Elf_Dyn* strtab = get_elf_dyn_by_type(elf_base,DT_STRTAB);
    Elf_Dyn* symtab = get_elf_dyn_by_type(elf_base,DT_SYMTAB);
    Elf_Dyn* dt_strsz = get_elf_dyn_by_type(elf_base,DT_STRSZ);
    if(strtab == NULL || symtab == NULL || dt_strsz == NULL)
        return NULL;
    if(symtab->d_un.d_ptr<=FAKE_MIN_ADDR || strtab->d_un.d_ptr<=FAKE_MIN_ADDR)
        return NULL;
    long strtab_size = dt_strsz->d_un.d_val;
    int i = 0;
    while(1){
        Elf_Sym* sym = (Elf_Sym*)(symtab->d_un.d_ptr + i*sizeof(Elf_Sym));
        if(sym->st_name>=strtab_size)
            break;
        char* sym_name = (char*)&((char*)strtab->d_un.d_ptr)[sym->st_name];
        if(my_strcmp(sym_name,symbols)==0)
            return sym;
        i++;
    }
    return NULL;
}

IN_LINE void* find_symbol_in_mmap_file(char* symbols,char* elf_file_name){
    //my_debug_0("Start find Symbol:%s --> %s \n",symbols,elf_file_name);
    int i = 0, j = 0;
    void* result = NULL;
    int elf_file_handle = my_open(elf_file_name,O_RDONLY,0644);
    if(elf_file_handle < 0){
        my_debug_0("Unable to open file: %s for symbol: %s",elf_file_handle,symbols);
        return NULL;
    }
    void* elf_mmap_addr = (void*)my_mmap(0,0x1000000,PROT_READ, MAP_PRIVATE,elf_file_handle,0);
    if(elf_mmap_addr == NULL){
        my_debug_0("Unable to mmap file: %s for symbol: %s",elf_file_handle,symbols);
        return NULL;
    }

    Elf_Ehdr* elf_ehdr = ( Elf_Ehdr* )elf_mmap_addr ;
    unsigned char* tmp_symbol_name;
    int section_entry_size = elf_ehdr->e_shentsize;
    int section_entry_num = elf_ehdr->e_shnum;
    int section_file_offset = elf_ehdr->e_shoff;

    Elf_Shdr* lib_section_shdr;
    Elf_Shdr* lib_section_shdr_link;
    for(i=0;i<section_entry_num;i++){
        lib_section_shdr = ( Elf_Shdr*)((char*)elf_mmap_addr +section_file_offset+i * section_entry_size );
        if(lib_section_shdr->sh_type == SHT_DYNSYM || lib_section_shdr->sh_type == SHT_SYMTAB){
        }
        else
            continue;
        int link_section = lib_section_shdr->sh_link;
        if(link_section>=0){
            lib_section_shdr_link =( Elf_Shdr*)((char*)elf_mmap_addr +section_file_offset+link_section * section_entry_size );
        }
        else
            continue;
        int symbol_section_file_offset = lib_section_shdr->sh_offset;
        int symbol_section_file_entsize = lib_section_shdr->sh_entsize;
        int symbol_section_file_size = lib_section_shdr->sh_size;
        Elf_Sym* symbol ;
        for(j=0;j*symbol_section_file_entsize < symbol_section_file_size;j++){
            symbol = (Elf_Sym*)((char*)elf_mmap_addr + symbol_section_file_offset+j * symbol_section_file_entsize);
            if(symbol->st_value == 0)
                continue;
            int symbol_length = my_strlen(symbols);
            if(symbol_length>=98)
                break;
            int str_section_file_offset = lib_section_shdr_link->sh_offset;
            tmp_symbol_name = (char*)elf_mmap_addr + str_section_file_offset + symbol->st_name;
            if(my_strlen(tmp_symbol_name) < my_strlen(symbols))
                continue;
            //my_debug_0("compare: %s -- %s\n",tmp_symbol_name,symbols);
            if(my_strcmp(tmp_symbol_name,symbols) ==0 ) {
                result = (void *) ELF_ADDR_ADD(get_elf_base(), symbol->st_value);
                //my_debug_0("Success find Symbol:%s --> %s : 0x%lx \n",symbols,elf_file_name,(void*)result);
                goto out;
            }
            /*
            if(!(my_strcmp(read_symbol_name,symbols,symbol_length)==0))
                continue;
            if (read_symbol_name[symbol_length] == '@'&& read_symbol_name[symbol_length+1] == '@'){
                return st_value;
            }
             */
        }
    }
out:
    my_munmap(elf_mmap_addr,0x1000000);
    my_close(elf_file_handle);
    return result;
}


IN_LINE void* lookup_symbools_from_dynamic_symbol(char* symbols,void* elf_base){
    Elf_Sym* sym;
    void* sym_addr = NULL;
    sym = find_symbol_in_lib_fast(symbols,elf_base);
    if (sym) {
        sym_addr = sym->st_value + elf_base;
        return sym_addr;
    }
    /*
    sym = find_symbol_in_lib_slow(symbols,elf_base);
    if (sym) {
        sym_addr = sym->st_value + elf_base;
        return sym_addr;
    }*/
    return NULL;
}

IN_LINE void* lookup_symbols_in_elf(unsigned char* symbols,void* elf_base){
    int i = 0, j = 0;
    if(symbols==NULL || elf_base==NULL)
        return NULL;
    if(check_elf_magic(elf_base)==-1)
        return NULL;
    return lookup_symbools_from_dynamic_symbol(symbols,elf_base);
}

IN_LINE  void* lookup_symbols(char* symbol){
    struct link_map* map = get_elf_linkmap_from_plt_got(get_elf_base());
    if(map == NULL){
        map = get_elf_linkmap_from_dt_debug(get_elf_base());
    }
    if(map == NULL) {
        if(my_strlen(g_elf_path)!=0)
            return find_symbol_in_mmap_file(symbol,g_elf_path);
        return NULL;
    }
    while(map->l_prev!=NULL) map = map->l_prev;
    void* sym_addr = 0;
    char black_bin_list[][32] = {"linux-vdso","linux-gate","[vdso]"};
    int i = 0;
    int continue_flag = 0;
    while (!sym_addr && map){
        char* so_name = map->l_name;
        continue_flag = 0;
        if(so_name != NULL)
            for(i=0;i<sizeof(black_bin_list)/sizeof(black_bin_list[0]);i++)
                if(my_strstr(so_name,black_bin_list[i])!=NULL){
                    map = map->l_next;
                    continue_flag = 1;
                    break;
            }
        if(continue_flag)
            continue;
        if(map->l_addr == 0){
            map = map->l_next;
            continue;
        }
        sym_addr = (void*)lookup_symbols_in_elf(symbol,(char*)map->l_addr);
        if(sym_addr!=NULL) {
            return sym_addr;
        }
        map = map->l_next;
    }
    return NULL;
}

IN_LINE void* hook_address_helper(void* addr){
    if(is_pie(get_elf_base()))
        return (void*)((long)get_elf_base() + (long)addr);
    return addr;
}






static int get_errno(){
    return g_errno;
}

/*
static void my_printf(const char *format, ...)
{
    void(*vprintf_handler)(const char *,va_list) = lookup_symbols("vprintf");
    if(vprintf_handler!=NULL) {
        va_list args;       //定义一个va_list类型的变量，用来储存单个参数
        va_start(args, format); //使args指向可变参数的第一个参数
        vprintf_handler(format, args);  //必须用vprintf等带V的
        va_end(args);       //结束可变参数的获取
    }
    else{
        my_write_stdout(format);
    }
}*/


static void my_debug(const char *format, ...)
{
    if(g_loader_param.enable_debug) {
        void (*vprintf_handler)(const char *, va_list) = lookup_symbols("vprintf");
        if (vprintf_handler != NULL) {
            va_list args;       //定义一个va_list类型的变量，用来储存单个参数
            va_start(args, format); //使args指向可变参数的第一个参数
            vprintf_handler(format, args);  //必须用vprintf等带V的
            va_end(args);       //结束可变参数的获取
        } else {
            my_write_stdout(format);
        }
    }
}



IN_LINE void dynamic_hook_function(void* old_function,void* new_function,char* hook_name){
    PATCH_CODE_SLOT* slot = alloc_patch_code_slot(old_function);
    if(slot == NULL) {
        DEBUG_LOG("dynamic_hook_function: alloc hook slot failed");
        return;
    }
    long res = my_mprotect((void*)DOWN_PADDING((long)old_function,0x1000),0x1000,PROT_READ|PROT_WRITE|PROT_EXEC);
    if(res < 0) {
        DEBUG_LOG("dynamic_hook_function: mprotect RWX failed, addr: 0x%lx",DOWN_PADDING((long)old_function,0x1000));
        return;
    }
    slot->patch_addr = old_function;
#ifdef __x86_64__
    my_memcpy(slot->old_code_save,old_function,14);
    slot->old_code_save_len = 14;
    slot->code_slot_len = 14;
    slot->slot_type = SLOT_FUNCTION;

    slot->code_slot[0] = '\x68';
    *((unsigned int*)&(((unsigned char*)slot->code_slot) [1]))  = (unsigned int)((long)new_function&0xFFFFFFFF);
    *((unsigned int*)&(((unsigned char*)slot->code_slot) [5])) = 0x042444c7;
    *((unsigned int*)&(((unsigned char*)slot->code_slot) [9])) = (long)new_function>>32;
    ((unsigned char*)slot->code_slot) [13] = '\xc3';


    ((unsigned char*)old_function) [0] = '\x68';
    *((unsigned int*)&(((unsigned char*)old_function) [1]))  = (unsigned int)((long)slot->code_slot&0xFFFFFFFF);
    *((unsigned int*)&(((unsigned char*)old_function) [5])) = 0x042444c7;
    *((unsigned int*)&(((unsigned char*)old_function) [9])) = (long)slot->code_slot>>32;
    ((unsigned char*)old_function) [13] = '\xc3';
    slot->hook_code_len = 14;
    my_memcpy(slot->hook_code,old_function,slot->hook_code_len);

    DEBUG_LOG("Hook Success: 0x%lx --> 0x%lx: %s",old_function,new_function,hook_name);

    /*  ((unsigned char*)old_function) [0] = '\xE8';//call
      *((unsigned int*)&(((unsigned char*)old_function) [1]))   =  (unsigned int)(((long)slot->code_slot-(long)old_function - 5)&0xFFFFFFFF);
      slot->hook_code_len = 5;
      my_memcpy(slot->hook_code,old_function,slot->hook_code_len);*/

#elif __i386__
    my_memcpy(slot->old_code_save,old_function,5);
    slot->old_code_save_len = 5;
    slot->code_slot_len = 5;
    slot->slot_type = SLOT_FUNCTION;

    ((unsigned char*)slot->code_slot) [0] = '\xE9';//jmp
    *((unsigned int*)&(((unsigned char*)slot->code_slot) [1]))   =  (unsigned int)(((unsigned int)new_function-(unsigned int)slot->code_slot - 5)&0xFFFFFFFF);

    ((unsigned char*)old_function) [0] = '\xE9';//jmp
    *((unsigned int*)&(((unsigned char*)old_function) [1]))   =  (unsigned int)(((unsigned int)slot->code_slot-(unsigned int)old_function - 5)&0xFFFFFFFF);

    slot->hook_code_len = 5;
    my_memcpy(slot->hook_code,old_function,slot->hook_code_len);

    DEBUG_LOG("Hook Success: 0x%lx --> 0x%lx: %s",old_function,new_function,hook_name);
#elif __arm__

#elif __aarch64__

#elif __mips__

#endif
    res = my_mprotect((void*)DOWN_PADDING((long)old_function,0x1000),0x1000,PROT_READ|PROT_EXEC);
    if(res < 0) {
        DEBUG_LOG("dynamic_hook_function: mprotect RX failed, addr: 0x%lx",DOWN_PADDING((long)old_function,0x1000));
        return;
    }
}

IN_LINE void dynamic_hook_call(void* call_addr,void* new_function,char* hook_name){
    PATCH_CODE_SLOT* slot = alloc_patch_code_slot(call_addr);
    if(slot == NULL) {
        DEBUG_LOG("dynamic_hook_call: alloc hook slot failed");
        return;
    }
    long res = my_mprotect((void*)DOWN_PADDING((long)call_addr,0x1000),0x1000,PROT_READ|PROT_WRITE|PROT_EXEC);
    if(res < 0) {
        DEBUG_LOG("dynamic_hook_call: mprotect RWX failed, addr: 0x%lx",DOWN_PADDING((long)call_addr,0x1000));
        return;
    }
    slot->patch_addr = call_addr;
#ifdef __x86_64__
    if((long)slot->code_slot - (long)call_addr >= 100000000  || (long)slot->code_slot - (long)call_addr <= -100000000) {
        dealloc_patch_code_slot();
        DEBUG_LOG("failed to dynamic_hook_call,call_addr =%p, slot->code=%p, new_function=%p\n",call_addr,slot->code_slot,new_function);

    }
    my_memcpy(slot->old_code_save,call_addr,5);
    slot->old_code_save_len = 5;
    slot->code_slot_len = 14;
    slot->slot_type = SLOT_CALL;

    slot->code_slot[0] = '\x68'; //push && ret
    *((unsigned int*)&(((unsigned char*)slot->code_slot) [1]))  = (unsigned int)((long)new_function&0xFFFFFFFF);
    *((unsigned int*)&(((unsigned char*)slot->code_slot) [5])) = 0x042444c7;
    *((unsigned int*)&(((unsigned char*)slot->code_slot) [9])) = (long)new_function>>32;
    ((unsigned char*)slot->code_slot) [13] = '\xc3';

    ((unsigned char*)call_addr) [0] = '\xE8';//call
    *((unsigned int*)&(((unsigned char*)call_addr) [1]))   =  (unsigned int)(((long)slot->code_slot-(long)call_addr - 5)&0xFFFFFFFF);

    slot->hook_code_len = 5;
    my_memcpy(slot->hook_code,call_addr,slot->hook_code_len);
    DEBUG_LOG("Hook Success: 0x%lx --> 0x%lx :%s",call_addr,new_function,hook_name);


#elif __i386__
    my_memcpy(slot->old_code_save,call_addr,5);
    slot->old_code_save_len = 5;
    slot->code_slot_len = 5;
    slot->slot_type = SLOT_FUNCTION;

    ((unsigned char*)slot->code_slot) [0] = '\xE9';//jmp
    *((unsigned int*)&(((unsigned char*)slot->code_slot) [1]))   =  (unsigned int)(((unsigned int)new_function-(unsigned int)slot->code_slot - 5)&0xFFFFFFFF);

    ((unsigned char*)call_addr) [0] = '\xE8';//jmp
    *((unsigned int*)&(((unsigned char*)call_addr) [1]))   =  (unsigned int)(((unsigned int)slot->code_slot-(unsigned int)call_addr - 5)&0xFFFFFFFF);

    slot->hook_code_len = 5;
    my_memcpy(slot->hook_code,call_addr,slot->hook_code_len);

    DEBUG_LOG("Hook Success: 0x%lx --> 0x%lx: %s",call_addr,new_function,hook_name);
#elif __arm__

#elif __aarch64__

#elif __mips__

#endif
    res = my_mprotect((void*)DOWN_PADDING((long)call_addr,0x1000),0x1000,PROT_READ|PROT_EXEC);
    if(res < 0) {
        DEBUG_LOG("dynamic_hook_call: mprotect RX failed, addr: 0x%lx",DOWN_PADDING((long)call_addr,0x1000));
        return;
    }

}


IN_LINE void dynamic_hook_got(void* old_function,void* new_function,char *hook_name){

#ifdef __x86_64__
    PATCH_CODE_SLOT* slot = alloc_patch_code_slot(old_function);
    if(slot == NULL) {
        DEBUG_LOG("dynamic_hook_got: alloc hook slot failed");
        return;
    }
    long res = my_mprotect((void*)DOWN_PADDING((long)old_function,0x1000),0x1000,PROT_READ|PROT_WRITE|PROT_EXEC);
    if(res < 0) {
        DEBUG_LOG("dynamic_hook_got: mprotect RWX failed, addr: 0x%lx",DOWN_PADDING((long)old_function,0x1000));
        return;
    }
    slot->patch_addr = old_function;
    my_memcpy(slot->old_code_save,old_function,14);
    slot->old_code_save_len = 14;
    slot->code_slot_len = 14;
    slot->slot_type = SLOT_FUNCTION;

    slot->code_slot[0] = '\x68';
    *((unsigned int*)&(((unsigned char*)slot->code_slot) [1]))  = (unsigned int)((long)new_function&0xFFFFFFFF);
    *((unsigned int*)&(((unsigned char*)slot->code_slot) [5])) = 0x042444c7;
    *((unsigned int*)&(((unsigned char*)slot->code_slot) [9])) = (long)new_function>>32;
    ((unsigned char*)slot->code_slot) [13] = '\xc3';

    ((unsigned char*)old_function) [0] = '\xE8';//call
    *((unsigned int*)&(((unsigned char*)old_function) [1]))   =  (unsigned int)(((long)slot->code_slot-(long)old_function - 5)&0xFFFFFFFF);
    slot->hook_code_len = 5;
    my_memcpy(slot->hook_code,old_function,slot->hook_code_len);
    DEBUG_LOG("Hook Success: 0x%lx --> 0x%lx :%s",old_function,new_function,hook_name);
    ;
#else
    dynamic_hook_function(old_function,new_function,hook_name);
#endif
}



IN_LINE void dynamic_unhook(void* addr){
    PATCH_CODE_SLOT* slot = search_patch_code_slot(addr);
    if(slot!=NULL){
        DEBUG_LOG("dynamic_unhook: 0x%lx",addr);
        long res = my_mprotect((void*)DOWN_PADDING((long)addr,0x1000),0x1000,PROT_READ|PROT_WRITE|PROT_EXEC);
        if(res < 0) {
            return;
        }
        my_memcpy(addr,slot->old_code_save,slot->old_code_save_len);
        res = my_mprotect((void*)DOWN_PADDING((long)addr,0x1000),0x1000,PROT_READ|PROT_EXEC);
        if(res < 0) {
            return;
        }
    }
}
IN_LINE void dynamic_rehook(void* addr){
    PATCH_CODE_SLOT* slot = search_patch_code_slot(addr);
    if(slot!=NULL){
        DEBUG_LOG("dynamic_rehook: 0x%lx",addr);
        long res = my_mprotect((void*)DOWN_PADDING((long)addr,0x1000),0x1000,PROT_READ|PROT_WRITE|PROT_EXEC);
        if(res < 0) {
            return;
        }
        my_memcpy(addr,slot->hook_code,slot->hook_code_len);
        res = my_mprotect((void*)DOWN_PADDING((long)addr,0x1000),0x1000,PROT_READ|PROT_EXEC);
        if(res < 0) {
            return;
        }
    }
}




IN_LINE Elf_Shdr* get_elf_section_by_index(long index,char* elf_base){
    Elf_Ehdr* ehdr = (Elf_Ehdr*) elf_base;
    Elf_Shdr* shdr = (Elf_Shdr*)(elf_base + ehdr->e_shoff + index*ehdr->e_shentsize);
    return shdr;
}

IN_LINE Elf_Shdr* get_elf_shstrtab(char* elf_base){
    Elf_Ehdr* ehdr = (Elf_Ehdr*) elf_base;
    return get_elf_section_by_index(ehdr->e_shstrndx,elf_base);
}

IN_LINE Elf_Shdr* get_elf_section_by_name(char* section_name,char* elf_base){
    Elf_Ehdr* ehdr = (Elf_Ehdr*) elf_base;
    int i = 0;
    Elf_Shdr* shstrtab_section = get_elf_shstrtab(elf_base);
    if(shstrtab_section == NULL)
        return NULL;
    char* strtab = (char*)(elf_base + shstrtab_section->sh_offset);
    for(i=0;i<ehdr->e_shnum;i++){
        Elf_Shdr* shdr = (Elf_Shdr*)(elf_base + ehdr->e_shoff + i*ehdr->e_shentsize);
        if(my_strcasecmp((char*)&strtab[shdr->sh_name],section_name)==0)
            return shdr;
    }
    return NULL;
}


IN_LINE void process_got_hook(char* name,Elf_Sym* symbol,char* so_base){
    DEBUG_LOG("Process _hook_got_:  %s  Start\n",name);
    long old_plt_vaddr = 0;
    old_plt_vaddr = my_strtol(name,NULL,16);
    if(old_plt_vaddr == 0){
        DEBUG_LOG("Process _hook_got_:  %s  Failed , unable get vaddr of name\n",name);
        return;
    }
    old_plt_vaddr = (long) hook_address_helper((void*)old_plt_vaddr);
    char* new_addr = (char*)g_loader_param.patch_data_mmap_code_base+symbol->st_value;
    DEBUG_LOG("HOOK_GOT: 0x%lx --> 0x%lx",old_plt_vaddr,new_addr);
    dynamic_hook_got((void*)old_plt_vaddr,(void*)new_addr,name);
}

IN_LINE void process_elf_hook(char* symbol_name,Elf_Sym* symbol,char* so_base){
    DEBUG_LOG("Process _hook_elf_:  %s  Start\n",symbol_name);
    long need_modify_vaddr = my_strtol(symbol_name,NULL,16);
    if(need_modify_vaddr == 0){
        DEBUG_LOG("Process _hook_elf_:  %s  Failed , unable get vaddr of name\n",symbol_name);
        return;
    }
    need_modify_vaddr = (long)hook_address_helper((void*)need_modify_vaddr);
    char* new_addr = (char*)g_loader_param.patch_data_mmap_code_base+symbol->st_value;
    DEBUG_LOG("HOOK_ELF: 0x%lx --> 0x%lx",need_modify_vaddr,new_addr);
    dynamic_hook_function((void*)need_modify_vaddr,(void*)new_addr,symbol_name);

}

IN_LINE void process_call_hook(char* call_addr,Elf_Sym* symbol,char* so_base){
    DEBUG_LOG("Process _hook_call_:  %s  Start\n",call_addr);
    long need_modify_vaddr = my_strtol(call_addr,NULL,16);
    if(need_modify_vaddr == 0){
        DEBUG_LOG("Process _hook_call_:  %s  Failed , unable get vaddr of name\n",call_addr);
        return;
    }
    need_modify_vaddr = (long)hook_address_helper((void*)need_modify_vaddr);
    char* new_addr = (char*)g_loader_param.patch_data_mmap_code_base+symbol->st_value;
    DEBUG_LOG("HOOK_CALL: 0x%lx --> 0x%lx",need_modify_vaddr,new_addr);
    dynamic_hook_call((void*)need_modify_vaddr,(void*)new_addr,call_addr);
}


IN_LINE void process_hook(char* so_base){
    Elf_Shdr* symtab_section = get_elf_section_by_name(".symtab",(char*)so_base);
    long sym_offset = symtab_section->sh_offset;
    long sym_entsize = symtab_section->sh_entsize;
    long sym_size = symtab_section->sh_size;
    long sym_num = sym_size/sym_entsize;
    long sym_link = symtab_section->sh_link;
    Elf_Shdr* strtab_section = get_elf_section_by_index(sym_link,(char*)so_base);
    char* strtab = (char*)(so_base + strtab_section->sh_offset);
    int i = 0;
    for(i=0;i<sym_num;i++){
        Elf_Sym* symbol = (Elf_Sym*)(so_base + sym_offset + i*sym_entsize);
        char* symbol_name = (char*)(&strtab[symbol->st_name]);
        if(my_strncasecmp(symbol_name,"__hook_got_",my_strlen("__hook_got_"))==0)
            process_got_hook(&symbol_name[my_strlen("__hook_got_")],symbol,(char*)so_base);
        else if(my_strncasecmp(symbol_name,"__hook_elf_",my_strlen("__hook_elf_"))==0)
            process_elf_hook(&symbol_name[my_strlen("__hook_elf_")],symbol,(char*)so_base);
        else if(my_strncasecmp(symbol_name,"__hook_call_",my_strlen("__hook_call_"))==0)
            process_call_hook(&symbol_name[my_strlen("__hook_call_")],symbol,(char*)so_base);
        /*
        else if(strncasecmp(symbol_name,"__hook_start_",strlen("__hook_start_"))==0)
            process_start_hook(&symbol_name[strlen("__hook_start_")],symbol,file_desc,so_base);
            */
    }
}

/*
IN_LINE void dynamic_hook_process_execve(){
    char execve_str[] ={"execve"};
    void* hook_handler = (void*)__hook_dynamic_execve;
    char* execve_handler = lookup_symbols(execve_str);
    if(execve_handler==NULL)
        return;
    dynamic_hook_function(execve_handler,hook_handler);
}

IN_LINE void dynamic_hook_process_mmap(){
    char mmap_str[] ={"__mmap"};
    char* mmap_handler = lookup_symbols(mmap_str);
    if(mmap_handler==NULL)
        return;
}

 */


IN_LINE void init_hook_env(){
    g_patch_code_slot = (PATCH_CODE_SLOT*)my_mmap((long)(get_elf_base() - 0x100000),UP_PADDING(MAX_PATCH_NUM*sizeof(g_patch_code_slot),0x1000),PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    DEBUG_LOG("g_patch_code_slot is 0x%lx",g_patch_code_slot);
    if(g_patch_code_slot<=0) {
        g_patch_code_slot = NULL;
        g_patch_code_index = 0;
    }
    else{
        g_patch_code_index = 0;
    }
}

IN_LINE long my_write_packet(int fd,char* buf,long size){
    long res = my_write(fd,buf,size);
    return res;
}

IN_LINE void generate_random_str(char* buf ,int len){
    int i =0 ;
    char random_str[] = {"abcdefghijklmnopqrstuvwxyz"};
    int fd = my_open("/dev/urandom",O_RDONLY,0);
    unsigned char chr;
    if(fd> 0) {
        for (i = 0; i < len; i++) {
            my_read(fd,&chr,1);
            buf[i] = random_str[((unsigned int)chr)%26];
        }
        my_close(fd);
    }
    else{
        buf[0] = 'a';
    }
}


static char UUID[0x08];


IN_LINE void build_packet(char type,char* buf,int buf_len,char* packet,int* packet_len){
    my_memcpy(packet,UUID,sizeof(UUID));
    my_memcpy(packet+ sizeof(UUID),&type,1);
    my_memcpy(packet+sizeof(UUID)+1,(char*)&buf_len,4);
    my_memcpy(packet+sizeof(UUID)+1+4,buf,buf_len);
    *packet_len = sizeof(UUID)+1+4 + buf_len;
}

static void* __heap_base;
IN_LINE char* get_heap_base(){
    /*
    char* tmp_address = 0;
    void*(*malloc_handler)(int) = lookup_symbols("malloc");
    void (*free_handler)(void*) = lookup_symbols("free");
    if(malloc_handler!=NULL && free_handler!=NULL) {
        tmp_address = malloc_handler(0x600);
        if(tmp_address!=NULL) {
            free_handler(tmp_address);
            return (char*)((long)(tmp_address) - (long)tmp_address%0x1000);
        }
    }
    return 0;*/
    return (void*)__heap_base;
}

IN_LINE void init_heap_base(){
    __heap_base =  (void**)my_brk(0);
}

IN_LINE void destory_patch_data(){
#if(CONFIG_LOADER_TYPE == LOAD_FROM_FILE)
    my_munmap((void*)g_loader_param.patch_data_mmap_file_base,UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000));
#endif
}




IN_LINE int _test_syscall(int syscall_id){
#ifdef __x86_64__
    int ignore_syscall_ids[] = {__NR_read,__NR_write,__NR_open,__NR_close,__NR_reboot,__NR_shutdown,__NR_rt_sigreturn,__NR_pause,__NR_syslog,__NR_vhangup,__NR_shmat};
#elif __i386__
    int ignore_syscall_ids[] = {__NR_read,__NR_write,__NR_open,__NR_close,__NR_reboot,__NR_shutdown,__NR_rt_sigreturn,__NR_pause,__NR_syslog,__NR_vhangup,__NR_shmat};
#endif
    int res = 0;
    int stats = 0;
    for(int i=0;i<sizeof(ignore_syscall_ids)/sizeof(int);i++){
        if(ignore_syscall_ids[i] == syscall_id){
            SHELL_LOG("test syscall: %3d -> %32s , ignore",syscall_id,SYSCALL_ALL_STR[syscall_id]);
            return -1;
        }
    }
    int pid = my_fork();
    if(pid == 0){
        my_alarm(1);
        fd_set read_events;
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000;
        int rc = 0;
        int max_fd = 0;
        switch(syscall_id){
#ifdef __i386
            case __NR__newselect:
#elif __x86_64__
            case __NR_select:
#else
#error unsupport other arch
#endif
                FD_ZERO(&read_events);
                FD_SET(0, &read_events);
                my_select(max_fd + 1, &read_events, NULL, NULL, &timeout);
                break;
            default:
                asm_syscall_test(syscall_id,res);
        }

        my_exit_group(0);
    }else if(pid < 0){
        SHELL_LOG("test syscall: %3d -> %32s , fork failed",syscall_id,SYSCALL_ALL_STR[syscall_id]);
        return -1;
    }else{
        //my_sleep(200);
        if(my_waitpid(pid,(long)&stats,0)!=0){
            if(WIFEXITED(stats)) {
                SHELL_LOG("test syscall: %3d -> %32s , success,ret: %d", syscall_id, SYSCALL_ALL_STR[syscall_id],
                          WEXITSTATUS(stats));
                return 0;
            }
            else {
                SHELL_LOG("test syscall: %3d -> %32s , failed", syscall_id, SYSCALL_ALL_STR[syscall_id]);
                return -1;
            }
        }
        else{
            SHELL_LOG("test syscall: %3d -> %32s , wait failed",syscall_id,SYSCALL_ALL_STR[syscall_id]);
            return -1;
        }
    }
}


IN_LINE void init_syscall_enable_table(){
    my_memset((void*)__syscall_enable_table,-1,sizeof(__syscall_enable_table));
    for(int i=0;i<sizeof(__syscall_enable_table)/sizeof(__syscall_enable_table[0]);i++)
        __syscall_enable_table[i] = SYSCALL_NOT_INIT;
}

IN_LINE enum SYSCALL_STATUS_ENUM get_syscall_enable(int syscall_id){
    if(syscall_id >= sizeof(__syscall_enable_table)/sizeof(__syscall_enable_table[0])){
        DEBUG_LOG("Syscall ID is error: %d",syscall_id);
        return 0;
    }
    if(__syscall_enable_table[syscall_id] == SYSCALL_NOT_INIT){
        int ret = _test_syscall(syscall_id);
        if(ret == 0)
            __syscall_enable_table[syscall_id] = SYSCALL_ENABLE;
        else
            __syscall_enable_table[syscall_id] = SYSCALL_DISABLE;
    }
    return __syscall_enable_table[syscall_id];
}

IN_LINE enum SYSCALL_STATUS_ENUM get_select_syscall_enable(){
#ifdef __i386__
    int select_syscall = __NR__newselect;
#elif __x86_64__
    int select_syscall =__NR_select;
#else
#error Unsupport arch
#endif
    return get_syscall_enable(select_syscall);
}

static long __UNUSED_COUT;
IN_LINE void my_sleep(long milli_second){
    struct timespec slptm;
    long tmp = 0;
    long res = 0;
    slptm.tv_sec = milli_second >> 10;
    tmp = milli_second % 1000;
    slptm.tv_nsec = tmp * 1000000;
    if(get_syscall_enable(__NR_nanosleep)==SYSCALL_ENABLE) {
        asm_nanosleep((void *) &slptm, 0, res);
    }
    else{
        if(__UNUSED_COUT != 0)
            __UNUSED_COUT = 0;
        for(volatile long i=0;i<300000*milli_second;i++)
            res = res + 1;
    }
    tmp =res + 1;
    __UNUSED_COUT = tmp;
}


IN_LINE int my_copyfd(int old_fd,int new_fd){
    if(get_syscall_enable(__NR_dup2)==SYSCALL_ENABLE)
        return my_dup2(old_fd,new_fd);
    int tmp_fd[1024];
    int count = 0;
    if(get_syscall_enable(__NR_fcntl)==SYSCALL_ENABLE) {
        my_close(new_fd);
        int dup_fd = my_fcntl(old_fd, F_DUPFD, 0);
        while(dup_fd < new_fd && dup_fd >= 0){
            tmp_fd[count++] = dup_fd;
            dup_fd = my_fcntl(old_fd, F_DUPFD, 0);
        }
        if(dup_fd < 0){
            for(int i=0;i<count;i++)
                my_close(tmp_fd[i]);
            return -1;
        }
        if(dup_fd == new_fd){
            for(int i=0;i<count;i++)
                my_close(tmp_fd[i]);
            return dup_fd;
        }
        if(dup_fd > new_fd){
            DEBUG_LOG("DUP_FD is lagger than NEW_FD, something wrong");
            return -1;
        }
    }
    return -1;
}


IN_LINE int isconnected(int sockfd, fd_set *rd, fd_set *wr)
{
    if (!FD_ISSET(sockfd, rd) && !FD_ISSET(sockfd, wr)) {
        return 0;
    }
    int err = 0;
    socklen_t len = sizeof(err);
    if (my_getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
        return 0;
    }
    return err == 0;
}

// Return 1 on success, 0 on timeout and -1 on failed
IN_LINE int connect_timeout(int sockfd, const struct sockaddr *addr,
                                   socklen_t addrlen, struct timeval *timeout)
{
    int flags = my_fcntl( sockfd, F_GETFL, 0 );
    if (flags == -1) {
        return -1;
    }
    if (my_fcntl( sockfd, F_SETFL, flags | O_NONBLOCK ) < 0) {
        return -1;
    }

    int status = my_connect(sockfd, (void*)addr, addrlen);

    if (status == 0) {
        if (my_fcntl(sockfd, F_SETFL, flags) <  0) {
            return -1;
        }
        return 1;
    }
    my_sleep(timeout->tv_sec * 1000);
    status = my_connect(sockfd, (void*)addr, addrlen);
    if (status == 0) {
        if (my_fcntl(sockfd, F_SETFL, flags) <  0) {
            return -1;
        }
        return 1;
    }
    return 0;
}

// Return 1 on success, 0 on timeout and -1 on failed
IN_LINE int connect_timeout_unused(int sockfd, const struct sockaddr *addr,
                            socklen_t addrlen, struct timeval *timeout)
{
    int flags = my_fcntl( sockfd, F_GETFL, 0 );
    if (flags == -1) {
        return -1;
    }
    if (my_fcntl( sockfd, F_SETFL, flags | O_NONBLOCK ) < 0) {
        return -1;
    }

    int status = my_connect(sockfd, (void*)addr, addrlen);

    if (status == 0) {
        if (my_fcntl(sockfd, F_SETFL, flags) <  0) {
            return -1;
        }
        return 1;
    }
    fd_set read_events;
    fd_set write_events;
    FD_ZERO(&read_events);
    FD_SET(sockfd, &read_events);
    write_events = read_events;
    int rc = my_select(sockfd + 1, &read_events, &write_events, NULL, timeout );
    if (rc < 0) {
        return -1;
    } else if (rc == 0) {
        return 0;
    }
    if (!isconnected(sockfd, &read_events, &write_events) )
    {
        return -1;
    }
    if (my_fcntl( sockfd, F_SETFL, flags ) < 0 ) {
        return -1;
    }
    return 1;
}

IN_LINE void dump_program_info(LIBC_START_MAIN_ARG){
    DEBUG_LOG("MAIN at: %p",MAIN);
    DEBUG_LOG("ARGC   : %d",ARGC);
    DEBUG_LOG("UBP_AV : %p",UBP_AV);
    char **ev = &UBP_AV[ARGC + 1];
    int i = 0;
    char** argv = &UBP_AV[0];
    for(i=0;i<ARGC;i++){
        my_debug_0("argc[%d]=%s\n",i,argv[i]);
    }
    i = 0;
    while (ev[i] != NULL){
        DEBUG_LOG("ev[%d]=%p, %s",i,ev[i],ev[i]);
        i++;
    }
}




IN_LINE int common_init(LIBC_START_MAIN_ARG,LOADER_STAGE_THREE* three_base_tmp){
    g_elf_base = three_base_tmp->elf_load_base;
    init_heap_base();
    my_memcpy((char*)&g_loader_param,(const char*)three_base_tmp,sizeof(LOADER_STAGE_THREE));
    my_strcpy(g_elf_path,((char**)(&UBP_AV[0])) [0] ,0);
    DEBUG_LOG("stage_three_start");
    DEBUG_LOG("Version: %s %s",__DATE__,__TIME__);
    DEBUG_LOG("g_elf_base: 0x%lx",g_elf_base );
    DEBUG_LOG("patch_data_mmap_file_base: 0x%lx",three_base_tmp->patch_data_mmap_file_base);
    DEBUG_LOG("patch_data_mmap_code_base: 0x%lx",three_base_tmp->patch_data_mmap_code_base);
    if(g_elf_base == NULL){
        DEBUG_LOG("g_elf_base is NULL, Failed\n");
        return -1;
    }
    if(check_elf_magic(g_elf_base)==-1){
        DEBUG_LOG("g_elf_base is wrong,not elf header");
        //my_exit(-1);
        return -1;
    }
    dump_program_info(LIBC_START_MAIN_ARG_VALUE);
    init_syscall_enable_table();
    return 0;
}
