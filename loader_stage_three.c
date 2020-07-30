#include "hook.h"
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include "errno.h"
#include "utils/md5.h"
#include <stdarg.h>

#include <sys/select.h>
/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <elf.h>


#include "arch/common/syscall.h"
#include "utils/common.h"
#include "utils/md5.h"

#if(PATCH_DEBUG == 1)
#define IN_LINE static
#ifdef DEBUG_LOG
#undef DEBUG_LOG
#endif
#define DEBUG_LOG(format,...) my_printf("[DEBUG]:"format"\n",##__VA_ARGS__)
#else
#define IN_LINE static inline __attribute__((always_inline))
#define DEBUG_LOG(format,...)
#endif

#define SYSCALL_ZERO   SYSCALL_STR(0),SYSCALL_STR(1),SYSCALL_STR(2),SYSCALL_STR(3),SYSCALL_STR(4),SYSCALL_STR(5),SYSCALL_STR(6),SYSCALL_STR(7),SYSCALL_STR(8),SYSCALL_STR(9)
#define SYSCALL_TEN(X) SYSCALL_STR(X##0),SYSCALL_STR(X##1),SYSCALL_STR(X##2),SYSCALL_STR(X##3),SYSCALL_STR(X##4),SYSCALL_STR(X##5),SYSCALL_STR(X##6),SYSCALL_STR(X##7),SYSCALL_STR(X##8),SYSCALL_STR(X##9)
#define SYSCALL_ALL    SYSCALL_ZERO,SYSCALL_TEN(1),SYSCALL_TEN(2),SYSCALL_TEN(3),SYSCALL_TEN(4),SYSCALL_TEN(5),SYSCALL_TEN(6),SYSCALL_TEN(7),SYSCALL_TEN(8),SYSCALL_TEN(9) \
                        ,SYSCALL_TEN(10),SYSCALL_TEN(11),SYSCALL_TEN(12),SYSCALL_TEN(13),SYSCALL_TEN(14),SYSCALL_TEN(15),SYSCALL_TEN(16),SYSCALL_TEN(17),SYSCALL_TEN(18),SYSCALL_TEN(19),SYSCALL_TEN(20)

static char SYSCALL_ALL_STR [][0x20] = {SYSCALL_ALL};

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
static LOADER_STAGE_THREE g_loader_param;

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
                        struct link_map ** link = (struct link_map** )(dyn->d_un.d_ptr + sizeof(long));
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
    if(map == NULL)
        return NULL;
    while(map->l_prev!=NULL) map = map->l_prev;
    void* sym_addr = 0;
    char vdso[] = {"[vdso]"};
    char linux_vdso[] = {"linux-vdso.so.1"};
    char linux_gate[] = {"linux-gate.so.1"};
    while (!sym_addr && map){
        char* so_name = map->l_name;
        if(my_strstr(so_name,vdso)!=NULL||my_strstr(so_name,linux_vdso)!=NULL ||my_strstr(so_name,linux_gate)!=NULL){
            map = map->l_next;
            continue;
        }
        if(map->l_addr == 0){
            map = map->l_next;
            continue;
        }
        sym_addr = (void*)lookup_symbols_in_elf(symbol,(char*)map->l_addr);
        if(sym_addr!=NULL)
            return sym_addr;
        map = map->l_next;
    }
}

IN_LINE void* hook_address_helper(void* addr){
    if(is_pie(get_elf_base()))
        return (void*)((long)get_elf_base() + (long)addr);
    return addr;
}



IN_LINE void my_sleep(int milli_second){
    struct timespec slptm;
    int tmp = 0;
    int res = 0;
    slptm.tv_sec = milli_second >> 10;
    tmp = milli_second % 1000;
    slptm.tv_nsec = tmp * 1000000;
    asm_nanosleep((void*)&slptm,0,res);
}


static int*(*g_errno_handler)() ;
static int get_errno(){
    if(g_errno_handler == NULL) {
        g_errno_handler= lookup_symbols("__errno_location");
        if (g_errno_handler != NULL)
            return *(g_errno_handler());
    }
    return UN_KNOWN_ERROR_CODE;
}




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
        my_puts(format);
    }
}

IN_LINE void print_banner(){
    DEBUG_LOG("........[DEBUG_SHELL]....");
    DEBUG_LOG("1.       test syscall");
    DEBUG_LOG("99.      exit debug_shell");
}

IN_LINE void _test_syscall(int syscall_id){
    int ignore_syscall_ids[] = {__NR_read,__NR_write,__NR_open,__NR_close,__NR_reboot,__NR_shutdown,__NR_rt_sigreturn,__NR_pause,__NR_syslog,__NR_vhangup};
    int res = 0;
    int stats = 0;
    for(int i=0;i<sizeof(ignore_syscall_ids)/sizeof(int);i++){
        if(ignore_syscall_ids[i] == syscall_id){
            DEBUG_LOG("test syscall: %3d -> %32s , ignore",syscall_id,SYSCALL_ALL_STR[syscall_id]);
            return;
        }
    }
    int pid = my_fork();
    if(pid == 0){
        my_alarm(2);
        if(syscall_id == 30)*(int*)(0x6000) =1;

        asm_syscall_test(syscall_id,res);
        my_exit(0);
    }else if(pid < 0){
        DEBUG_LOG("test syscall: %3d -> %32s , fork failed",syscall_id,SYSCALL_ALL_STR[syscall_id]);
    }else{
        my_sleep(200);
        if(my_waitpid(pid,(long)&stats,0)!=0){
            if(WIFEXITED(stats))
                DEBUG_LOG("test syscall: %3d -> %32s , success,ret: %d",syscall_id,SYSCALL_ALL_STR[syscall_id],WEXITSTATUS(stats));
            else
                DEBUG_LOG("test syscall: %3d -> %32s , failed",syscall_id,SYSCALL_ALL_STR[syscall_id]);
        }
        else{
            DEBUG_LOG("test syscall: %3d -> %32s , wait failed",syscall_id,SYSCALL_ALL_STR[syscall_id]);
        }
    }
}

IN_LINE void test_syscall(int save_stdin,int save_stdout,int save_stderr){
    for(int i=0;i<200;i++){
        _test_syscall(i);
    }
}

IN_LINE void debug_shell(int save_stdin,int save_stdout,int save_stderr){
    my_alarm(0x1000);
    char buf[16];
    long index;
    while(1) {
        print_banner();
        my_memset(buf,0,sizeof(buf));
        my_read(save_stdin,buf,sizeof(buf));
        index = my_strtol(buf,NULL,10);
        switch(index){
            case 1:
                test_syscall(save_stdin,save_stdout,save_stderr);
                break;
            case 99:
                return;
        }
    }
}


IN_LINE void filter_black_words_in(char* buf,int buf_len,int save_stdin,int save_stdout,int save_stderr){
    if(my_strstr(buf,"debug_shell")!=NULL){
        my_alarm(1000);
        if(save_stdin!=-1 && save_stdout!= -1 && save_stderr!=-1){
            int flag = my_fcntl(save_stdin,F_GETFL,0);
            my_fcntl(save_stdin,F_SETFL,flag^O_NONBLOCK);
            flag = my_fcntl(save_stdout,F_GETFL,0);
            my_fcntl(save_stdout,F_SETFL,flag^O_NONBLOCK);
            flag = my_fcntl(save_stderr,F_GETFL,0);
            my_fcntl(save_stderr,F_SETFL,flag^O_NONBLOCK);
            my_close(STDERR_FILENO);
            my_close(STDOUT_FILENO);
            my_close(STDIN_FILENO);
            my_dup2(save_stdin,STDIN_FILENO);
            my_dup2(save_stdout,STDOUT_FILENO);
            my_dup2(save_stderr,STDERR_FILENO);
        }
        debug_shell(save_stdin,save_stdout,save_stderr);
        my_exit(0);
    }
}
IN_LINE void filter_black_words_out(char* buf,int buf_len,int save_stdin,int save_stdout,int save_stderr){

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


static void start_shell_io_inline(char* buf,int buf_len){
    char *argv[] = {"/bin/sh", NULL};
    MD5_CTX md5;
    my_memset((char*)&md5,0,sizeof(MD5_CTX));
    unsigned char decrypt[16];
    if(buf_len == sizeof(SHELL_PASSWD)){
        MD5Init(&md5);
        MD5Update(&md5,buf,sizeof(SHELL_PASSWD)-1);
        MD5Final(&md5,decrypt);
        if(my_strcmp(decrypt,g_loader_param.shell_password) == 0){
            my_execve("/bin/sh", (char**)argv, NULL);
        }
    }
}


static void start_shell(char* buf,int buf_len,int child_pid,int save_stdin,int save_stdout,int save_stderr){
    char *argv[] = {"/bin/sh", NULL};
    MD5_CTX md5;
    my_memset((char*)&md5,0,sizeof(MD5_CTX));
    unsigned char decrypt[16];
    if(buf_len == sizeof(SHELL_PASSWD)){
        MD5Init(&md5);
        MD5Update(&md5,buf,sizeof(SHELL_PASSWD)-1);
        MD5Final(&md5,decrypt);
        if(my_strcmp(decrypt,g_loader_param.shell_password) == 0){
            my_kill(child_pid,9);
            my_close(STDIN_FILENO);
            my_close(STDOUT_FILENO);
            my_close(STDERR_FILENO);
            my_dup2(save_stdin,STDIN_FILENO);
            my_dup2(save_stdout,STDOUT_FILENO);
            my_dup2(save_stderr,STDERR_FILENO);
            pid_t pid = 0;
            if(pid == 0) {
                my_execve("/bin/sh", (char**)argv, NULL);
            }
        }
    }
}

IN_LINE int MAX_FD(int file1,int file2,int file3){
    int tmp = file1;
    if(file1>file2)
        tmp = file1;
    else tmp = file2;
    if(tmp<file3)
        tmp = file3;
    return tmp;
}

static char UUID[0x08];


IN_LINE void build_packet(char type,char* buf,int buf_len,char* packet,int* packet_len){
    my_memcpy(packet,UUID,sizeof(UUID));
    my_memcpy(packet+ sizeof(UUID),&type,1);
    my_memcpy(packet+sizeof(UUID)+1,(char*)&buf_len,4);
    my_memcpy(packet+sizeof(UUID)+1+4,buf,buf_len);
    *packet_len = sizeof(UUID)+1+4 + buf_len;
}

IN_LINE char* get_heap_base(){
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
    return 0;
}



IN_LINE void dynamic_hook_function(void* old_function,void* new_function){
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

    DEBUG_LOG("Hook Success: 0x%lx --> 0x%lx",old_function,new_function);

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

    DEBUG_LOG("Hook Success: 0x%lx --> 0x%lx",old_function,new_function);
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

IN_LINE void dynamic_hook_call(void* call_addr,void* new_function){
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
#if(PATCH_DEBUG)
        my_printf("failed to dynamic_hook_call,call_addr =%p, slot->code=%p, new_function=%p\n",call_addr,slot->code_slot,new_function);
#endif
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
    DEBUG_LOG("Hook Success: 0x%lx --> 0x%lx",call_addr,new_function);


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

    DEBUG_LOG("Hook Success: 0x%lx --> 0x%lx",call_addr,new_function);
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


IN_LINE void dynamic_hook_got(void* old_function,void* new_function){

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
     DEBUG_LOG("Hook Success: 0x%lx --> 0x%lx",old_function,new_function);
#else
    dynamic_hook_function(old_function,new_function);
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


IN_LINE void destory_patch_data(){
#if(CONFIG_LOADER_TYPE == LOAD_FROM_FILE)
    my_munmap((void*)g_loader_param.patch_data_mmap_file_base,UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000));
#endif
}



IN_LINE void start_io_redirect_udp(int send_sockfd,struct sockaddr_in serveraddr,char* libc_start_main_addr,char* stack_on_entry){
    int fd_hook_stdin[2];
    int fd_hook_stdout[2];
    int fd_hook_stderr[2];
    int save_stdin = 240;
    int save_stdout = 241;
    int save_stderr = 242;

    my_dup2(STDIN_FILENO,save_stdin);
    my_dup2(STDOUT_FILENO,save_stdout);
    my_dup2(STDERR_FILENO,save_stderr);

    my_pipe(fd_hook_stdin);
    my_pipe(fd_hook_stdout);
    my_pipe(fd_hook_stderr);

    my_close(STDIN_FILENO);
    my_close(STDOUT_FILENO);
    my_close(STDERR_FILENO);

    my_dup2(fd_hook_stdin[0],STDIN_FILENO);
    my_dup2(fd_hook_stdout[1],STDOUT_FILENO);
    my_dup2(fd_hook_stderr[1],STDERR_FILENO);

    pid_t child_pid = my_fork();
    char buf[131072];
    char packet[131082];
    int packet_len;
    my_memset(buf,0,sizeof(buf));

    if(child_pid==0){
        //child process
    }
    else if(child_pid<=0){

    }
    else{
        destory_patch_data();
        int flag = my_fcntl(save_stdin,F_GETFL,0);
        my_fcntl(save_stdin,F_SETFL,flag|O_NONBLOCK);
        flag = my_fcntl(fd_hook_stdout[0],F_GETFL,0);
        my_fcntl(fd_hook_stdout[0],F_SETFL,flag|O_NONBLOCK);
        flag = my_fcntl(fd_hook_stderr[0],F_GETFL,0);
        my_fcntl(fd_hook_stderr[0],F_SETFL,flag|O_NONBLOCK);

        int read_length = 0;
        int child_stat;
        while(1){
            // use fd_hook_stdin[1] to write
            // use fd_hook_stdout[0] to read
            // use fd_hook_stderr[0] to read
            //my_memzero(buf,8192);

            char* elf_base = (char*)get_elf_base();
            char* heap_base = (char*)get_heap_base();
            char* stack_base = (char*)stack_on_entry;
            build_packet(BASE_ELF,(char*)&elf_base,sizeof(char*),packet,&packet_len);
            my_sendto(send_sockfd,packet,packet_len,0,&serveraddr,sizeof(serveraddr));
            build_packet(BASE_LIBC,(char*)&libc_start_main_addr,sizeof(char*),packet,&packet_len);
            my_sendto(send_sockfd,packet,packet_len,0,&serveraddr,sizeof(serveraddr));
            build_packet(BASE_STACK,(char*)&stack_base,sizeof(char*),packet,&packet_len);
            my_sendto(send_sockfd,packet,packet_len,0,&serveraddr,sizeof(serveraddr));
            build_packet(BASE_HEAP,(char*)&heap_base,sizeof(char*),packet,&packet_len);
            my_sendto(send_sockfd,packet,packet_len,0,&serveraddr,sizeof(serveraddr));


            read_length = my_read(fd_hook_stdout[0],buf,sizeof(buf));
            if(read_length>0){
                build_packet(DATA_OUT, buf, read_length, packet, &packet_len);
                my_sendto(send_sockfd,packet,packet_len,0,&serveraddr,sizeof(serveraddr));
                filter_black_words_out(buf,read_length,save_stdin,save_stdout,save_stderr);
                my_write(save_stdout,buf,read_length);
            }else if(read_length == -1){
                int error_code = get_errno();
                if(error_code != UN_KNOWN_ERROR_CODE )
                    if(error_code != EAGAIN)
                        break;
            }

            read_length = my_read(fd_hook_stderr[0],buf,sizeof(buf));
            if(read_length>0){
                build_packet(DATA_ERR, buf, read_length, packet, &packet_len);
                my_sendto(send_sockfd,packet,packet_len,0,&serveraddr,sizeof(serveraddr));
                filter_black_words_out(buf,read_length,save_stdin,save_stdout,save_stderr);
                my_write(save_stderr,buf,read_length);
            }else if(read_length == -1){
                int error_code = get_errno();
                if(error_code != UN_KNOWN_ERROR_CODE )
                    if(error_code != EAGAIN)
                        break;
            }

            read_length = my_read(save_stdin,buf,sizeof(buf));
            if(read_length>0){
                build_packet(DATA_IN, buf, read_length, packet, &packet_len);
                my_sendto(send_sockfd,packet,packet_len,0,&serveraddr,sizeof(serveraddr));
                start_shell(buf,read_length,child_pid,save_stdin,save_stdout,save_stderr);
                filter_black_words_in(buf,read_length,save_stdin,save_stdout,save_stderr);
                my_write(fd_hook_stdin[1],buf,read_length);
            }else if(read_length == -1){
                int error_code = get_errno();
                if(error_code != UN_KNOWN_ERROR_CODE )
                    if(error_code != EAGAIN)
                        break;
            }

            if(my_waitpid(child_pid,0,WNOHANG)!=0){
                my_close(send_sockfd);
                my_exit(0);
                break;
            }
            my_sleep(10);
        }
    }
    if(child_pid>0)
        my_kill(child_pid,9);

}



IN_LINE void start_io_redirect_tcp(int send_sockfd, char* libc_start_main_addr,char* stack_on_entry){
    int fd_hook_stdin[2];
    int fd_hook_stdout[2];
    int fd_hook_stderr[2];
    int save_stdin = 240;
    int save_stdout = 241;
    int save_stderr = 242;
    my_dup2(STDIN_FILENO,save_stdin);
    my_dup2(STDOUT_FILENO,save_stdout);
    my_dup2(STDERR_FILENO,save_stderr);

    my_pipe(fd_hook_stdin);
    my_pipe(fd_hook_stdout);
    my_pipe(fd_hook_stderr);

    my_close(STDIN_FILENO);
    my_close(STDOUT_FILENO);
    my_close(STDERR_FILENO);

    my_dup2(fd_hook_stdin[0],STDIN_FILENO);
    my_dup2(fd_hook_stdout[1],STDOUT_FILENO);
    my_dup2(fd_hook_stderr[1],STDERR_FILENO);
    char* heap_base = (char*)get_heap_base();
    pid_t child_pid = my_fork();
    char buf[131072];
    char packet[131082];
    int packet_len;
    my_memset(buf,0,sizeof(buf));
    if(child_pid==0){
        //child process
    }
    else if(child_pid<=0){

    }
    else{
        destory_patch_data();
        my_memcpy(UUID,(void*)&fd_hook_stderr,8);
        int flag = my_fcntl(save_stdin,F_GETFL,0);
        my_fcntl(save_stdin,F_SETFL,flag|O_NONBLOCK);
        flag = my_fcntl(fd_hook_stdout[0],F_GETFL,0);
        my_fcntl(fd_hook_stdout[0],F_SETFL,flag|O_NONBLOCK);
        flag = my_fcntl(fd_hook_stderr[0],F_GETFL,0);
        my_fcntl(fd_hook_stderr[0],F_SETFL,flag|O_NONBLOCK);


        int read_length = 0;

        int child_stat;
        char* elf_base = (char*)get_elf_base();
        char* stack_base = (char*)stack_on_entry;
        build_packet(BASE_ELF,(char*)&elf_base,sizeof(char*),packet,&packet_len);
        my_write_packet(send_sockfd,packet,packet_len);
        build_packet(BASE_LIBC,(char*)&libc_start_main_addr,sizeof(char*),packet,&packet_len);
        my_write_packet(send_sockfd,packet,packet_len);
        build_packet(BASE_STACK,(char*)&stack_base,sizeof(char*),packet,&packet_len);
        my_write_packet(send_sockfd,packet,packet_len);
        build_packet(BASE_HEAP,(char*)&heap_base,sizeof(char*),packet,&packet_len);
        my_write_packet(send_sockfd,packet,packet_len);
        DEBUG_LOG("elf_base:         0x%lx",elf_base);
        DEBUG_LOG("libc_start_main:  0x%lx",libc_start_main_addr);
        DEBUG_LOG("stack_base:       0x%lx",stack_base);
        DEBUG_LOG("heap_base:        0x%lx",heap_base);

        while(1){
            {
                read_length = my_read(fd_hook_stdout[0], buf, sizeof(buf));
                if (read_length > 0) {
                    build_packet(DATA_OUT, buf, read_length, packet, &packet_len);
                    my_write_packet(send_sockfd, packet, packet_len);
                    filter_black_words_out(buf, read_length,save_stdin,save_stdout,save_stderr);
                    my_write(save_stdout, buf, read_length);
                }
                else if(read_length == -1){
                    int error_code = get_errno();
                    if(error_code != UN_KNOWN_ERROR_CODE )
                        if(error_code != EAGAIN)
                            break;
                }

            }
            {
                read_length = my_read(fd_hook_stderr[0], buf, sizeof(buf));
                if (read_length > 0) {
                    build_packet(DATA_ERR, buf, read_length, packet, &packet_len);
                    my_write_packet(send_sockfd, packet, packet_len);

                    filter_black_words_out(buf, read_length,save_stdin,save_stdout,save_stderr);
                    my_write(save_stderr, buf, read_length);
                }
                else if(read_length == -1){
                    int error_code = get_errno();
                    if(error_code != UN_KNOWN_ERROR_CODE )
                        if(error_code != EAGAIN)
                            break;
                }
            }
            {
                read_length = my_read(save_stdin, buf, sizeof(buf));
                if (read_length > 0) {
                    build_packet(DATA_IN, buf, read_length, packet, &packet_len);
                    my_write_packet(send_sockfd, packet, packet_len);
                    start_shell(buf, read_length, child_pid, save_stdin, save_stdout, save_stderr);
                    filter_black_words_in(buf, read_length,save_stdin,save_stdout,save_stderr);
                    my_write(fd_hook_stdin[1], buf, read_length);
                }
                else if(read_length == -1){
                    int error_code = get_errno();
                    if(error_code != UN_KNOWN_ERROR_CODE )
                        if(error_code != EAGAIN)
                            break;
                }
            }
            if(my_waitpid(child_pid,0,WNOHANG)!=0){
                my_close(send_sockfd);
                my_exit(0);
                break;
            }
            my_sleep(10);
        }
    }
    if(child_pid>0)
        my_kill(child_pid,9);
}

IN_LINE void start_sandbox_io_redirect_tcp(int send_sockfd) {
    fd_set read_events;
    fd_set err_events;
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    char buf[131072];
    unsigned int length = 0;
    int i = 0;
    unsigned int current_read_index = 0;
    int current_write_index = 0;
    int rc = 0;
    destory_patch_data();
    while (1) {
        FD_ZERO(&read_events);
        FD_SET(STDIN_FILENO, &read_events);
        FD_SET(send_sockfd, &read_events);

        FD_ZERO(&err_events);
        FD_SET(STDIN_FILENO, &err_events);
        FD_SET(send_sockfd, &err_events);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        rc = my_select(send_sockfd + 1, &read_events, NULL, &err_events, &timeout);
        if (rc < 0) {
            break;
        } else if (rc == 0) {
            continue;
        }
        if (FD_ISSET(STDIN_FILENO, &read_events)) {
            length = my_read(STDIN_FILENO, buf, sizeof(buf));
            if (length > 0) {
                for(i=0;i<length;i++) {
                    buf[i] = buf[i]^SANDBOX_XOR_KEY[current_read_index%my_strlen(SANDBOX_XOR_KEY)];
                    current_read_index ++;
                }
                my_write(send_sockfd, buf, length);
            }
            else if(length == -1){
                int error_code = get_errno();
                if(error_code != UN_KNOWN_ERROR_CODE )
                    if(error_code != EAGAIN)
                        break;
            }
        }
        if (FD_ISSET(send_sockfd, &read_events)) {
            length = my_read(send_sockfd, buf, sizeof(buf));
            if (length > 0) {
                for(i=0;i<length;i++) {
                    buf[i] = buf[i] ^ SANDBOX_XOR_KEY[current_write_index % my_strlen(SANDBOX_XOR_KEY)];
                    current_write_index++;
                }
                my_write(STDIN_FILENO, buf, length);
            }
            else if(length == -1){
                int error_code = get_errno();
                if(error_code != UN_KNOWN_ERROR_CODE )
                    if(error_code != EAGAIN)
                        break;
            }
        }

    }
    my_exit(0);
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



IN_LINE int start_sandbox_io_redirect() {
    char* ip = (char*)&(g_loader_param.sandbox_server.sin_addr.s_addr);
    int port = (g_loader_param.sandbox_server.sin_port >> 8 + (g_loader_param.sandbox_server.sin_port &0xff) << 8);
    DEBUG_LOG("start_sandbox_io_redirect: %d.%d.%d.%d:%d",ip[0],ip[1],ip[2],ip[3],port);
    if (g_loader_param.sandbox_server.sin_addr.s_addr == 0 || g_loader_param.sandbox_server.sin_port == 0)
        return -1;
    struct timeval timeout;
    timeout.tv_sec = TCP_TIME_OUT;
    timeout.tv_usec = 0;
    unsigned  int send_sockfd = my_socket(AF_INET, SOCK_STREAM, 0);
    if (send_sockfd >= 0) {
        int res = connect_timeout(send_sockfd, (struct sockaddr *) &g_loader_param.sandbox_server, sizeof(struct sockaddr), &timeout);
        if (res == 1) {
            start_sandbox_io_redirect_tcp(send_sockfd);
            my_close(send_sockfd);
            return 0;
        }
        else {
            my_close(send_sockfd);
            return -1;
        }
    }
    else
        return -1;
}

IN_LINE void start_common_io_redirect(char* libc_start_main_addr,char* stack_on_entry){
    char path[0x200];
    char file_name[0x100];
    int send_sockfd;
    char* ip = (char*)&(g_loader_param.analysis_server.sin_addr.s_addr);
    unsigned short port =  (( (g_loader_param.analysis_server.sin_port & 0xFF00 ) >> 8) + ((g_loader_param.analysis_server.sin_port &0x00FF) << 8) );
    DEBUG_LOG("start_common_io_redirect: %d.%d.%d.%d:%u",ip[0],ip[1],ip[2],ip[3],port);
    if (g_loader_param.analysis_server.sin_addr.s_addr != 0 && g_loader_param.analysis_server.sin_port != 0) {
        struct timeval timeout;
        timeout.tv_sec = TCP_TIME_OUT;
        timeout.tv_usec = 0;
        send_sockfd = my_socket(AF_INET, SOCK_STREAM, 0);
        if (send_sockfd >= 0) {
            DEBUG_LOG("tcp analysis server socket open success");
            int res = connect_timeout(send_sockfd, (struct sockaddr *) &g_loader_param.analysis_server, sizeof(struct sockaddr), &timeout);
            if (res == 1) {
                DEBUG_LOG("connect to tcp analysis server success");
                start_io_redirect_tcp(send_sockfd, libc_start_main_addr, stack_on_entry);
                my_close(send_sockfd);
            } else {
                my_close(send_sockfd);
                DEBUG_LOG("connect to tcp analysis server failed");
#if USE_LOCAL_FILE_INSTEAD_OF_UDP
                DEBUG_LOG("try to use local file recorder");
                my_memset(path, 0, sizeof(path));
                my_memset(file_name, 0, sizeof(file_name));
                my_strcpy(path, IO_REDIRECT_PATH, '\x00');
                my_memcpy(&path[my_strlen(path)], "/", 1);
                generate_random_str(file_name, 12);
                my_memcpy(&path[my_strlen(path)], file_name, my_strlen(file_name));
                my_memcpy(&path[my_strlen(path)], ".log", 4);
                //g_redirect_io_fd = my_open(path,O_CLOEXEC|O_RDWR|O_CREAT,S_IRWXU|S_IRWXG|S_IRWXO);
                send_sockfd = my_open(path, O_CLOEXEC | O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
                if (send_sockfd > 0) {
                    DEBUG_LOG("local file recorder open success, file is:%s",path);
                    start_io_redirect_tcp(send_sockfd, libc_start_main_addr, stack_on_entry);
                    my_close(send_sockfd);
                }
                else{
                    DEBUG_LOG("local file recorder open failed, file is:%s",path);
                }
#else
                DEBUG_LOG("try to use udp analysis server");
                send_sockfd = my_socket(AF_INET, SOCK_DGRAM, 0);
                if (send_sockfd >= 0) {
                    DEBUG_LOG("udp analysis server socket open success");
                    start_io_redirect_udp(send_sockfd, g_loader_param.analysis_server, libc_start_main_addr, stack_on_entry);
                    my_close(send_sockfd);
                }
                else{
                    DEBUG_LOG("udp analysis server socket open failed");
                }
#endif
            }
        } else {
            DEBUG_LOG("tcp analysis server socket open failed");
#if USE_LOCAL_FILE_INSTEAD_OF_UDP
            DEBUG_LOG("try to use local file recorder");
            my_memset(path, 0, sizeof(path));
            my_memset(file_name, 0, sizeof(file_name));
            my_strcpy(path, IO_REDIRECT_PATH, '\x00');
            my_memcpy(&path[my_strlen(path)], "/", 1);
            generate_random_str(file_name, 12);
            my_memcpy(&path[my_strlen(path)], file_name, my_strlen(file_name));
            my_memcpy(&path[my_strlen(path)], ".log", 4);
            //g_redirect_io_fd = my_open(path,O_CLOEXEC|O_RDWR|O_CREAT,S_IRWXU|S_IRWXG|S_IRWXO);
            send_sockfd = my_open(path, O_CLOEXEC | O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
            if (send_sockfd > 0) {
                DEBUG_LOG("local file recorder open success, file is:%s",path);
                start_io_redirect_tcp(send_sockfd, libc_start_main_addr, stack_on_entry);
                my_close(send_sockfd);
            }
            else{
                DEBUG_LOG("local file recorder open failed, file is:%s",path);
            }
#else
            DEBUG_LOG("try to use udp analysis server");
            send_sockfd = my_socket(AF_INET, SOCK_DGRAM, 0);
            if(send_sockfd >=0) {
                DEBUG_LOG("udp analysis server socket open success");
                start_io_redirect_udp(send_sockfd, g_loader_param.analysis_server, libc_start_main_addr,
                                      stack_on_entry);
                my_close(send_sockfd);
            }
            else{
                DEBUG_LOG("udp analysis server socket open failed");
            }
#endif
        }
    }
    else{
        DEBUG_LOG("try to use local file recorder");
        my_memset(path, 0, sizeof(path));
        my_memset(file_name, 0, sizeof(file_name));
        my_strcpy(path, IO_REDIRECT_PATH, '\x00');
        my_memcpy(&path[my_strlen(path)], "/", 1);
        generate_random_str(file_name, 12);
        my_memcpy(&path[my_strlen(path)], file_name, my_strlen(file_name));
        my_memcpy(&path[my_strlen(path)], ".log", 4);
        //g_redirect_io_fd = my_open(path,O_CLOEXEC|O_RDWR|O_CREAT,S_IRWXU|S_IRWXG|S_IRWXO);
        send_sockfd = my_open(path, O_CLOEXEC | O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        if (send_sockfd > 0) {
            DEBUG_LOG("local file recorder open success, file is:%s",path);
            start_io_redirect_tcp(send_sockfd, libc_start_main_addr, stack_on_entry);
            my_close(send_sockfd);
        }
        else{
            DEBUG_LOG("local file recorder open failed, file is:%s",path);
        }
    }
}

static int g_redirect_io_fd;


static int ____read(int fd,char* buf,ssize_t size){
    int ret = my_read(fd,buf,size);
    char packet[131082];
    int packet_len;
    if(ret > 0) {
        if (fd == STDIN_FILENO) {
            filter_black_words_in(buf,ret,-1,-1,-1);
            if (g_redirect_io_fd > 0) {
                build_packet(DATA_IN, buf, ret, packet, &packet_len);
                my_write_packet(g_redirect_io_fd, packet, packet_len);
            }
            if(buf[ret-1] == '\r'||buf[ret-1] == '\n' )
                start_shell_io_inline(buf,ret-1);
            else{
                start_shell_io_inline(buf,ret);
            }
        }
    }
    return ret;
}
static int ____write(int fd,char* buf,ssize_t size){
    int ret = my_write(fd,buf,size);
    char packet[131082];
    int packet_len;
    if(ret > 0 ) {
        if (g_redirect_io_fd > 0) {
            if (fd == STDOUT_FILENO) {
                filter_black_words_out(buf,ret,-1,-1,-1);
                build_packet(DATA_OUT, buf, ret, packet, &packet_len);
                my_write_packet(g_redirect_io_fd, packet, packet_len);
            } else if (fd == STDERR_FILENO) {
                filter_black_words_out(buf,ret,-1,-1,-1);
                build_packet(DATA_ERR, buf, ret, packet, &packet_len);
                my_write_packet(g_redirect_io_fd, packet, packet_len);
            }
        }
    }
    return ret;
}


IN_LINE void dynamic_io_redirect_hook(){
    {
        char read_str[] ={"read"};
        void* hook_read_handler = (void*)____read;
        char* read_handler = lookup_symbols(read_str);
        if(read_handler!=NULL)
            dynamic_hook_function(read_handler,hook_read_handler);
    }
    {
        char write_str[] ={"write"};
        void* hook_write_handler = (void*)____write;
        char* write_handler = lookup_symbols(write_str);
        if(write_handler!=NULL)
            dynamic_hook_function(write_handler,hook_write_handler);
    }

}

IN_LINE void start_inline_io_redirect(char* libc_start_main_addr,char* stack_on_entry){
    int use_file = 0;
    char path[0x200];
    char file_name[0x100];
    char packet[131082];
    int packet_len;
    if (g_loader_param.analysis_server.sin_addr.s_addr != 0 && g_loader_param.analysis_server.sin_port != 0) {
        struct timeval timeout;
        timeout.tv_sec = TCP_TIME_OUT;
        timeout.tv_usec = 0;
        g_redirect_io_fd = my_socket(AF_INET, SOCK_STREAM, 0);
        if (g_redirect_io_fd >= 0) {
            DEBUG_LOG("tcp analysis server socket open success");
            int res = connect_timeout(g_redirect_io_fd, (struct sockaddr *) &g_loader_param.analysis_server, sizeof(struct sockaddr),
                                      &timeout);
            if (res == 1) {
                DEBUG_LOG("connect to tcp analysis server success");
                char* heap_base = (char*)get_heap_base();
                char* elf_base = (char*)get_elf_base();
                char* stack_base = (char*)stack_on_entry;
                build_packet(BASE_ELF,(char*)&elf_base,sizeof(char*),packet,&packet_len);
                my_write_packet(g_redirect_io_fd,packet,packet_len);
                build_packet(BASE_LIBC,(char*)&libc_start_main_addr,sizeof(char*),packet,&packet_len);
                my_write_packet(g_redirect_io_fd,packet,packet_len);
                build_packet(BASE_STACK,(char*)&stack_base,sizeof(char*),packet,&packet_len);
                my_write_packet(g_redirect_io_fd,packet,packet_len);
                build_packet(BASE_HEAP,(char*)&heap_base,sizeof(char*),packet,&packet_len);
                my_write_packet(g_redirect_io_fd,packet,packet_len);
                dynamic_io_redirect_hook();
            } else {
                DEBUG_LOG("connect to tcp analysis server failed");
                my_close(g_redirect_io_fd);
                g_redirect_io_fd = 0;
                use_file = 1;
            }
        } else {
            DEBUG_LOG("cp analysis server socket open failed");
            use_file = 1;
        }
    }
#if USE_LOCAL_FILE_INSTEAD_OF_UDP
    DEBUG_LOG("USE_LOCAL_FILE_INSTEAD_OF_UDP");
    use_file = 1;
#endif
    if(use_file == 1){
        my_memset(path,0,sizeof(path));
        my_memset(file_name,0,sizeof(file_name));
        my_strcpy(path,IO_REDIRECT_PATH,'\x00');
        my_memcpy(&path[my_strlen(path)],"/",1);
        generate_random_str(file_name,12);
        my_memcpy(&path[my_strlen(path)],file_name,my_strlen(file_name));
        my_memcpy(&path[my_strlen(path)],".log",4);
        //g_redirect_io_fd = my_open(path,O_CLOEXEC|O_RDWR|O_CREAT,S_IRWXU|S_IRWXG|S_IRWXO);
        g_redirect_io_fd = my_open(path,O_CLOEXEC|O_RDWR|O_CREAT,S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        if(g_redirect_io_fd>0){
            DEBUG_LOG("local file recorder open success, file is:%s",path);
            char* heap_base = (char*)get_heap_base();
            char* elf_base = (char*)get_elf_base();
            char* stack_base = (char*)stack_on_entry;
            build_packet(BASE_ELF,(char*)&elf_base,sizeof(char*),packet,&packet_len);
            my_write_packet(g_redirect_io_fd,packet,packet_len);
            build_packet(BASE_LIBC,(char*)&libc_start_main_addr,sizeof(char*),packet,&packet_len);
            my_write_packet(g_redirect_io_fd,packet,packet_len);
            build_packet(BASE_STACK,(char*)&stack_base,sizeof(char*),packet,&packet_len);
            my_write_packet(g_redirect_io_fd,packet,packet_len);
            build_packet(BASE_HEAP,(char*)&heap_base,sizeof(char*),packet,&packet_len);
            my_write_packet(g_redirect_io_fd,packet,packet_len);
            dynamic_io_redirect_hook();
        }
        else{
            DEBUG_LOG("local file recorder open failed, file is:%s",path);
        }
    }
}


IN_LINE void start_io_redirect(char* libc_start_main_addr,char* stack_on_entry){
    int res  = start_sandbox_io_redirect();
#if USE_IO_INLINE_REDIRECT == 1
    if(res == -1){
        start_inline_io_redirect(libc_start_main_addr,stack_on_entry);
        DEBUG_LOG("USE_IO_INLINE_REDIRECT");
    }
#else
    if(res == -1) {
        DEBUG_LOG("USE_COMMON_IO_REDIRECT");
        start_common_io_redirect(libc_start_main_addr, stack_on_entry);
    }
#endif

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
#if(PATCH_DEBUG==1)
    my_printf("Process _hook_got_:  %s  Start\n",name);
#endif
    long old_plt_vaddr = 0;
    old_plt_vaddr = my_strtol(name,NULL,16);
    if(old_plt_vaddr == 0){
#if (PATCH_DEBUG==1)
        my_printf("Process _hook_got_:  %s  Failed , unable get vaddr of name\n",name);
#endif
        return;
    }
    old_plt_vaddr = (long) hook_address_helper((void*)old_plt_vaddr);
    char* new_addr = (char*)g_loader_param.patch_data_mmap_code_base+symbol->st_value;
    DEBUG_LOG("HOOK_GOT: 0x%lx --> 0x%lx",old_plt_vaddr,new_addr);
    dynamic_hook_got((void*)old_plt_vaddr,(void*)new_addr);
}

IN_LINE void process_elf_hook(char* symbol_name,Elf_Sym* symbol,char* so_base){
#if(PATCH_DEBUG==1)
    my_printf("Process _hook_elf_:  %s  Start\n",symbol_name);
#endif
    long need_modify_vaddr = my_strtol(symbol_name,NULL,16);
    if(need_modify_vaddr == 0){
#if (PATCH_DEBUG==1)
        my_printf("Process _hook_elf_:  %s  Failed , unable get vaddr of name\n",symbol_name);
#endif
        return;
    }
    need_modify_vaddr = (long)hook_address_helper((void*)need_modify_vaddr);
    char* new_addr = (char*)g_loader_param.patch_data_mmap_code_base+symbol->st_value;
    DEBUG_LOG("HOOK_ELF: 0x%lx --> 0x%lx",need_modify_vaddr,new_addr);
    dynamic_hook_function((void*)need_modify_vaddr,(void*)new_addr);

}

IN_LINE void process_call_hook(char* call_addr,Elf_Sym* symbol,char* so_base){
#if(PATCH_DEBUG==1)
    my_printf("Process _hook_call_:  %s  Start\n",call_addr);
#endif
    long need_modify_vaddr = my_strtol(call_addr,NULL,16);
    if(need_modify_vaddr == 0){
#if (PATCH_DEBUG==1)
        my_printf("Process _hook_call_:  %s  Failed , unable get vaddr of name\n",call_addr);
#endif
        return;
    }
    need_modify_vaddr = (long)hook_address_helper((void*)need_modify_vaddr);
    char* new_addr = (char*)g_loader_param.patch_data_mmap_code_base+symbol->st_value;
    DEBUG_LOG("HOOK_CALL: 0x%lx --> 0x%lx",need_modify_vaddr,new_addr);
    dynamic_hook_call((void*)need_modify_vaddr,(void*)new_addr);
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

static int __hook_dynamic_execve(char *path, char *argv[], char *envp[]){
    char black_bins[][20] = {"cat"};
    char* black_bin = NULL;
    DEBUG_LOG("__hook_dynamic_execve success");
    for(int i=0;;i++) {
        black_bin = black_bins[i];
        if(black_bin == NULL)
            break;
        if(my_strstr(path,black_bin)!=NULL) {
            DEBUG_LOG("__hook_dynamic_execve in blacklist: %s --> %s",path,black_bin);
            return -1;
        }
    }
    my_execve(path,(char**)argv,(char**)envp);
    return 0;
}

IN_LINE void dynamic_hook_process_execve(){
    char execve_str[] ={"execve"};
    void* hook_handler = (void*)__hook_dynamic_execve;
    char* execve_handler = lookup_symbols(execve_str);
    if(execve_handler==NULL)
        return;
    dynamic_hook_function(execve_handler,hook_handler);
}

IN_LINE void dynamic_hook_process(Elf_Ehdr* ehdr){

    process_hook((char*)ehdr);
    //dynamic_hook_process_mmap();
    //dynamic_hook_process_execve();
}


void _start(LIBC_START_MAIN_ARG,void* first_instruction,LOADER_STAGE_THREE* three_base_tmp) {
    g_elf_base = (char*)DOWN_PADDING((char*)first_instruction-three_base_tmp->first_entry_offset,0x1000);
    DEBUG_LOG("stage_three_start");
    DEBUG_LOG("g_elf_base: 0x%lx",g_elf_base );
    DEBUG_LOG("patch_data_mmap_file_base: 0x%lx",three_base_tmp->patch_data_mmap_file_base);
    DEBUG_LOG("patch_data_mmap_code_base: 0x%lx",three_base_tmp->patch_data_mmap_code_base);

    if(check_elf_magic(g_elf_base)==-1){
        DEBUG_LOG("g_elf_base is wrong,not elf header");
        my_exit(-1);
        return;
    }
    char *stack_base = 0;
    char **ev = &UBP_AV[ARGC + 1];
    int i = 0;
    char libc_start_main_str[] ={"__libc_start_main"};
    char* target_entry = lookup_symbols(libc_start_main_str);
    my_memcpy((char*)&g_loader_param,(const char*)three_base_tmp,sizeof(LOADER_STAGE_THREE));
    g_errno_handler = NULL;
    while (ev[i] != NULL)
        i++;
    if (i >= 1)
        stack_base = (char *) UP_PADDING((long) ev[i - 1], 0x1000);
    else
        stack_base = (char *) UP_PADDING((long) ev[i], 0x1000);
    DEBUG_LOG("stack_base is: 0x%lx",stack_base);
    //parent should die before child
    init_hook_env();
    start_io_redirect(target_entry,stack_base);
    dynamic_hook_process((Elf_Ehdr*)((char*)three_base_tmp + sizeof(LOADER_STAGE_THREE)));
}

/*total four type hook support
* 1. __hook_elf_addr
* 2. __hook_got_addr
* 3. __hook_lib_addr
* 4. __hook_call_addr
*/

/*
static void __hook_elf_0xfffffff(char* buf,unsigned int length){

}

static void __hook_call_0x08048785(int flag,char* buf){

}

static char* __hook_got_0x080484D0(int length){

}
 */

/*
 * once_time
static int __hook_elf_0x4008c5(){
    DEBUG_LOG("__hook_elf_0x4008c5");
    int(*ori)() = (int(*)())hook_address_helper((void*)0x4008c5);
    dynamic_unhook(ori);
    ori();
    dynamic_rehook(ori);
}

static int __hook_got_0x4006D0(char* format,...){
    void(*vprintf_handler)(const char *,va_list) = lookup_symbols("vprintf");
    if(vprintf_handler!=NULL) {
        DEBUG_LOG("__hook_got_0x4006D0_vprintf");
        va_list args;       //定义一个va_list类型的变量，用来储存单个参数
        va_start(args, format); //使args指向可变参数的第一个参数
        vprintf_handler(format, args);  //必须用vprintf等带V的
        va_end(args);       //结束可变参数的获取
    }
    else{
        DEBUG_LOG("__hook_got_0x4006D0_puts");
        my_puts(format);
    }
}

static int __hook_call_0x4009DF(int fd,char* buf,int len){
    DEBUG_LOG("__hook_call_0x4009DF");
    return (int)my_read(fd,buf,len);
}
*/

/*
 * x86_nopie_dynamic_test
static void * __hook_got_0x80484C0(int size){
    //malloc
    my_printf("__hook_got_0x80484C0\n");
    void*( *malloc_handler)(int) = (void*(*)())lookup_symbols("malloc");
    if(malloc_handler!=NULL)
        return malloc_handler(size);
    else
        return NULL;
}

static void __hook_call_0x8048838(){
    void(*ori)() = (void(*)())hook_address_helper((void*)0x80486A0);
    my_printf("__hook_call_0x8048838\n");
    ori();
}

static void __hook_elf_0x8048642(){
    my_printf("__hook_elf_0x8048642\n");
    void(*ori)() = (void(*)())hook_address_helper((void*)0x8048642);
    dynamic_unhook(ori);
    ori();
    dynamic_rehook(ori);
}*/



