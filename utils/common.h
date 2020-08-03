//
// Created by root on 7/23/20.
//

#ifndef HOOKUTILV3_COMMON_H
#define HOOKUTILV3_COMMON_H

#include "arch/common/syscall.h"


#ifndef ULONG_MAX
#define	ULONG_MAX	((unsigned long)(~0L))		/* 0xFFFFFFFF */
#endif

#ifndef LONG_MAX
#define	LONG_MAX	((long)(ULONG_MAX >> 1))	/* 0x7FFFFFFF */
#endif

#ifndef LONG_MIN
#define	LONG_MIN	((long)(~LONG_MAX))		/* 0x80000000 */
#endif

IN_LINE int  my_memcpy(char *dst, const char *src,int len){
    int i = 0;
    while(i<len){
        dst[i] = src[i];
        i++;
    }
    return 0;
}

IN_LINE void my_memset(char *dst,char chr,int len){
    int i = 0;
    for(i=0;i<len;i++)
        dst[i] = chr;
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

IN_LINE unsigned long divmod(unsigned long large,unsigned long mod){
    while(large>=mod)
        large = large - mod;
    return large;
}

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



IN_LINE void my_puts(const char* str){
    char end[] = {'\n'};
    my_write(1,str,my_strlen(str));
    my_write(1,end,1);
}


IN_LINE void my_write_stdout(const char* str){
    char end[] = {'\n'};
    my_write(1,str,my_strlen(str));
}



#endif //HOOKUTILV3_COMMON_H
