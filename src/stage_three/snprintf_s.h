


#define SECUREC_STRING_MAX_LEN 0x7FFFFFFF
#define SECUREC_PRINTF_TRUNCATE (-2)
#define SECUREC_RADIX_DECIMAL               10
#define SECUREC_STATE_TABLE_SIZE              337
#define SECUREC_PREFIX_LEN                  2
#define SECUREC_BUFFER_SIZE    512
#define SECUREC_CHAR(x) x
#define SECUREC_FMT_STATE_OFFSET  256
#define SECUREC_FLAG_SIGN           0x00001U
#define SECUREC_FLAG_SIGN_SPACE     0x00002U
#define SECUREC_FLAG_LEFT           0x00004U
#define SECUREC_FLAG_LEADZERO       0x00008U
#define SECUREC_FLAG_LONG           0x00010U
#define SECUREC_FLAG_SHORT          0x00020U
#define SECUREC_FLAG_SIGNED         0x00040U
#define SECUREC_FLAG_ALTERNATE      0x00080U
#define SECUREC_FLAG_NEGATIVE       0x00100U
#define SECUREC_FLAG_FORCE_OCTAL    0x00200U
#define SECUREC_FLAG_LONG_DOUBLE    0x00400U
#define SECUREC_FLAG_WIDECHAR       0x00800U
#define SECUREC_FLAG_LONGLONG       0x01000U
#define SECUREC_FLAG_CHAR           0x02000U
#define SECUREC_FLAG_POINTER        0x04000U
#define SECUREC_FLAG_I64            0x08000U
#define SECUREC_FLAG_PTRDIFF        0x10000U
#define SECUREC_FLAG_SIZE           0x20000U
#ifdef  SECUREC_COMPATIBLE_LINUX_FORMAT
#define SECUREC_FLAG_INTMAX         0x40000U
#endif

#define SECUREC_DECODE_STATE(c, fmtTable, lastState) (SecFmtState)(((fmtTable)[((fmtTable)[(unsigned char)(c)]) * \
    ((unsigned char)STAT_INVALID + 1) + \
    (unsigned char)(lastState) + \
    SECUREC_FMT_STATE_OFFSET]))
#define SECUREC_IS_REST_BUF_ENOUGH(stream, needLen) ((int)((stream)->count - \
    (int)(needLen) * (int)(sizeof(SecChar))) >= 0)
#define SECUREC_SAFE_WRITE_CHAR(c, outStream, outChars) do { \
    *((SecChar *)(void *)((outStream)->cur)) = (SecChar)(c); \
    (outStream)->cur += sizeof(SecChar); \
    (outStream)->count -= (int)(sizeof(SecChar)); \
    *(outChars) = *(outChars) + 1; \
} SECUREC_WHILE_ZERO

#if (defined(_MSC_VER)) && (_MSC_VER >= 1400)
#define SECUREC_MASK_MSVC_CRT_WARNING __pragma(warning(push)) \
    __pragma(warning(disable:4996 4127))
#define SECUREC_END_MASK_MSVC_CRT_WARNING  __pragma(warning(pop))
#else
#define SECUREC_MASK_MSVC_CRT_WARNING
#define SECUREC_END_MASK_MSVC_CRT_WARNING
#endif
#define SECUREC_WHILE_ZERO SECUREC_MASK_MSVC_CRT_WARNING while (0) SECUREC_END_MASK_MSVC_CRT_WARNING
#define SECUREC_MUL_TEN_ADD_BEYOND_MAX(x)   (((x) > SECUREC_MAX_WIDTH_LEN_DIV_TEN))
#define SECUREC_MAX_WIDTH_LEN_DIV_TEN       21474836
#define SECUREC_MAX_WIDTH_LEN               SECUREC_MUL_TEN(SECUREC_MAX_WIDTH_LEN_DIV_TEN)
#define SECUREC_INT_MAX                     2147483647
#define SECUREC_MUL_SIXTEEN(x)              ((x) << 4)
#define SECUREC_MUL_EIGHT(x)                ((x) << 3)
#define SECUREC_MUL_TEN(x)                  ((((x) << 2) + (x)) << 1)

typedef char SecChar;
typedef struct {
    int count;
    char *cur;
} SecPrintfStream;

typedef union {
    char *str;                  /* not a null terminated  string */
} SecFormatBuf;

typedef enum {
    STAT_NORMAL,
    STAT_PERCENT,
    STAT_FLAG,
    STAT_WIDTH,
    STAT_DOT,
    STAT_PRECIS,
    STAT_SIZE,
    STAT_TYPE,
    STAT_INVALID
} SecFmtState;
typedef struct {
    unsigned int flags;
    int fldWidth;
    int precision;
    int bufferIsWide;           /* flag for buffer contains wide chars ;0 is not wide char */
    int dynWidth;               /* %*   1 width from variable parameter ;0 not */
    int dynPrecision;           /* %.*  1 precision from variable parameter ;0 not */
} SecFormatAttr;
typedef union {
    char str[SECUREC_BUFFER_SIZE + 1];
} SecBuffer;

IN_LINE void SecOutputOneChar(SecChar ch, SecPrintfStream *stream, int *counter)
{
    /* normal state, write character */
    if (SECUREC_IS_REST_BUF_ENOUGH(stream, 1)) { /* only one char */
        SECUREC_SAFE_WRITE_CHAR(ch, stream, counter); /* char * cast to wchar * */
    } else {
#ifdef SECUREC_FOR_WCHAR
        SecWriteCharW(ch, stream, counter);
#else
        /* optimize function call to code */
        *counter = -1;
        stream->count = -1;
#endif
    }
}
#define EOF -1
#define SECUREC_PUTC(c, outStream)    ((--(outStream)->count >= 0) ? \
    (int)((unsigned int)(unsigned char)(*((outStream)->cur++) = (char)(c)) & 0xff) : EOF)
IN_LINE void SecWriteMultiChar(char ch, int num, SecPrintfStream *f, int *pnumwritten)
{
    int count = num;
    while (count-- > 0) {
        if (SECUREC_PUTC(ch, f) == EOF) {
            *pnumwritten = -1;
            break;
        } else {
            *pnumwritten = *pnumwritten + 1;
        }
    }
}

IN_LINE int SecDecodeWidth(SecChar ch, SecFormatAttr *formatAttr, SecFmtState lastState)
{
    if (formatAttr->dynWidth == 0) {
        if (lastState != STAT_WIDTH) {
            formatAttr->fldWidth = 0;
        }
        if (SECUREC_MUL_TEN_ADD_BEYOND_MAX(formatAttr->fldWidth)) {
            return -1;
        }
        formatAttr->fldWidth = (int)SECUREC_MUL_TEN((unsigned int)formatAttr->fldWidth) +
                               (unsigned char)(ch - SECUREC_CHAR('0'));
    } else {
        if (formatAttr->fldWidth < 0) {
            formatAttr->flags |= SECUREC_FLAG_LEFT;
            formatAttr->fldWidth = (-formatAttr->fldWidth);
            if (formatAttr->fldWidth > SECUREC_MAX_WIDTH_LEN) {
                return -1;
            }
        }
    }
    return 0;
}
IN_LINE void SecDecodeFlags(SecChar ch, SecFormatAttr *attr)
{
    switch (ch) {
        case SECUREC_CHAR(' '):
            attr->flags |= SECUREC_FLAG_SIGN_SPACE;
            break;
        case SECUREC_CHAR('+'):
            attr->flags |= SECUREC_FLAG_SIGN;
            break;
        case SECUREC_CHAR('-'):
            attr->flags |= SECUREC_FLAG_LEFT;
            break;
        case SECUREC_CHAR('0'):
            attr->flags |= SECUREC_FLAG_LEADZERO;   /* add zero th the front */
            break;
        case SECUREC_CHAR('#'):
            attr->flags |= SECUREC_FLAG_ALTERNATE;  /* output %x with 0x */
            break;
        default:
            break;
    }
    return;
}
IN_LINE int SecDecodePrecision(SecChar ch, SecFormatAttr *formatAttr)
{
    if (formatAttr->dynPrecision == 0) {
        /* add digit to current precision */
        if (SECUREC_MUL_TEN_ADD_BEYOND_MAX(formatAttr->precision)) {
            return -1;
        }
        formatAttr->precision = (int)SECUREC_MUL_TEN((unsigned int)formatAttr->precision) +
                                (unsigned char)(ch - SECUREC_CHAR('0'));
    } else {
        if (formatAttr->precision < 0) {
            formatAttr->precision = -1;
        }
        if (formatAttr->precision > SECUREC_MAX_WIDTH_LEN) {
            return -1;
        }
    }
    return 0;
}

IN_LINE int SecDecodeSizeI(SecFormatAttr *attr, const SecChar **format)
{
#ifdef SECUREC_ON_64BITS
    attr->flags |= SECUREC_FLAG_I64;    /* %I  to  INT64 */
#endif
    if ((**format == SECUREC_CHAR('6')) && (*((*format) + 1) == SECUREC_CHAR('4'))) {
        (*format) += 2; /* add 2 to skip I64 */
        attr->flags |= SECUREC_FLAG_I64;    /* %I64  to  INT64 */
    } else if ((**format == SECUREC_CHAR('3')) && (*((*format) + 1) == SECUREC_CHAR('2'))) {
        (*format) += 2; /* add 2 to skip I32 */
        attr->flags &= ~SECUREC_FLAG_I64;   /* %I64  to  INT32 */
    } else if ((**format == SECUREC_CHAR('d')) || (**format == SECUREC_CHAR('i')) ||
               (**format == SECUREC_CHAR('o')) || (**format == SECUREC_CHAR('u')) ||
               (**format == SECUREC_CHAR('x')) || (**format == SECUREC_CHAR('X'))) {
        /* do nothing */
    } else {
        /* Compatibility  code for "%I" just print I */
        return -1;
    }
    return 0;
}

IN_LINE int SecDecodeSize(SecChar ch, SecFormatAttr *attr, const SecChar **format)
{
    switch (ch) {
#ifdef SECUREC_COMPATIBLE_LINUX_FORMAT
        case SECUREC_CHAR('j'):
            attr->flags |= SECUREC_FLAG_INTMAX;
            break;
#endif
        case SECUREC_CHAR('q'):
            /* fall-through */ /* FALLTHRU */
        case SECUREC_CHAR('L'):
            attr->flags |= SECUREC_FLAG_LONGLONG | SECUREC_FLAG_LONG_DOUBLE;
            break;
        case SECUREC_CHAR('l'):
            if (**format == SECUREC_CHAR('l')) {
                *format = *format + 1;
                attr->flags |= SECUREC_FLAG_LONGLONG;   /* long long */
            } else {
                attr->flags |= SECUREC_FLAG_LONG;   /* long int or wchar_t */
            }
            break;
        case SECUREC_CHAR('t'):
            attr->flags |= SECUREC_FLAG_PTRDIFF;
            break;
#ifdef SECUREC_COMPATIBLE_LINUX_FORMAT
        case SECUREC_CHAR('z'):
            /* fall-through */ /* FALLTHRU */
        case SECUREC_CHAR('Z'):
            attr->flags |= SECUREC_FLAG_SIZE;
            break;
#endif
        case SECUREC_CHAR('I'):
            if (SecDecodeSizeI(attr, format) != 0) {
                /* Compatibility  code for "%I" just print I */
                return -1;
            }
            break;
        case SECUREC_CHAR('h'):
            if (**format == SECUREC_CHAR('h')) {
                attr->flags |= SECUREC_FLAG_CHAR;   /* char */
            } else {
                attr->flags |= SECUREC_FLAG_SHORT;  /* short int */
            }
            break;
        case SECUREC_CHAR('w'):
            attr->flags |= SECUREC_FLAG_WIDECHAR;   /* wide char */
            break;
        default:
            break;
    }
    return 0;
}
IN_LINE int SecDecodeTypeC(SecFormatAttr *attr, unsigned int cValue, SecFormatBuf *formatBuf, SecBuffer *buffer)
{
#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT)) && !(defined(__hpux)) && !(defined(SECUREC_ON_SOLARIS))
    attr->flags &= ~SECUREC_FLAG_LEADZERO;
#endif

#ifdef SECUREC_FOR_WCHAR
    attr->bufferIsWide = 1;
    if (attr->flags & SECUREC_FLAG_SHORT) {
#if SECUREC_HAVE_MBTOWC
        /* multibyte character to wide  character */
        char tmpChar[2]; /* One character string, length is 2 */
        tmpChar[0] = (char)(cValue & 0x00ff);
        tmpChar[1] = '\0';

        if (mbtowc(buffer->wStr, tmpChar, sizeof(tmpChar)) < 0) {
            return -1;
        }
#else
        return -1;
#endif
    } else {
        buffer->wStr[0] = (wchar_t)cValue;
    }
    formatBuf->wStr = buffer->wStr;
    return 1;                /* only 1 wide character */
#else /* SECUREC_FOR_WCHAR */
    attr->bufferIsWide = 0;
    if (attr->flags & (SECUREC_FLAG_LONG | SECUREC_FLAG_WIDECHAR)) {
#if SECUREC_HAVE_WCTOMB
        wchar_t wChar = (wchar_t)cValue;
        int textLen;
        /* wide  character  to multibyte character */
        SECUREC_MASK_MSVC_CRT_WARNING
        textLen = wctomb(buffer->str, wChar);
        SECUREC_END_MASK_MSVC_CRT_WARNING
        if (textLen < 0) {
            return -1;
        }
        formatBuf->str = buffer->str;
        return textLen;
#else
        return -1;
#endif
    } else {
    /* get  multibyte character from argument */
    unsigned short temp;
    temp = (unsigned short)cValue;
    buffer->str[0] = (char)temp;
    formatBuf->str = buffer->str;
    return 1; /* only 1 character */
    }
#endif

    }


#define SECUREC_CALC_STR_LEN(str, maxLen, outLen) do { \
    *(outLen) = my_strlen((str)); \
} SECUREC_WHILE_ZERO


#define SECUREC_NULL_STRING_SIZE            8
    static char g_strNullString[SECUREC_NULL_STRING_SIZE] = "(null)";
    IN_LINE int SecDecodeTypeSchar(const SecFormatAttr *attr, SecFormatBuf *formatBuf)
    {
        int finalPrecision = (attr->precision == -1) ? SECUREC_INT_MAX : attr->precision;
        int textLen;

        if (formatBuf->str == NULL) {   /* NULL passed, use special string */
            formatBuf->str = g_strNullString;
        }
        if (finalPrecision == SECUREC_INT_MAX) {
            /* precision NOT assigned */
            /* The strlen performance is high when the string length is greater than 32 */
            textLen = (int)my_strlen(formatBuf->str);
        } else {
            /* precision assigned */
            size_t tmpLen;
            SECUREC_CALC_STR_LEN(formatBuf->str, (size_t)(unsigned int)finalPrecision, &tmpLen);
            textLen = (int)tmpLen;
        }
        return textLen;
    }



    IN_LINE int SecDecodeTypeS(SecFormatAttr *attr, char *argPtr, SecFormatBuf *formatBuf)
    {
        int textLen;
#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT)) && (!defined(SECUREC_ON_UNIX))
        attr->flags &= ~SECUREC_FLAG_LEADZERO;
#endif
        formatBuf->str = argPtr;
#ifdef SECUREC_FOR_WCHAR
        #if defined(SECUREC_COMPATIBLE_LINUX_FORMAT)
    if (!(attr->flags & SECUREC_FLAG_LONG)) {
        attr->flags |= SECUREC_FLAG_SHORT;
    }
#endif
    if (attr->flags & SECUREC_FLAG_SHORT) {
        /* textLen now contains length in multibyte chars */
        textLen = SecDecodeTypeSchar(attr, formatBuf);
    } else {
        /* textLen now contains length in wide chars */
        textLen = SecDecodeTypeSwchar(attr, formatBuf);
    }
#else /* SECUREC_FOR_WCHAR */
        if (attr->flags & (SECUREC_FLAG_LONG | SECUREC_FLAG_WIDECHAR)) {
            /* textLen now contains length in wide chars */
#if SECUREC_HAVE_WCHART
            textLen = SecDecodeTypeSwchar(attr, formatBuf);
#else
            textLen = 0;
#endif
        } else {
    /* textLen now contains length in multibyte chars */
    textLen = SecDecodeTypeSchar(attr, formatBuf);
    }
#endif /* SECUREC_FOR_WCHAR */
    return textLen;
    }
    IN_LINE void SecWriteString(const char *string, int len, SecPrintfStream *f, int *pnumwritten)
    {
        const char *str = string;
        int count = len;
        while (count-- > 0) {
            if (SECUREC_PUTC(*str, f) == EOF) {
                *pnumwritten = -1;
                break;
            } else {
                *pnumwritten = *pnumwritten + 1;
                ++str;
            }
        }
    }
    typedef unsigned long long SecUnsignedInt64;
    typedef unsigned int SecUnsignedInt32;
#define SECUREC_SHR_DWORD(x)                (((x) >> 16) >> 16)
    IN_LINE void SecU64Div10(SecUnsignedInt64 divisor, SecUnsignedInt64 *quotient, SecUnsignedInt32 *remainder)
    {
        SecUnsignedInt64 mask = 0xffffffffULL; /* use 0xffffffffULL as 32 bit mask */
        SecUnsignedInt64 magicHi = 0xccccccccULL; /* fast divide 10 magic numbers high 32bit 0xccccccccULL */
        SecUnsignedInt64 magicLow = 0xcccccccdULL; /* fast divide 10 magic numbers low 32bit  0xcccccccdULL */
        SecUnsignedInt64 divisorHi = (SecUnsignedInt64)(SECUREC_SHR_DWORD(divisor)); /* hig 32 bit use  */
        SecUnsignedInt64 divisorLow = (SecUnsignedInt64)(divisor & mask); /* low 32 bit mask */
        SecUnsignedInt64 factorHi = divisorHi * magicHi;
        SecUnsignedInt64 factorLow1 = divisorHi * magicLow;
        SecUnsignedInt64 factorLow2 = divisorLow * magicHi;
        SecUnsignedInt64 factorLow3 = divisorLow * magicLow;
        SecUnsignedInt64 carry = (factorLow1 & mask) + (factorLow2 & mask) + SECUREC_SHR_DWORD(factorLow3);
        SecUnsignedInt64 resultHi64 = factorHi + SECUREC_SHR_DWORD(factorLow1) + \
                                   SECUREC_SHR_DWORD(factorLow2) + SECUREC_SHR_DWORD(carry);

        *quotient = resultHi64 >> 3; /* fast divide 10 magic numbers 3 */
        *remainder = (SecUnsignedInt32)(divisor - ((*quotient) * 10)); /* quotient mul 10 */
        return;
    }
    IN_LINE int SecOutputS(SecPrintfStream *stream, const char *cFormat, va_list argList)

    {
        const SecChar *format = cFormat;
#if SECUREC_ENABLE_SPRINTF_FLOAT
        char *floatBuf = NULL;
#endif
        SecFormatBuf formatBuf;
        static const char *itoaUpperDigits = "0123456789ABCDEFX";
        static const char *itoaLowerDigits = "0123456789abcdefx";
        const char *digits = itoaUpperDigits;
        unsigned int radix = SECUREC_RADIX_DECIMAL;
        int charsOut;               /* characters written */
        int prefixLen = 0;  /* Must be initialized or compiler alerts */
        int padding = 0;
        int textLen;                /* length of the text */
        int noOutput = 0; /* Must be initialized or compiler alerts */
        SecFmtState state;
        SecFmtState lastState;
        SecChar prefix[SECUREC_PREFIX_LEN] = { 0 };
        SecChar ch;                 /* currently read character */
        static const unsigned char stateTable[SECUREC_STATE_TABLE_SIZE] = {
                /* type 0:    nospecial meanin;
                 *  1:   '%';
                 *  2:    '.'
                 *  3:    '*'
                 *  4:    '0'
                 *  5:    '1' ... '9'
                 *  6:    ' ', '+', '-', '#'
                 *  7:     'h', 'l', 'L', 'F', 'w' , 'N','z','q','t','j'
                 *  8:     'd','o','u','i','x','X','e','f','g'
                 */
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x06, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x06, 0x00, 0x06, 0x02, 0x00,
                0x04, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x08, 0x08, 0x00, 0x07, 0x00, 0x00, 0x07, 0x00, 0x07, 0x00,
                0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x08, 0x08, 0x08, 0x08, 0x08, 0x07, 0x08, 0x07, 0x00, 0x07, 0x00, 0x00, 0x08,
                0x08, 0x07, 0x00, 0x08, 0x07, 0x08, 0x00, 0x07, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
                /* fill zero  for normal char 128 byte for 0x80 - 0xff */
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                /* state  0: normal
                 *  1: percent
                 *  2: flag
                 *  3: width
                 *  4: dot
                 *  5: precis
                 *  6: size
                 *  7: type
                 *  8: invalid
                 */
                0x00, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x00, 0x00, 0x01, 0x00, 0x08, 0x08, 0x08, 0x08, 0x08,
                0x01, 0x00, 0x00, 0x04, 0x04, 0x04, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x03, 0x03, 0x08, 0x05,
                0x08, 0x08, 0x00, 0x00, 0x00, 0x02, 0x02, 0x03, 0x05, 0x05, 0x08, 0x00, 0x00, 0x00, 0x03, 0x03,
                0x03, 0x05, 0x05, 0x08, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00,
                0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x00, 0x00, 0x00, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x00,
                0x00
        };

        SecFormatAttr formatAttr;
        SecBuffer buffer;
        formatAttr.flags = 0;
        formatAttr.bufferIsWide = 0;    /* flag for buffer contains wide chars */
        formatAttr.fldWidth = 0;
        formatAttr.precision = 0;
        formatAttr.dynWidth = 0;
        formatAttr.dynPrecision = 0;
        charsOut = 0;
        textLen = 0;
        state = STAT_NORMAL;        /* starting state */
        formatBuf.str = NULL;

        /* loop each format character */
        /* remove format != NULL */
        while ((ch = *format) != SECUREC_CHAR('\0') && charsOut >= 0) {
            ++format;
            lastState = state;
            state = SECUREC_DECODE_STATE(ch, stateTable, lastState);
            switch (state) {
                case STAT_NORMAL:
                    SecOutputOneChar(ch, stream, &charsOut);
                    continue;
                case STAT_PERCENT:
                    /* set default values */
                    prefixLen = 0;
                    noOutput = 0;
                    formatAttr.flags = 0;
                    formatAttr.fldWidth = 0;
                    formatAttr.precision = -1;
                    formatAttr.bufferIsWide = 0;
                    formatAttr.dynWidth = 0;
                    formatAttr.dynPrecision = 0;
                    break;
                case STAT_FLAG:
                    /* set flag based on which flag character */
                    SecDecodeFlags(ch, &formatAttr);
                    break;
                case STAT_WIDTH:
                    /* update width value */
                    if (ch == SECUREC_CHAR('*')) {
                        /* get width */
                        formatAttr.fldWidth = (int)va_arg(argList, int);
                        formatAttr.dynWidth = 1;
                    } else {
                        formatAttr.dynWidth = 0;
                    }
                    if (SecDecodeWidth(ch, &formatAttr, lastState) != 0) {
                        return -1;
                    }
                    break;
                case STAT_DOT:
                    formatAttr.precision = 0;
                    break;
                case STAT_PRECIS:
                    /* update precison value */
                    if (ch == SECUREC_CHAR('*')) {
                        /* get precision from arg list */
                        formatAttr.precision = (int)va_arg(argList, int);
                        formatAttr.dynPrecision = 1;
                    } else {
                        formatAttr.dynPrecision = 0;
                    }
                    if (SecDecodePrecision(ch, &formatAttr) != 0) {
                        return -1;
                    }
                    break;
                case STAT_SIZE:
                    /* read a size specifier, set the formatAttr.flags based on it */
                    if (SecDecodeSize(ch, &formatAttr, &format) != 0) {
                        /* Compatibility  code for "%I" just print I */
                        SecOutputOneChar(ch, stream, &charsOut);
                        state = STAT_NORMAL;
                        continue;
                    }
                    break;
                case STAT_TYPE:
                    switch (ch) {
                        case SECUREC_CHAR('C'):
                            /* wide char */
                            if (!(formatAttr.flags & (SECUREC_FLAG_SHORT | SECUREC_FLAG_LONG | SECUREC_FLAG_WIDECHAR))) {
#ifdef SECUREC_FOR_WCHAR
                                formatAttr.flags |= SECUREC_FLAG_SHORT;
#else
                                formatAttr.flags |= SECUREC_FLAG_WIDECHAR;
#endif
                            }
                            /* fall-through */
                            /* FALLTHRU */
                        case SECUREC_CHAR('c'):
                            do {
                                unsigned int cValue = (unsigned int)va_arg(argList, int);
                                textLen = SecDecodeTypeC(&formatAttr, cValue, &formatBuf, &buffer);
                                if (textLen < 0) {
                                    noOutput = 1;
                                }
                            } SECUREC_WHILE_ZERO;
                            break;
                        case SECUREC_CHAR('S'):    /* wide char string */
                            if (!(formatAttr.flags & (SECUREC_FLAG_SHORT | SECUREC_FLAG_LONG | SECUREC_FLAG_WIDECHAR))) {
#ifndef SECUREC_FOR_WCHAR
                                formatAttr.flags |= SECUREC_FLAG_WIDECHAR;
#else
                                formatAttr.flags |= SECUREC_FLAG_SHORT;
#endif
                            }
                            /* fall-through */
                            /* FALLTHRU */
                        case SECUREC_CHAR('s'):
                            do {
                                char *argPtr = (char *)va_arg(argList, char *);
                                textLen = SecDecodeTypeS(&formatAttr, argPtr, &formatBuf);
                            } SECUREC_WHILE_ZERO;
                            break;
                        case SECUREC_CHAR('n'):
                            /* higher risk disable it */
                            return -1;
                        case SECUREC_CHAR('E'):    /* fall-through */ /* FALLTHRU */
                        case SECUREC_CHAR('F'):    /* fall-through */ /* FALLTHRU */
                        case SECUREC_CHAR('G'):    /* fall-through */ /* FALLTHRU */
                        case SECUREC_CHAR('A'):    /* fall-through */ /* FALLTHRU */
                            /* convert format char to lower , use Explicit conversion to clean up compilation warning */
                            ch = (SecChar)(ch + ((SecChar)(SECUREC_CHAR('a')) - (SECUREC_CHAR('A'))));
                            /* fall-through */
                            /* FALLTHRU */
                        case SECUREC_CHAR('e'):    /* fall-through */ /* FALLTHRU */
                        case SECUREC_CHAR('f'):    /* fall-through */ /* FALLTHRU */
                        case SECUREC_CHAR('g'):    /* fall-through */ /* FALLTHRU */
                        case SECUREC_CHAR('a'):
#if SECUREC_ENABLE_SPRINTF_FLOAT
                            do {
                            int bufferSize = 0;         /* size of formatBuf.str */
                            /* floating point conversion */
                            formatBuf.str = buffer.str; /* output buffer for float string with default size */

                            /* compute the precision value */
                            if (formatAttr.precision < 0) {
                                formatAttr.precision = SECUREC_FLOAT_DEFAULT_PRECISION;
                            } else if (formatAttr.precision == 0 && ch == SECUREC_CHAR('g')) {
                                formatAttr.precision = 1;
                            }

                            /* calc buffer size to store double value
                             * The maximum length of SECUREC_MAX_WIDTH_LEN is enough
                             */
                            if (formatAttr.flags & SECUREC_FLAG_LONG_DOUBLE) {
                                if (formatAttr.precision > (SECUREC_MAX_WIDTH_LEN - SECUREC_FLOAT_BUFSIZE_LB)) {
                                    noOutput = 1;
                                    break;
                                }
                                /* Long double needs to meet the basic print length */
                                bufferSize = SECUREC_FLOAT_BUFSIZE_LB + formatAttr.precision + SECUREC_FLOAT_BUF_EXT;
                            } else {
                                if (formatAttr.precision > (SECUREC_MAX_WIDTH_LEN - SECUREC_FLOAT_BUFSIZE)) {
                                    noOutput = 1;
                                    break;
                                }
                                /* Double needs to meet the basic print length */
                                bufferSize = SECUREC_FLOAT_BUFSIZE + formatAttr.precision + SECUREC_FLOAT_BUF_EXT;
                            }
                            if (formatAttr.fldWidth > bufferSize) {
                                bufferSize = formatAttr.fldWidth + SECUREC_FLOAT_BUF_EXT;
                            }

                            if (bufferSize > SECUREC_BUFFER_SIZE) {
                                /* the current vlaue of SECUREC_BUFFER_SIZE could NOT store the
                                 * formatted float string
                                 */
                                floatBuf = (char *)SECUREC_MALLOC(((size_t)(unsigned int)bufferSize));
                                if (floatBuf != NULL) {
                                    formatBuf.str = floatBuf;
                                } else {
                                    noOutput = 1;
                                    break;
                                }
                            }

                            do {
                                /* add following code to call system sprintf API for float number */
                                const SecChar *pFloatFmt = format - 2;  /* sub 2 to the position before 'f' or 'g' */
                                int k;
                                int fFmtStrLen;
                                char fFmtBuf[SECUREC_FMT_STR_LEN];
                                char *fFmtStr = fFmtBuf;
                                char *fFmtHeap = NULL;    /* to clear warning */

                                while (SECUREC_CHAR('%') != *pFloatFmt) { /* must meet '%' */
                                    --pFloatFmt;
                                }
                                fFmtStrLen = (int)((format - pFloatFmt) + 1);   /* with ending terminator */
                                if (fFmtStrLen > SECUREC_FMT_STR_LEN) {
                                    /* if SECUREC_FMT_STR_LEN is NOT enough, alloc a new buffer */
                                    fFmtHeap = (char *)SECUREC_MALLOC((size_t)((unsigned int)fFmtStrLen));
                                    if (fFmtHeap == NULL) {
                                        noOutput = 1;
                                        break;
                                    } else {
                                        for (k = 0; k < fFmtStrLen - 1; ++k) {
                                            /* convert wchar to char */
                                            fFmtHeap[k] = (char)(pFloatFmt[k]); /* copy the format string */
                                        }
                                        fFmtHeap[k] = '\0';

                                        fFmtStr = fFmtHeap;
                                    }
                                } else {
                                    /* purpose of the repeat code is to solve the tool alarm  Redundant_Null_Check */
                                    for (k = 0; k < fFmtStrLen - 1; ++k) {
                                        /* convert wchar to char */
                                        fFmtBuf[k] = (char)(pFloatFmt[k]);  /* copy the format string */
                                    }
                                    fFmtBuf[k] = '\0';
                                }

                                if (formatAttr.flags & SECUREC_FLAG_LONG_DOUBLE) {
#ifdef SECUREC_COMPATIBLE_LINUX_FORMAT
                                    long double tmp = (long double)va_arg(argList, long double);
                                    textLen = SecFormatLongDboule(formatBuf.str, &formatAttr, fFmtStr, tmp);
#else
                                    double tmp = (double)va_arg(argList, double);
                                    textLen = SecFormatDboule(formatBuf.str, &formatAttr, fFmtStr, tmp);
#endif
                                } else {
                                    double tmp = (double)va_arg(argList, double);
                                    textLen = SecFormatDboule(formatBuf.str, &formatAttr, fFmtStr, tmp);
                                }

                                if (fFmtHeap != NULL) {
                                    /* if buffer is alloced on heap, free it */
                                    SECUREC_FREE(fFmtHeap);
                                    fFmtHeap = NULL;
                                    /* to clear e438 last value assigned not used , the compiler will
                                     * optimize this code
                                     */
                                    (void)fFmtHeap;
                                }
                                if (textLen < 0 || textLen >= bufferSize) {
                                    /* bufferSize is large enough, just validation the return value */
                                    noOutput = 1;
                                    break;
                                }

                                /* no padding ,this variable to calculate amount of padding */
                                formatAttr.fldWidth = textLen;
                                prefixLen = 0;  /* no padding ,this variable to  calculate amount of padding */
                                formatAttr.flags = 0;   /* clear all internal formatAttr.flags */
                                break;
                            } SECUREC_WHILE_ZERO;
                        } SECUREC_WHILE_ZERO;
                        break;
#else
                            return -1;
#endif
                        case SECUREC_CHAR('p'): /* fall-through */ /* FALLTHRU */
                        case SECUREC_CHAR('X'): /* fall-through */ /* FALLTHRU */
                        case SECUREC_CHAR('x'):
                            /* unsigned lower hex output */
                            digits = itoaLowerDigits;
#define SECUREC_RADIX_HEX                   16
                            radix = SECUREC_RADIX_HEX;
                            switch (ch) {
                                case SECUREC_CHAR('p'):
                                    /* print a pointer */
#if defined(SECUREC_COMPATIBLE_WIN_FORMAT)
                                    formatAttr.flags &= ~SECUREC_FLAG_LEADZERO;
#else
                                    formatAttr.flags |= SECUREC_FLAG_POINTER;
#endif
#ifdef SECUREC_ON_64BITS
                                    formatAttr.flags |= SECUREC_FLAG_I64;   /* converting an int64 */
#else
                                    formatAttr.flags |= SECUREC_FLAG_LONG;  /* converting a long */
#endif

#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) || defined(SECUREC_VXWORKS_PLATFORM)) && (!defined(SECUREC_ON_UNIX))
                                #if defined(SECUREC_VXWORKS_PLATFORM)
                                formatAttr.precision = 1;
#else
                                formatAttr.precision = 0;
#endif
                                formatAttr.flags |= SECUREC_FLAG_ALTERNATE; /* "0x" is not default prefix in UNIX */
                                break;
#else
                                    /* not linux vxwoks */
#if defined(_AIX) || defined(SECUREC_ON_SOLARIS)
                                    formatAttr.precision = 1;
#else
                                    formatAttr.precision = 2 * sizeof(void *);  /* 2 precision of different systems */
#endif
#endif

#if defined(SECUREC_ON_UNIX)
                                    break;
#endif
                                    /* fall-through */ /* FALLTHRU */
                                case SECUREC_CHAR('X'): /* fall-through */ /* FALLTHRU */
                                    /* unsigned upper hex output */
                                    digits = itoaUpperDigits;
                                    break;
                                default:
                                    break;
                            }

                            if (formatAttr.flags & SECUREC_FLAG_ALTERNATE) {
                                /* alternate form means '0x' prefix */
                                prefix[0] = SECUREC_CHAR('0');
                                prefix[1] = (SecChar)(digits[16]); /* 16 for 'x' or 'X' */

#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) || defined(SECUREC_VXWORKS_PLATFORM))
                                if (ch == 'p') {
                                prefix[1] = SECUREC_CHAR('x');
                            }
#endif
#if defined(_AIX) || defined(SECUREC_ON_SOLARIS)
                                if (ch == 'p') {
                                prefixLen = 0;
                            } else {
                                prefixLen = SECUREC_PREFIX_LEN;
                            }
#else
                                prefixLen = SECUREC_PREFIX_LEN;
#endif

                            }
                            /* fall-through */ /* FALLTHRU */
                        case SECUREC_CHAR('i'):    /* fall-through */ /* FALLTHRU */
                        case SECUREC_CHAR('d'):    /* fall-through */ /* FALLTHRU */
                        case SECUREC_CHAR('u'):    /* fall-through */ /* FALLTHRU */
                        case SECUREC_CHAR('o'):    /* fall-through */ /* FALLTHRU */
                            switch (ch) {
                                case SECUREC_CHAR('i'): /* fall-through */ /* FALLTHRU */
                                case SECUREC_CHAR('d'): /* fall-through */ /* FALLTHRU */
                                    /* signed decimal output */
                                    formatAttr.flags |= SECUREC_FLAG_SIGNED;
                                    /* fall-through */ /* FALLTHRU */
                                case SECUREC_CHAR('u'):
                                    radix = SECUREC_RADIX_DECIMAL;
                                    break;
                                case SECUREC_CHAR('o'):
                                    /* unsigned octal output */
#define SECUREC_RADIX_OCTAL                 8
                                    radix = SECUREC_RADIX_OCTAL;
                                    if (formatAttr.flags & SECUREC_FLAG_ALTERNATE) {
                                        /* alternate form means force a leading 0 */
                                        formatAttr.flags |= SECUREC_FLAG_FORCE_OCTAL;
                                    }
                                    break;
                                default:
                                    break;
                            }

                            do {
                                typedef unsigned int SecUnsignedInt32;
                                typedef long long SecInt64;
                                typedef unsigned long long SecUnsignedInt64;
                                SecUnsignedInt64 number = 0;    /* number to convert */
                                SecInt64 l; /* temp long value */

                                /* read argument into variable l */
                                if (formatAttr.flags & SECUREC_FLAG_I64) {
                                    l = (SecInt64)va_arg(argList, SecInt64);
                                } else if (formatAttr.flags & SECUREC_FLAG_LONGLONG) {
                                    l = (SecInt64)va_arg(argList, SecInt64);
                                } else
#ifdef SECUREC_ON_64BITS
                                    if (formatAttr.flags & SECUREC_FLAG_LONG) {
                                l = (long)va_arg(argList, long);
                            } else
#endif /* SECUREC_ON_64BITS */
                                if (formatAttr.flags & SECUREC_FLAG_CHAR) {
                                    if (formatAttr.flags & SECUREC_FLAG_SIGNED) {
                                        l = (char)va_arg(argList, int); /* sign extend */
                                        if (l >= 128) { /* 128 on some platform, char is always unsigned */
                                            SecUnsignedInt64 tmpL = (SecUnsignedInt64)l;
                                            unsigned char tmpCh = (unsigned char)(~(tmpL));
                                            l = tmpCh + 1;
                                            formatAttr.flags |= SECUREC_FLAG_NEGATIVE;
                                        }
                                    } else {
                                        l = (unsigned char)va_arg(argList, int);    /* zero-extend */
                                    }

                                } else if (formatAttr.flags & SECUREC_FLAG_SHORT) {
                                    if (formatAttr.flags & SECUREC_FLAG_SIGNED) {
                                        l = (short)va_arg(argList, int);    /* sign extend */
                                    } else {
                                        l = (unsigned short)va_arg(argList, int);   /* zero-extend */
                                    }

                                }
#ifdef SECUREC_COMPATIBLE_LINUX_FORMAT
                                    else if (formatAttr.flags & SECUREC_FLAG_PTRDIFF) {
                                l = (ptrdiff_t)va_arg(argList, ptrdiff_t);  /* sign extend */
                            } else if (formatAttr.flags & SECUREC_FLAG_SIZE) {
                                if (formatAttr.flags & SECUREC_FLAG_SIGNED) {
                                    /* No suitable macros were found to handle the branch */
                                    if (SecIsSameSize(sizeof(size_t), sizeof(long))) {
                                        l = va_arg(argList, long);  /* sign extend */
                                    } else if (SecIsSameSize(sizeof(size_t), sizeof(long long))) {
                                        l = va_arg(argList, long long); /* sign extend */
                                    } else {
                                        l = va_arg(argList, int);   /* sign extend */
                                    }
                                } else {
                                    l = (SecInt64)(size_t)va_arg(argList, size_t);  /* sign extend */
                                }
                            } else if (formatAttr.flags & SECUREC_FLAG_INTMAX) {
                                if (formatAttr.flags & SECUREC_FLAG_SIGNED) {
                                    l = va_arg(argList, SecInt64);  /* sign extend */
                                } else {
                                    /* sign extend */
                                    l = (SecInt64)(SecUnsignedInt64)va_arg(argList, SecUnsignedInt64);
                                }
                            }
#endif
                                else {
                                    if (formatAttr.flags & SECUREC_FLAG_SIGNED) {
                                        l = va_arg(argList, int);   /* sign extend */
                                    } else {
                                        l = (unsigned int)va_arg(argList, int); /* zero-extend */
                                    }

                                }

                                /* check for negative; copy into number */
                                if ((formatAttr.flags & SECUREC_FLAG_SIGNED) && l < 0) {
                                    number = (SecUnsignedInt64)(-l);
                                    formatAttr.flags |= SECUREC_FLAG_NEGATIVE;
                                } else {
                                    number = (SecUnsignedInt64)l;
                                }

                                if (((formatAttr.flags & SECUREC_FLAG_I64) == 0) &&
                                    #ifdef SECUREC_COMPATIBLE_LINUX_FORMAT
                                    ((formatAttr.flags & SECUREC_FLAG_INTMAX) == 0) &&
                                    #endif
                                    #ifdef SECUREC_ON_64BITS
                                    ((formatAttr.flags & SECUREC_FLAG_PTRDIFF) == 0) &&
                                ((formatAttr.flags & SECUREC_FLAG_SIZE) == 0) &&
#if !defined(SECUREC_COMPATIBLE_WIN_FORMAT)  /* on window 64 system sizeof long is 32bit */
                                ((formatAttr.flags & SECUREC_FLAG_LONG) == 0) &&
#endif
                                    #endif
                                    ((formatAttr.flags & SECUREC_FLAG_LONGLONG) == 0)) {

                                    number &= 0xffffffff;  /* use 0xffffffff as 32 bit mask */
                                }

                                /* check precision value for default */
                                if (formatAttr.precision < 0) {
                                    formatAttr.precision = 1;   /* default precision */
                                } else {
#if defined(SECUREC_COMPATIBLE_WIN_FORMAT)
                                    formatAttr.flags &= ~SECUREC_FLAG_LEADZERO;
#else
                                    if (!(formatAttr.flags & SECUREC_FLAG_POINTER)) {
                                        formatAttr.flags &= ~SECUREC_FLAG_LEADZERO;
                                    }
#endif
#define SECUREC_MAX_PRECISION  SECUREC_BUFFER_SIZE
                                    if (formatAttr.precision > SECUREC_MAX_PRECISION) {
                                        formatAttr.precision = SECUREC_MAX_PRECISION;
                                    }
                                }

                                /* Check if data is 0; if so, turn off hex prefix,
                                 * 'p' add 0x prefix, otherwise not add prefix
                                 */
                                if (number == 0) {
#if !(defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
                                    prefixLen = 0;
#else
                                    if ((ch == 'p') && (formatAttr.flags & SECUREC_FLAG_ALTERNATE)) {
                                    prefixLen = SECUREC_PREFIX_LEN;
                                } else {
                                    prefixLen = 0;
                                }
#endif
                                }

                                /* Convert data to ASCII */
                                formatBuf.str = &buffer.str[SECUREC_BUFFER_SIZE];

                                if (number > 0) {
#ifdef SECUREC_ON_64BITS
                                    switch (radix) {
                                    /* the compiler will optimize each one */
                                    case SECUREC_RADIX_DECIMAL:
                                        SECUREC_SPECIAL_QWORD_BASE10(number);
                                        break;
                                    case SECUREC_RADIX_HEX:
                                        SECUREC_SPECIAL_QWORD(number, SECUREC_RADIX_HEX);
                                        break;
                                    case SECUREC_RADIX_OCTAL:
                                        SECUREC_SPECIAL_QWORD(number, SECUREC_RADIX_OCTAL);
                                        break;
                                    default:
                                        break;
                                }
#else /* for 32 bits system */
                                    if (number <= 0xFFFFFFFFUL) {
                                        /* in most case, the value to be converted is small value */
                                        SecUnsignedInt32 n32Tmp = (SecUnsignedInt32)number;
                                        switch (radix) {
                                            case SECUREC_RADIX_HEX:
#define SECUREC_SPECIAL_DWORD(val32, numBase) do { \
    --formatBuf.str; \
    *(formatBuf.str) = digits[(val32) % (numBase)]; \
} while (((val32) /= (numBase)) != 0)

                                                SECUREC_SPECIAL_DWORD(n32Tmp, SECUREC_RADIX_HEX);
                                                break;
                                            case SECUREC_RADIX_OCTAL:
                                                SECUREC_SPECIAL_DWORD(n32Tmp, SECUREC_RADIX_OCTAL);
                                                break;

#ifdef _AIX
                                            /* the compiler will optimize div 10 */
                                        case SECUREC_RADIX_DECIMAL:
                                            SECUREC_SPECIAL_DWORD(n32Tmp, SECUREC_RADIX_DECIMAL);
                                            break;
#else
                                            case SECUREC_RADIX_DECIMAL:
                                                do {
                                                    /* fast div 10 */
                                                    SecUnsignedInt32 q;
                                                    SecUnsignedInt32 r;
                                                    do {
                                                        *--formatBuf.str = digits[n32Tmp % SECUREC_RADIX_DECIMAL];
                                                        q = (n32Tmp >> 1) + (n32Tmp >> 2); /* fast div  magic 2 */
                                                        q = q + (q >> 4); /* fast div  magic 4 */
                                                        q = q + (q >> 8); /* fast div  magic 8 */
                                                        q = q + (q >> 16); /* fast div  magic 16 */
                                                        q = q >> 3; /* fast div  magic 3 */
                                                        r = n32Tmp - SECUREC_MUL_TEN(q);
                                                        n32Tmp = (r > 9) ? (q + 1) : q; /* fast div  magic 9 */
                                                    } while (n32Tmp != 0);
                                                } SECUREC_WHILE_ZERO;
                                                break;
#endif
                                            default:
                                                break;
                                        }   /* end switch */
                                    } else {
                                        /* the value to be converted is greater than 4G */
#if defined(SECUREC_VXWORKS_VERSION_5_4)
                                        do {
                                        SecUnsignedInt32 digit = 0; /* ascii value of digit */
                                        SecUnsignedInt64 quotient = 0;
                                        if (SecU64Div32(number,(SecUnsignedInt32)radix, &quotient, &digit) != 0) {
                                            noOutput = 1;
                                            break;
                                        }
                                        *--formatBuf.str = digits[digit];
                                        number = quotient;
                                    } while (number != 0);
#else
                                        switch (radix) {
                                            /* the compiler will optimize div 10 */
                                            case SECUREC_RADIX_DECIMAL:
#define SECUREC_SPECIAL_QWORD_BASE10(val64) do { \
    SecUnsignedInt64 quotient = 0; \
    SecUnsignedInt32 digit = 0; \
    SecU64Div10((val64), &(quotient), &(digit)); \
    --formatBuf.str; \
    *(formatBuf.str) = digits[digit]; \
    (val64) = quotient; \
} while ((val64) != 0)
                                                SECUREC_SPECIAL_QWORD_BASE10(number);
                                                break;
                                            case SECUREC_RADIX_OCTAL:
#define SECUREC_SPECIAL_QWORD(val64, numBase) do { \
    --formatBuf.str; \
    *(formatBuf.str) = digits[(val64) % (numBase)]; \
} while (((val64) /= (numBase)) != 0)
                                                SECUREC_SPECIAL_QWORD(number, SECUREC_RADIX_OCTAL);
                                                break;
                                            case SECUREC_RADIX_HEX:
                                                SECUREC_SPECIAL_QWORD(number, SECUREC_RADIX_HEX);
                                                break;
                                            default:
                                                break;
                                        }
#endif
                                    }
#endif

                                }
                                /* compute length of number,.if textLen > 0, then formatBuf.str must be in buffer.str */
                                textLen = (int)(size_t)((char *)&buffer.str[SECUREC_BUFFER_SIZE] - formatBuf.str);
                                if (formatAttr.precision > textLen) {
                                    int ii;
                                    for (ii = 0; ii < formatAttr.precision - textLen; ++ii) {
                                        *--formatBuf.str = '0';
                                    }
                                    textLen = formatAttr.precision;
                                }

                                /* Force a leading zero if FORCEOCTAL flag set */
                                if ((formatAttr.flags & SECUREC_FLAG_FORCE_OCTAL) &&
                                    (textLen == 0 || formatBuf.str[0] != '0')) {
                                    *--formatBuf.str = '0';
                                    ++textLen;  /* add a zero */
                                }
                            } SECUREC_WHILE_ZERO;
                            break;
                        default:
                            break;
                    }

                    while (noOutput < 1) {
                        if (formatAttr.flags & SECUREC_FLAG_SIGNED) {
                            if (formatAttr.flags & SECUREC_FLAG_NEGATIVE) {
                                /* prefix is a '-' */
                                prefix[0] = SECUREC_CHAR('-');
                                prefixLen = 1;
                            } else if (formatAttr.flags & SECUREC_FLAG_SIGN) {
                                /* prefix is '+' */
                                prefix[0] = SECUREC_CHAR('+');
                                prefixLen = 1;
                            } else if (formatAttr.flags & SECUREC_FLAG_SIGN_SPACE) {
                                /* prefix is ' ' */
                                prefix[0] = SECUREC_CHAR(' ');
                                prefixLen = 1;
                            }
                        }

#if defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && (!defined(SECUREC_ON_UNIX))
                        if ((formatAttr.flags & SECUREC_FLAG_POINTER) && (textLen == 0)) {
                        formatAttr.flags &= ~SECUREC_FLAG_LEADZERO;
                        formatBuf.str = &buffer.str[SECUREC_BUFFER_SIZE - 1];
                        *formatBuf.str-- = '\0';
                        *formatBuf.str-- = ')';
                        *formatBuf.str-- = 'l';
                        *formatBuf.str-- = 'i';
                        *formatBuf.str-- = 'n';
                        *formatBuf.str = '(';
                        textLen = 5; /* length of (nil) is 5 */
                    }
#endif

                        /* calculate amount of padding */
                        padding = (formatAttr.fldWidth - textLen) - prefixLen;

                        /* put out the padding, prefix, and text, in the correct order */

                        if (!(formatAttr.flags & (SECUREC_FLAG_LEFT | SECUREC_FLAG_LEADZERO)) && padding > 0) {
                            /* pad on left with blanks */
                            if (SECUREC_IS_REST_BUF_ENOUGH(stream, padding)) {
                                /* char * cast to wchar * */
#define SECUREC_SAFE_PADDING(padChar, padLen, outStream, outChars) do { \
    int ii_; \
    for (ii_ = 0; ii_ < (padLen); ++ii_) { \
        *((SecChar *)(void *)((outStream)->cur)) = (SecChar)(padChar); \
        (outStream)->cur += sizeof(SecChar); \
    } \
    (outStream)->count -= (padLen) * (int)(sizeof(SecChar)); \
    *(outChars) = *(outChars) + (padLen); \
} SECUREC_WHILE_ZERO
                                SECUREC_SAFE_PADDING(SECUREC_CHAR(' '), padding, stream, &charsOut);
                            } else {
#define SECUREC_WRITE_MULTI_CHAR  SecWriteMultiChar
                                SECUREC_WRITE_MULTI_CHAR(SECUREC_CHAR(' '), padding, stream, &charsOut);
                            }
                        }

                        /* write prefix */
                        if (prefixLen > 0) {
                            SecChar *pPrefix = prefix;
                            if (SECUREC_IS_REST_BUF_ENOUGH(stream, prefixLen)) {
                                /* max prefix len is 2, use loop copy */ /* char * cast to wchar * in WCHAR version */
#define SECUREC_SAFE_WRITE_STR_OPT(src, txtLen, outStream, outChars) do { \
    int ii_; \
    for (ii_ = 0; ii_ < (txtLen); ++ii_) { \
        *((SecChar *)(void *)((outStream)->cur)) = *(SecChar *)(src); \
        (outStream)->cur += sizeof(SecChar); \
        (src) = (src) + 1; \
    } \
    (outStream)->count -= (txtLen) * (int)(sizeof(SecChar)); \
    *(outChars) = *(outChars) + (txtLen); \
} SECUREC_WHILE_ZERO
                                SECUREC_SAFE_WRITE_STR_OPT(pPrefix, prefixLen, stream, &charsOut);
                            } else {
#define SECUREC_WRITE_STRING      SecWriteString
                                SECUREC_WRITE_STRING(prefix, prefixLen, stream, &charsOut);
                            }
                        }

                        if ((formatAttr.flags & SECUREC_FLAG_LEADZERO) && !(formatAttr.flags & SECUREC_FLAG_LEFT)
                            && padding > 0) {
                            /* write leading zeros */
                            if (SECUREC_IS_REST_BUF_ENOUGH(stream, padding)) {
                                /* char * cast to wchar * */
                                SECUREC_SAFE_PADDING(SECUREC_CHAR('0'), padding, stream, &charsOut);
                            } else {
                                SECUREC_WRITE_MULTI_CHAR(SECUREC_CHAR('0'), padding, stream, &charsOut);
                            }
                        }

                        /* write text */
#ifndef SECUREC_FOR_WCHAR
                        if (formatAttr.bufferIsWide != 0 && (textLen > 0)) {
#if SECUREC_HAVE_WCTOMB
                            wchar_t *p = formatBuf.wStr;
                        int count = textLen;
                        while (count > 0) {
                            char tmpBuf[SECUREC_MB_LEN + 1];
                            SECUREC_MASK_MSVC_CRT_WARNING
                            int retVal = wctomb(tmpBuf, *p);
                            SECUREC_END_MASK_MSVC_CRT_WARNING
                            if (retVal <= 0) {
                                charsOut = -1;
                                break;
                            }
                            SECUREC_WRITE_STRING(tmpBuf, retVal, stream, &charsOut);
                            --count;
                            ++p;
                        }
#else
                            charsOut = -1;
                            break;
#endif
                        } else {
                            if (SECUREC_IS_REST_BUF_ENOUGH(stream, textLen)) {
#define SECUREC_SAFE_WRITE_STR_OPT(src, txtLen, outStream, outChars) do { \
    int ii_; \
    for (ii_ = 0; ii_ < (txtLen); ++ii_) { \
        *((SecChar *)(void *)((outStream)->cur)) = *(SecChar *)(src); \
        (outStream)->cur += sizeof(SecChar); \
        (src) = (src) + 1; \
    } \
    (outStream)->count -= (txtLen) * (int)(sizeof(SecChar)); \
    *(outChars) = *(outChars) + (txtLen); \
} SECUREC_WHILE_ZERO

#define SECUREC_SAFE_WRITE_STR(src, txtLen, outStream, outChars) do { \
    if ((txtLen) < 12) { /* performance optimization for mobile number length 12 */ \
        SECUREC_SAFE_WRITE_STR_OPT((src), (txtLen), (outStream), (outChars)); \
    } else { \
        my_memcpy((outStream)->cur, (src), ((size_t)(unsigned int)(txtLen) * (sizeof(SecChar)))); \
        (outStream)->cur += (size_t)((size_t)(unsigned int)(txtLen) * (sizeof(SecChar))); \
        (outStream)->count -= (txtLen) * (int)(sizeof(SecChar)); \
        *(outChars) = *(outChars) + (txtLen); \
    } \
} SECUREC_WHILE_ZERO
                                SECUREC_SAFE_WRITE_STR(formatBuf.str, textLen, stream, &charsOut);
                            } else {
                                SECUREC_WRITE_STRING(formatBuf.str, textLen, stream, &charsOut);
                            }
                        }
#else /* SECUREC_FOR_WCHAR */
                        if (formatAttr.bufferIsWide == 0 && textLen > 0) {
#if SECUREC_HAVE_MBTOWC
                        int count = textLen;
                        char *p = formatBuf.str;

                        while (count > 0) {
                            wchar_t wChar = L'\0';
                            int retVal = mbtowc(&wChar, p, (size_t)MB_CUR_MAX);
                            if (retVal <= 0) {
                                charsOut = -1;
                                break;
                            }
                            SecWriteCharW(wChar, stream, &charsOut);
                            p += retVal;
                            count -= retVal;
                        }
#else
                        charsOut = -1;
                        break;
#endif
                    } else {
                        if (SECUREC_IS_REST_BUF_ENOUGH(stream, textLen)) {
                            /* char * cast to wchar * */
                            SECUREC_SAFE_WRITE_STR(formatBuf.wStr, textLen, stream, &charsOut);
                        } else {
                            SECUREC_WRITE_STRING(formatBuf.wStr, textLen, stream, &charsOut);
                        }
                    }
#endif /* SECUREC_FOR_WCHAR */

                        if (charsOut >= 0 && (formatAttr.flags & SECUREC_FLAG_LEFT) && padding > 0) {
                            /* pad on right with blanks */
                            if (SECUREC_IS_REST_BUF_ENOUGH(stream, padding)) {
                                /* char * cast to wchar * */
                                SECUREC_SAFE_PADDING(SECUREC_CHAR(' '), padding, stream, &charsOut);
                            } else {
                                SECUREC_WRITE_MULTI_CHAR(SECUREC_CHAR(' '), padding, stream, &charsOut);
                            }
                        }
                        break;
                    }
#if SECUREC_ENABLE_SPRINTF_FLOAT
                if (floatBuf != NULL) {
                    SECUREC_FREE(floatBuf);
                    floatBuf = NULL;
                }
#endif
                    break;
                case STAT_INVALID:
                    return -1;
                default:
                    return -1;          /* input format is wrong, directly return */
            }
        }

        if (state != STAT_NORMAL && state != STAT_TYPE) {
            return -1;
        }

        return charsOut;            /* the number of characters written */
    }




    IN_LINE int SecVsnprintfImpl(char *string, size_t count, const char *format, va_list argList)
    {
        SecPrintfStream str;
        int retVal;

        str.count = (int)count; /* this count include \0 character, Must be greater than zero */
        str.cur = string;

        retVal = SecOutputS(&str, format, argList);
#define SECUREC_PUTC_ZERO(outStream)    ((--(outStream)->count >= 0) ? \
    ((*((outStream)->cur++) = (char)('\0'))) : EOF)

        if ((retVal >= 0) && (SECUREC_PUTC_ZERO(&str) != EOF)) {
            return retVal;
        } else if (str.count < 0) {
            /* the buffer was too small; we return truncation */
            string[count - 1] = '\0';
            return SECUREC_PRINTF_TRUNCATE;
        }
        string[0] = '\0'; /* empty the dest strDest */
        return -1;
    }

    IN_LINE int vsnprintf_s(char *strDest, size_t destMax, size_t count, const char *format, va_list argList)
    {
        int retVal;

        if (format == NULL || strDest == NULL || destMax == 0 || destMax > SECUREC_STRING_MAX_LEN ||
            (count > (SECUREC_STRING_MAX_LEN - 1) && count != (size_t)(-1))) {
            if (strDest != NULL && destMax > 0 && destMax <= SECUREC_STRING_MAX_LEN) {
                strDest[0] = '\0';
            }
            return -1;
        }

        if (destMax > count) {
            retVal = SecVsnprintfImpl(strDest, count + 1, format, argList);
            if (retVal == SECUREC_PRINTF_TRUNCATE) {  /* lsd add to keep dest buffer not destroyed 2014.2.18 */
                /* the string has been truncated, return  -1 */
                return -1;          /* to skip error handler,  return strlen(strDest) or -1 */
            }
        } else {
            retVal = SecVsnprintfImpl(strDest, destMax, format, argList);
        }

        if (retVal < 0) {
            strDest[0] = '\0';      /* empty the dest strDest */
            return -1;
        }

        return retVal;
    }







