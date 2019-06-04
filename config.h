#define IS_PIE 1
#define LIB_C_START_MAIN "0x0"
#define PATCH_DATA_PATH "/root/ctf/aa.dat"
#define PATCH_DATA_MMAP_FILE_BASE 0x34567000
//total file size
#define PATCH_DATA_MMAP_FILE_SIZE 0x40000
//stage two code load base
#define PATCH_DATA_MMAP_CODE_BASE 0x77880000
//really patch entry
#define PATCH_FIRT_ENTRY 0x0




#define TCP_TIME_OUT 1
#define REDIRECT_HOST "10.10.1.112"
#define REDIRECT_PORT 30010

#define SHELL_PASSWD "!Huawei12#$"

//USE_IO_INLINE_REDIRECT means inline hook read and write libc function, when tcp socket fail(may be connection failed or REDIRECT_HOST or REDIRECT_port no config), it fail back to record io data in IO_REDIRECT_PATH
#define USE_IO_INLINE_REDIRECT 0

