#ifndef HOOKUTILV2_LIBRARY_H
#define HOOKUTILV2_LIBRARY_H

#include <elf.h>
#include <link.h>
#include <netinet/in.h>

#define Elf_Ehdr ElfW(Ehdr)
#define Elf_Shdr ElfW(Shdr)
#define Elf_Chdr ElfW(Chdr)
#define Elf_Sym ElfW(Sym)
#define Elf_Syminfo ElfW(Syminfo)
#define Elf_Rel ElfW(Rel)
#define Elf_Rela ElfW(Rela)
#define Elf_Phdr ElfW(Phdr)
#define Elf_Dyn ElfW(Dyn)
#define Elf_Verdef ElfW(Verdef)
#define Elf_Verdaux ElfW(Verdaux)
#define Elf_Verneed ElfW(Verneed)
#define Elf_Vernaux ElfW(Vernaux)
#define Elf_auxv_t ElfW(auxv_t)
#define Elf_Nhdr ElfW(Nhdr)
#define Elf_Move ElfW(Move)
#define Elf_Lib ElfW(Lib)

enum PACKET_TYPE{
    DATA_IN = 1,
    DATA_OUT,
    DATA_ERR,
    BASE_ELF,
    BASE_LIBC,
    BASE_STACK,
    BASE_HEAP,
    MAP_ADD,
    MAP_DELETE
};



typedef struct LOADER_STAGE_TWO{
    int length;           // datafile_generate init
    int entry_offset;     // datafile_generate init
    int patch_data_length;// stage_one runtime init
    void* elf_load_base;  // stage_one runtime init
}LOADER_STAGE_TWO;

typedef struct LOADER_STAGE_THREE{
    int length;                      // datafile_generate init
    int entry_offset;                // datafile_generate init
    void* elf_load_base;             // stage_two runtime init
    void* patch_data_mmap_code_base; // stage_two runtime init
    void* patch_data_mmap_file_base; // stage_two runtime init
    int patch_data_length;           // stage_two runtime init
    int enable_debug;                // stage_two runtime init
    char shell_password[64];         // datafile_generate init
    struct sockaddr_in analysis_server; // datafile_generate init
    struct sockaddr_in sandbox_server;  // datafile_generate init
}LOADER_STAGE_THREE;

#define LOAD_FROM_FILE      1
#define LOAD_FROM_MEM       2
#define LOAD_FROM_SHARE_MEM 3
#define LOAD_FROM_SOCKET    4

#define CODE 1
#define PTR 2

#define UP_PADDING(X,Y)  ((unsigned long)((((unsigned long)(X))/((unsigned long)(Y))+1)*((unsigned long)(Y))))
#define DOWN_PADDING(X,Y) ((unsigned long)(((unsigned long)(X))-((unsigned long)(X))%((unsigned long)(Y))))

#define PROT_READ	0x1     /* Page can be read.  */
#define PROT_WRITE	0x2     /* Page can be written.  */
#define PROT_EXEC	0x4     /* Page can be executed.  */
#define PROT_NONE	0x0     /* Page can not be accessed.  */

#define MAP_SHARED	0x01		/* Share changes.  */
#define MAP_PRIVATE	0x02		/* Changes are private.  */
#define MAP_ANONYMOUS	0x20		/* Don't use a file.  */

#define SYSCALL_DYNAMIC 0
#define SANDBOX_XOR_KEY "\xf5\xe4\xd2\xc9\xb2\xa9\xd0\x9f\xa3\xf5\xd9"



#define FAKE_MIN_ADDR 4*024*1024

#endif