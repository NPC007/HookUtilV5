#ifndef __LOADER_X86_H__
#define __LOADER_X86_H__

#define NO_AUX

#ifdef NO_AUX

#define LIBC_START_MAIN_ARG void* __SHOULD_NOT_USED_SAVED_EBX,int(*MAIN)(int,char**,char**),int ARGC,char **UBP_AV,void(*INIT)(void),void(*FINI)(void),void(*RTLD_FINI)(void),void* STACK_END
#define LIBC_START_MAIN_ARG_PROTO void*,int(*)(int,char**,char**),int,char **,void(*)(void),void(*)(void),void(*)(void),void*
#define LIBC_START_MAIN_ARG_VALUE __SHOULD_NOT_USED_SAVED_EBX,MAIN,ARGC,UBP_AV,INIT,FINI,RTLD_FINI,STACK_END
#else

#endif

#endif