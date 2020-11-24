#ifndef __LOADER_X64_H__
#define __LOADER_X64_H__


//#define LIBC_START_MAIN_ARG int(*MAIN)(int,char**,char**),int ARGC,char **UBP_AV
//#define LIBC_START_MAIN_ARG_PROTO int(*)(int,char**,char**),int,char **
//#define LIBC_START_MAIN_ARG_VALUE MAIN,ARGC,UBP_AV

#define STAGE_ONE_MAIN_ARG int(*MAIN)(int,char**,char**),int ARGC,char **UBP_AV
#define STAGE_ONE_MAIN_ARG_PROTO int(*)(int,char**,char**),int,char **
#define STAGE_ONE_MAIN_ARG_VALUE MAIN,ARGC,UBP_AV

#define STAGE_TWO_MAIN_ARG  char **UBP_AV
#define STAGE_TWO_MAIN_ARG_PROTO char **
#define STAGE_TWO_MAIN_ARG_VALUE UBP_AV


#define STAGE_THREE_MAIN_ARG  int ARGC,char **UBP_AV
#define STAGE_THREE_MAIN_ARG_PROTO int,char **
#define STAGE_THREE_MAIN_ARG_VALUE ARGC,UBP_AV


#endif