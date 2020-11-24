#include <stage_three/common.h>

void test_syscall(){
    for(int i=0;i<200;i++){
        _test_syscall(i);
    }
}

void _start(){
    g_loader_param.enable_debug = 1;
    test_syscall();
}