# v5
开启v5：
- 在CMkaeList.txt 中`set(IS_V5 true)`
- 在config.json 中添加key为`v5`的键值对（值无所谓）




# -HookUtilV3  
 HookUtilV3

#DataFile Structure  
stage_three_code is XOR encrypt  
<--stage_two_struct-->  
<--starge_two_code-->  
<--stage_three_struct-->   
<--stage_three_code>  

# stage_one  
stage_one entry must in stage_one .text start byte

# stage_two
stage_two entry must in stage_two .text start byte, in order to decrease stage_one bytes

# MUST
1. we should disable docker userland-proxy
/etc/docker/daemon.json
{
    "userland-proxy": false
}
2. normal_mode should use select,should not use no block mode io
