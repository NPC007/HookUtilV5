# -HookUtilV3  
 HookUtilV3

#DataFile Structure  
stage_three_code is XOR encrypt  
<--stage_two_struct-->  
<--starge_two_code-->  
<--stage_three_struct-->   
<--stage_three_code>  

#stage_one  
stage_one entry must in stage_one .text start byte

# MUST
1. we should disable docker userland-proxy
/etc/docker/daemon.json
{
    "userland-proxy": false
}
2. normal_mode should use select,should not use no block mode io
