#!/bin/bash

base_port=__BASE_PORT__
analysis_port=$base_port
redirect_port=$base_port
let redirect_port=$base_port+1
test_port=$base_port
let test_port=$base_port+2
io_decrypt_port=$base_port
let io_decrypt_port=$base_port+3
ssh_server_port=$base_port
let ssh_server_port=base_port+4
local_sandbox_port=base_port
let local_sandbox_port=base_port+5
stage_normal_socket_server=base_port
let stage_normal_socket_server=base_port+6
stage_sandbox_socket_server=base_port
let stage_sandbox_socket_server=base_port+7
#echo "Docker Image Name:              $image_name"
#echo "Docker Container Name:          $container_name"
echo "Record Analysis Port:           $analysis_port"
echo "Sandbox Redirect Port:          $redirect_port"
echo "Local Test Port:                $test_port"
echo "IO Decrypt Port:                $io_decrypt_port"
echo "SSH Server Port:                $ssh_server_port"
echo "Local Sandbox Port:             $local_sandbox_port"
echo "Stage Normal Socket Server Port:        $stage_normal_socket_server"
echo "Stage Sandbox Socket Server Port:       $stage_sandbox_socket_server"


sed -i "s/60002/${test_port}/g" /root/translate_traccfic_to_poc.py

python3 /root/analysis_server.py  0.0.0.0 ${analysis_port} /root/  /root/input_elf /root/libc.so 1  &
tmux splitw -h -p 50 'python3 /root/verify.py  /root/ /root/input_elf /root/libc.so'
tmux selectp -t 0
chmod +x /root/frpc
tmux splitw -v -p 50 'while [ "x" == "x" ];do /root/frpc -c /root/frpc.ini;sleep 2;done'
tmux selectp -t 2
tmux splitw -v -p 50 'bash'
sleep 10
bash