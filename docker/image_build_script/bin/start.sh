#!/bin/bash

if [ $# != 2 ];then
echo "usage: $0 NAME BASE_PORT"
exit 255
fi
if [ ! -f "input_elf" ];then
echo "please rename pwn file to input_elf"
exit 255
fi
chmod +x input_elf
image_name=$1
container_name="${image_name}1"
base_port=$2
analysis_port=$base_port
redirect_port=$base_port
let redirect_port=redirect_port+1
test_port=$base_port
let test_port=test_port+2
io_decrypt_port=$base_port
let io_decrypt_port=io_decrypt_port+3
ssh_server_port=$base_port
let ssh_server_port=base_port+4
local_sandbox_port=base_port
let local_sandbox_port=local_sandbox_port+5
echo "Docker Image Name:        $image_name"
echo "Docker Container Name:    $container_name"
echo "Record Analysis Port:     $analysis_port"
echo "Sandbox Redirect Port:    $redirect_port"
echo "Local Test Port:          $test_port"
echo "IO Decrypt Port:          $io_decrypt_port"
echo "SSH Server Port:          $ssh_server_port"
echo "Local Sandbox Port:       $local_sandbox_port"


sed -i "s/    HOST, PORT = \"0.0.0.0\",.*/    HOST, PORT = \"0.0.0.0\",$analysis_port/g" auto_tracficc_anslysis.py
if [ ! -z "$(cat auto_tracficc_anslysis.py|grep $analysis_port)" ];then
    echo "success set auto_tracficc_anslysis.py to listen:    $analysis_port"
else
    echo "failed  set auto_tracficc_anslysis.py to listen:    $analysis_port"
    exit 255
fi

sed -i "s/    port        = .*/    port        = $redirect_port/g" ctf.xinetd
if [ ! -z "$(cat ctf.xinetd|grep $redirect_port)" ];then
    echo "success set ctf.xinetd to listen:                   $redirect_port"
else
    echo "failed  set ctf.xinetd to listen:                   $redirect_port"
    exit 255
fi

sed -i "s/    port        = .*/    port        = $test_port/g" ctf.xinetd.test
if [ ! -z "$(cat ctf.xinetd.test|grep $test_port)" ];then
    echo "success set ctf.xinetd.test to listen:              $test_port"
else
    echo "failed  set ctf.xinetd.test to listen:              $test_port"
    exit
fi

sed -i "s/#define SANDBOX_PORT .*/#define SANDBOX_PORT $io_decrypt_port/g" main.h
if [ ! -z "$(cat main.h|grep $io_decrypt_port)" ];then
    echo "success set main.h sandbox port to io decrypt port: $io_decrypt_port"
else
    echo "failed set main.h sandbox port to io decrypt port: $io_decrypt_port"
    exit 255
fi

sed -i "s/#define REDIRECT_PORT .*/#define REDIRECT_PORT $analysis_port/g" main.h
if [ ! -z "$(cat main.h|grep $analysis_port)" ];then
    echo "success set main.h redirect port to analysis port:  $analysis_port"
else
    echo "failed  set main.h redirect port to analysis port:  $analysis_port"
    exit 255
fi

sed -i "s/    HOST, PORT = \"0.0.0.0\".*/    HOST, PORT = \"0.0.0.0\",$io_decrypt_port/g" io_decrypt_server.py
if [ ! -z "$(cat io_decrypt_server.py|grep $io_decrypt_port)" ];then
    echo "success set io_decrypt_server.py to listen:         $io_decrypt_port"
else
    echo "failed  set io_decrypt_server.py to listen:         $io_decrypt_port"
    exit 255
fi

sed -i "s/    UPSTREAM_HOST,UPSTREAM_PORT = \"127.0.0.1\".*/    UPSTREAM_HOST,UPSTREAM_PORT = \"127.0.0.1\",$redirect_port/g" io_decrypt_server.py
if [ ! -z "$(cat io_decrypt_server.py|grep $redirect_port)" ];then
    echo "success set io_decrypt_server.py upstream port:     $redirect_port"
else
    echo "failed  set io_decrypt_server.py upstream port:     $redirect_port"
    exit 255
fi

sed -i "s/    port        = .*/    port        = $local_sandbox_port/g" sandbox.xinetd
if [ ! -z "$(cat sandbox.xinetd|grep $local_sandbox_port)" ];then
    echo "success set sandbox.xinetd to listen:               $local_sandbox_port"
else
    echo "failed  set sandbox.xinetd to listen:               $local_sandbox_port"
    exit
fi


if [ ! -z "$(file input_elf|grep 80386)" ];then
    echo "target is i386"
    make -f hook.makefile x32
elif [ ! -z "$(file input_elf|grep x86-64)" ];then
    echo "target is amd64"
    make -f hook.makefile x64
elif [ ! -z "$(file input_elf|grep arm)" ];then
    echo "target is arm,not support yet"
    exit 255
    make -f hook.makefile arm
else
    echo "unknown file type: $(file input_elf)"
    exit 255
fi


docker stop $container_name
docker rm $container_name
docker rmi $image_name
docker build ./ -t $image_name
docker run -d -p 0.0.0.0:$analysis_port:$analysis_port -p 0.0.0.0:$redirect_port:$redirect_port -p 0.0.0.0:$test_port:$test_port -p 0.0.0.0:$io_decrypt_port:$io_decrypt_port -p 0.0.0.0:$ssh_server_port:22 -p 0.0.0.0:$local_sandbox_port:$local_sandbox_port --name $container_name --privileged=true $image_name