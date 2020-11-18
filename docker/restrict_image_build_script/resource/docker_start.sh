#!/bin/bash

/root/init.sh

mkdir /home/ctf/proc && mount -t proc proc /home/ctf/proc

cp /root/sandbox_elf /home/ctf/sandbox_elf

#/etc/init.d/xinetd restart
#/usr/sbin/xinetd -dontfork -stayalive -inetd_compat -d 2>&1 >> /var/log/xinetd.debug.log &

/etc/init.d/ssh restart

python3 /root/io_decrypt_server.py IO_DECRYPT_LISTEN_HOST IO_DECRYPT_LISTEN_PORT IO_DECRYPT_UPSTREAM_HOST IO_DECRYPT_UPSTREAM_PORT &
/root/stage_socket_server STAGE_NORMAL_SOCKET_SERVER_PORT /root/normal.datafile    2>&1 > /root/log/stage_normal_socket_server.log &
/root/stage_socket_server STAGE_SANDBOX_SOCKET_SERVER_PORT /root/sandbox.datafile  2>&1 > /root/log/stage_sandbox_socket_server.log &

#python3 /root/analysis_server.py  ANALYSIS_SERVER_HOST ANALYSIS_SERVER_PORT /root/  /root/input_elf /root/libc.so 0
#python3 verify.py  /root/ /root/input_elf /root/libc.so  #we must start tmux before this command
#python3 repeater.py  /root/ /root/input_elf

sleep infinity;
