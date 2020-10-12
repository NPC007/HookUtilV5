#!/bin/bash

/etc/init.d/xinetd restart
/etc/init.d/ssh restart
python3 /root/io_decrypt_server.py IO_DECRYPT_LISTEN_HOST IO_DECRYPT_LISTEN_PORT IO_DECRYPT_UPSTREAM_HOST IO_DECRYPT_UPSTREAM_PORT

#python3 /root/analysis_server.py  ANALYSIS_SERVER_HOST ANALYSIS_SERVER_PORT /root/  /root/input_elf /root/libc.so 0
#python3 verify.py  /root/ /root/input_elf /root/libc.so
#python3 repeater.py  /root/ /root/input_elf

sleep infinity;
