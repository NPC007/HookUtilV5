#!/bin/bash

/etc/init.d/xinetd restart
/etc/init.d/ssh restart
python3 /root/io_decrypt_server.py IO_DECRYPT_LISTEN_HOST IO_DECRYPT_LISTEN_PORT IO_DECRYPT_UPSTREAM_HOST IO_DECRYPT_UPSTREAM_PORT
#python3 /root/analysis_server.py  ANALYSIS_SERVER_HOST ANALYSIS_SERVER_PORT /root/  /root/input_elf /root/libc.so

sleep infinity;
