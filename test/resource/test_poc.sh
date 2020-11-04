#!/bin/bash

cd /root/
python3 /root/analysis_server.py  0.0.0.0 10000 /root/  /root/input_elf /root/libc.so 0  &
tmux splitw -h -p 50 'python3 /root/verify.py  /root/ /root/input_elf /root/libc.so'
sleep 2
tmux splitw -v -p 50 'python2 /root/poc.py'
tmux selectp -t 0
bash


#python3 repeater.py  /root/ /root/input_elf