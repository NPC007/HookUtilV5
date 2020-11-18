#!/bin/bash

cd /root/
python3 /root/analysis_server.py  0.0.0.0 60000 /root/  /root/input_elf /root/libc.so 1  &
tmux splitw -h -p 50 'python3 /root/verify.py  /root/ /root/input_elf /root/libc.so'
sleep 10
tmux splitw -v -p 50 'python2 /root/poc.py'
tmux selectp -t 0
sleep 5

while [ "x" == "x" ];
do
  if [ -z "$(ls /root/local_verify_failed)" ];then
    if [ -z "$(ls /root/local_verify_success)" ];then
      sleep 1
      continue
    fi
  fi
  sleep 4

  if [ ! -z "$(ls /root/local_verify_success)" ];then
    echo "verify success#######################################################################################################"
    touch /root/verify_success.flag
    break
  fi
  if [ ! -z "$(ls /root/local_verify_failed)" ];then
    echo "verify failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    touch /root/verify_failed.flag
    break
  fi
done

#bash
killall python3
killall python
killall python2



sleep 2
#bash



#python3 repeater.py  /root/ /root/input_elf