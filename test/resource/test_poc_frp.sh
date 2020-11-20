#!/bin/bash

cd /root/
killall python
killall python3
killall stage_socket_server
chmod +x /root/frps
chmod +x /root/frpc
python3 /root/io_decrypt_server.py 127.0.0.1 60103 127.0.0.1 60001 2>&1 > /root/log/io_decrypt_server.log &
/root/stage_socket_server 60106 /root/normal.datafile    2>&1 > /root/log/stage_normal_socket_server.log &
/root/stage_socket_server 60107 /root/sandbox.datafile  2>&1 > /root/log/stage_sandbox_socket_server.log &

python3 /root/analysis_server.py  0.0.0.0 60100 /root/  /root/input_elf /root/libc.so 1  &
tmux splitw -h -p 50 'python3 /root/verify.py  /root/ /root/input_elf /root/libc.so'
tmux selectp -t 0
tmux splitw -v -p 50 '/root/frps -c /root/frps.ini'
sleep 3
tmux selectp -t 1
tmux splitw -v -p 50 '/root/frpc -c /root/frpc.ini'
sleep 10
tmux selectp -t 3
chmod +x /root/poc.sh
tmux splitw -v -p 50 '/root/poc.sh'
sleep 5

while [ "x" == "x" ];
do

  if [ -z "$(ls /root/ori_verify_success 2>/dev/null)" ];then
    sleep 1
    echo "wait ori poc success............"
    continue
  fi

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
killall frps
killall frpc


sleep 2
#bash



#python3 repeater.py  /root/ /root/input_elf