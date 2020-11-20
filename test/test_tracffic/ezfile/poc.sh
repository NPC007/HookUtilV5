#!/bin/bash

while [ "x" == "x" ];
do
  python2 /root/poc.py
  ret=$?
  if [ $ret == 0 ];then
    break;
  fi
  echo "ori verify failed, try again..........."
done
touch /root/ori_verify_success
echo "ori verify success"
sleep 10