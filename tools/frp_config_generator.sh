#!/bin/bash

usage(){
  echo "Usage: $0 GAMEBOX_IP LOCAL_BASE_PORT REMOTE_BAS_PORT OUT_DIR NAME"
  exit 255
}

if [ "$#" != 5 ];then
  usage
fi

gamebox_ip=$1
local_base_port=$2
remote_base_port=$3
out_dir=$4
frp_name=$5

local_analysis_port=local_base_port
let local_analysis_port=local_base_port+0
local_redirect_port=local_base_port
let local_redirect_port=local_base_port+1
local_test_port=local_base_port
let local_test_port=local_base_port+2
local_io_decrypt_port=local_base_port
let local_io_decrypt_port=local_base_port+3
local_ssh_server_port=local_base_port
let local_ssh_server_port=local_base_port+4
local_local_sandbox_port=local_base_port
let local_local_sandbox_port=local_base_port+5
local_stage_normal_socket_server=local_base_port
let local_stage_normal_socket_server=local_base_port+6
local_stage_sandbox_socket_server=local_base_port
let local_stage_sandbox_socket_server=local_base_port+7


remote_analysis_port=remote_base_port
let remote_analysis_port=remote_base_port+0
remote_redirect_port=remote_base_port
let remote_redirect_port=remote_base_port+1
remote_test_port=remote_base_port
let remote_test_port=remote_base_port+2
remote_io_decrypt_port=remote_base_port
let remote_io_decrypt_port=remote_base_port+3
remote_ssh_server_port=remote_base_port
let remote_ssh_server_port=remote_base_port+4
remote_local_sandbox_port=remote_base_port
let remote_local_sandbox_port=remote_base_port+5
remote_stage_normal_socket_server=remote_base_port
let remote_stage_normal_socket_server=remote_base_port+6
remote_stage_sandbox_socket_server=remote_base_port
let remote_stage_sandbox_socket_server=remote_base_port+7
remote_frp_manager_port=remote_base_port
let remote_frp_manager_port=remote_base_port+8
remote_frp_status_port=remote_base_port
let remote_frp_status_port=remote_base_port+9


echo "Record Analysis Port:                    $local_analysis_port, remote:  $remote_analysis_port"
echo "Sandbox Redirect Port:                   $local_redirect_port, remote:  $remote_redirect_port"
echo "Local Test Port:                         $local_test_port, remote:  $remote_test_port"
echo "IO Decrypt Port:                         $local_io_decrypt_port, remote:  $remote_io_decrypt_port"
echo "SSH Server Port:                         $local_ssh_server_port, remote:  $remote_ssh_server_port"
echo "Local Sandbox Port:                      $local_local_sandbox_port, remote:  $remote_local_sandbox_port"
echo "Stage Normal Socket Server Port:         $local_stage_normal_socket_server, remote:  $remote_stage_normal_socket_server"
echo "Stage Sandbox Socket Server Port:        $local_stage_sandbox_socket_server, remote:  $remote_stage_sandbox_socket_server"
echo "Remote Frp Connect Port:                 $remote_frp_manager_port"
echo "Remote Frp Status  Port:                 $remote_frp_status_port"

generate_server_config(){
  echo "generate frp server config"
  echo "[common]" > "${out_dir}/frp_config/frps.ini"
  echo "bind_addr = 0.0.0.0"      >> "${out_dir}/frp_config/frps.ini"
  echo "bind_port = ${remote_frp_manager_port}"        >> "${out_dir}/frp_config/frps.ini"
  echo "dashboard_addr = 0.0.0.0" >> "${out_dir}/frp_config/frps.ini"
  echo "dashboard_port = ${remote_frp_status_port}"   >> "${out_dir}/frp_config/frps.ini"
  echo "dashboard_user = icsl"    >> "${out_dir}/frp_config/frps.ini"
  echo "dashboard_pwd = ICSL@123" >> "${out_dir}/frp_config/frps.ini"
  #echo "log_file = ./frps.log"    >> "${out_dir}/frp_config/frps.ini"
  #echo "log_level = info"         >> "${out_dir}/frp_config/frps.ini"
  echo "log_level = debug"         >> "${out_dir}/frp_config/frps.ini"
  echo "authentication_method = token"      >> "${out_dir}/frp_config/frps.ini"
  echo "token = 8777655678787"    >> "${out_dir}/frp_config/frps.ini"
  echo "authenticate_heartbeats = false"    >> "${out_dir}/frp_config/frps.ini"
  echo "tcp_mux = true"          >> "${out_dir}/frp_config/frps.ini"
}

generate_client_config(){
  echo "generate frp client config"
  echo "[common]" > "${out_dir}/frp_config/frpc.ini"
  echo "server_addr = ${gamebox_ip}" >> "${out_dir}/frp_config/frpc.ini"
  echo "server_port = ${remote_frp_manager_port}" >> "${out_dir}/frp_config/frpc.ini"
  echo "token = 8777655678787" >> "${out_dir}/frp_config/frpc.ini"
  echo "tcp_mux = true" >> "${out_dir}/frp_config/frpc.ini"
  echo "protocol = tcp" >> "${out_dir}/frp_config/frpc.ini"
  #echo "log_file = ./frpc.log" >> "${out_dir}/frp_config/frpc.ini"
  #echo "log_level = info" >> "${out_dir}/frp_config/frpc.ini"
  echo "log_level = debug" >> "${out_dir}/frp_config/frpc.ini"
  echo " " >> "${out_dir}/frp_config/frpc.ini"


  echo "[${frp_name}_analysis]" >> "${out_dir}/frp_config/frpc.ini"
  echo "type = tcp" >> "${out_dir}/frp_config/frpc.ini"
  echo "local_ip = 127.0.0.1" >> "${out_dir}/frp_config/frpc.ini"
  echo "local_port = ${local_analysis_port}" >> "${out_dir}/frp_config/frpc.ini"
  echo "remote_port = ${remote_analysis_port}" >> "${out_dir}/frp_config/frpc.ini"
  echo " " >> "${out_dir}/frp_config/frpc.ini"

  echo "[${frp_name}_redirect]" >> "${out_dir}/frp_config/frpc.ini"
  echo "type = tcp" >> "${out_dir}/frp_config/frpc.ini"
  echo "local_ip = 127.0.0.1" >> "${out_dir}/frp_config/frpc.ini"
  echo "local_port = ${local_redirect_port}" >> "${out_dir}/frp_config/frpc.ini"
  echo "remote_port = ${remote_redirect_port}" >> "${out_dir}/frp_config/frpc.ini"
  echo " " >> "${out_dir}/frp_config/frpc.ini"


  #echo "[${frp_name}_test]" >> "${out_dir}/frp_config/frpc.ini"
  #echo "type = tcp" >> "${out_dir}/frp_config/frpc.ini"
  #echo "local_ip = 127.0.0.1" >> "${out_dir}/frp_config/frpc.ini"
  #echo "local_port = ${local_test_port}" >> "${out_dir}/frp_config/frpc.ini"
  #echo "remote_port = ${remote_test_port}" >> "${out_dir}/frp_config/frpc.ini"
  #echo " " >> "${out_dir}/frp_config/frpc.ini"


  echo "[${frp_name}_io_decrypt]" >> "${out_dir}/frp_config/frpc.ini"
  echo "type = tcp" >> "${out_dir}/frp_config/frpc.ini"
  echo "local_ip = 127.0.0.1" >> "${out_dir}/frp_config/frpc.ini"
  echo "local_port = ${local_io_decrypt_port}" >> "${out_dir}/frp_config/frpc.ini"
  echo "remote_port = ${remote_io_decrypt_port}" >> "${out_dir}/frp_config/frpc.ini"
  echo " " >> "${out_dir}/frp_config/frpc.ini"


  echo "[${frp_name}_local]" >> "${out_dir}/frp_config/frpc.ini"
  echo "type = tcp" >> "${out_dir}/frp_config/frpc.ini"
  echo "local_ip = 127.0.0.1" >> "${out_dir}/frp_config/frpc.ini"
  echo "local_port = ${local_local_sandbox_port}" >> "${out_dir}/frp_config/frpc.ini"
  echo "remote_port = ${remote_local_sandbox_port}" >> "${out_dir}/frp_config/frpc.ini"
  echo " " >> "${out_dir}/frp_config/frpc.ini"


  echo "[${frp_name}_stage_normal]" >> "${out_dir}/frp_config/frpc.ini"
  echo "type = tcp" >> "${out_dir}/frp_config/frpc.ini"
  echo "local_ip = 127.0.0.1" >> "${out_dir}/frp_config/frpc.ini"
  echo "local_port = ${local_stage_normal_socket_server}" >> "${out_dir}/frp_config/frpc.ini"
  echo "remote_port = ${remote_stage_normal_socket_server}" >> "${out_dir}/frp_config/frpc.ini"
  echo " " >> "${out_dir}/frp_config/frpc.ini"


  echo "[${frp_name}_stage_sandbox]" >> "${out_dir}/frp_config/frpc.ini"
  echo "type = tcp" >> "${out_dir}/frp_config/frpc.ini"
  echo "local_ip = 127.0.0.1" >> "${out_dir}/frp_config/frpc.ini"
  echo "local_port = ${local_stage_sandbox_socket_server}" >> "${out_dir}/frp_config/frpc.ini"
  echo "remote_port = ${remote_stage_sandbox_socket_server}" >> "${out_dir}/frp_config/frpc.ini"
  echo " " >> "${out_dir}/frp_config/frpc.ini"

}

generate_server_config
generate_client_config

echo "generate done"
exit 0