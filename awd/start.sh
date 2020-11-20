#!/bin/bash

usage() {
  echo "$0 challenge_dir name base_port "
  echo "$0 challenge_dir name base_port frp gamebox_ip"
  exit 255
}

current_dir=$(pwd)
challenge_dir=$1
name=$2
base_port=$3


if [ "$#" != "3" ];then
  if [ "$#" != "5" ];then
    usage
  fi
fi

echo "current_dir: $current_dir"
if [ "$#" == "3" ];then
  echo "Not Frp Mode"
fi
if [ "$#" == "5" ];then
  echo "Frp Mode, start Generate FRP Config"
  ${current_dir}/../tools/frp_config_generator.sh $5 $base_port $base_port ${current_dir}/../out $name
  if [ $? != 0 ];then
    echo "frp generate failed"
    exit 255
  fi
fi


if [ -f "${challenge_dir}" ]; then
  echo "challenge_dir is not exist: ${challenge_dir}"
  usage
fi

check_port(){
  port=$1
  echo "start check port: $port"
  if [ -z "$(netstat -ltnp 2>/dev/null |grep $port|grep -v grep)" ];then
    return 1
  fi
    return 0
}



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


rm -rf ${challenge_dir}/out
rm ${currnet_dir}/../out/input_elf 2>/dev/null
rm ${currnet_dir}/../out/libc.so   2>/dev/null

challenge_dir_out=${challenge_dir}/generate/
rm -rf ${challenge_dir_out}
normal_config=${challenge_dir}/normal_config.json
sandbox_config=${challenge_dir}/sandbox_config.json
echo 's/\s*"project_root.*$/  "project_root":"'${current_dir//\//\\\/}'\/..\/",/g'
sed 's/\s*"project_root.*$/  "project_root":"'${current_dir//\//\\\/}'\/..\/",/g' -i ${normal_config}
sed 's/\s*"project_root.*$/  "project_root":"'${current_dir//\//\\\/}'\/..\/",/g' -i ${sandbox_config}

if [ "$#" == "3" ];then
  ip_addr=$(ifconfig ens33|grep inet|grep -v inet6 |awk -F' ' '{print $2}')
  echo "current_ip: ${ip_addr}"
fi
if [ "$#" == "5" ];then
  ip_addr="127.0.0.1"
  echo "current_ip: ${ip_addr}"
fi

sed -i 's/\s*"loader_stage_other_socket_server_ip.*$/  "loader_stage_other_socket_server_ip":"'${ip_addr}'",/g' -i ${sandbox_config}
sed -i 's/\s*"loader_stage_other_socket_server_ip.*$/  "loader_stage_other_socket_server_ip":"'${ip_addr}'",/g' -i ${normal_config}
sed -i 's/\s*"sandbox_server_ip.*$/  "sandbox_server_ip":"'${ip_addr}'",/g' -i ${sandbox_config}
sed -i 's/\s*"analysis_server_ip.*$/  "analysis_server_ip":"'${ip_addr}'",/g' -i ${normal_config}


sed -i "s/\"loader_stage_other_socket_server_port\":.*/\"loader_stage_other_socket_server_port\": \"${stage_sandbox_socket_server}\",/g" ${sandbox_config}
if [ ! -z "$(cat ${sandbox_config}|grep ${stage_sandbox_socket_server})" ];then
    echo "success set ${sandbox_config} loader_stage_other_socket_server_port to:            ${stage_sandbox_socket_server}"
else
    echo "failed  set ${sandbox_config} loader_stage_other_socket_server_port to:            ${stage_sandbox_socket_server}"
    exit 255
fi


sed -i "s/\"loader_stage_other_socket_server_port\":.*/\"loader_stage_other_socket_server_port\": \"$stage_normal_socket_server\",/g" ${normal_config}
if [ ! -z "$(cat ${normal_config}|grep ${stage_normal_socket_server})" ];then
    echo "success set ${normal_config} loader_stage_other_socket_server_port to:            ${stage_normal_socket_server}"
else
    echo "failed  set ${normal_config} loader_stage_other_socket_server_port to:            ${stage_normal_socket_server}"
    exit 255
fi



sed -i "s/\"sandbox_server_port\":.*/\"sandbox_server_port\": \"${io_decrypt_port}\",/g" ${sandbox_config}
if [ ! -z "$(cat ${sandbox_config}|grep ${io_decrypt_port})" ];then
    echo "success set ${sandbox_config} sandbox_server_port to:            ${io_decrypt_port}"
else
    echo "failed  set ${sandbox_config} sandbox_server_port to:            ${io_decrypt_port}"
    exit 255
fi

sed -i "s/\"analysis_server_port\":.*/\"analysis_server_port\": \"${analysis_port}\",/g" ${normal_config}
if [ ! -z "$(cat ${normal_config}|grep ${analysis_port})" ];then
    echo "success set ${normal_config} analysis_server_port to:            ${analysis_port}"
else
    echo "failed  set ${normal_config} analysis_server_port to:            ${analysis_port}"
    exit 255
fi




cp -f ${normal_config} ${current_dir}/../out/normal_config.json
cp -f ${sandbox_config} ${current_dir}/../out/sandbox_config.json

g_test_file=
get_test_file() {
  echo "trying to find pwn file"
  g_test_file=
  files=$(ls ./${1}/)
  for file in ${files}; do
    if [[ ${file} == *libc* ]]; then
      continue
    fi
    test_execute=$(file ${1}/${file} 2>/dev/null| grep 80386)
    if [ ! -z "${test_execute}" ]; then
      g_test_file=${1}/${file}
      return 0
    fi
    test_execute=$(file ${1}/${file} 2>/dev/null| grep x86-64)
    if [ ! -z "${test_execute}" ]; then
      g_test_file=${1}/${file}
      return 0
    fi
  done
}

g_test_libc_file=
get_test_libc_file() {
  echo "trying to find libc file"
  g_test_file=
  files=$(ls ./${1}/)
  for file in ${files}; do
    if [[ ${file} != *libc* ]]; then
      continue
    fi
    test_execute=$(file ${1}/${file} | grep 80386)
    if [ ! -z "${test_execute}" ]; then
      g_test_libc_file=${1}/${file}
      return 0
    fi
    test_execute=$(file ${1}/${file} | grep x86-64)
    if [ ! -z "${test_execute}" ]; then
      g_test_libc_file=${1}/${file}
      return 0
    fi
  done
}

g_libc_version=
get_test_libc_version() {
  g_libc_version=
  libc_file=$1
  echo "strings ${libc_file} 2>/dev/null|grep -v Fatal | grep 'glibc '|awk -F ' ' '{print $2}'"
  g_libc_version=$(strings ${libc_file} 2>/dev/null | grep -v Fatal | grep 'glibc ' | awk -F ' ' '{print $2}')
  echo "detect glibc_version: $g_libc_version"
}

get_test_file ${challenge_dir}
if [ -z "${g_test_file}" ]; then
  echo "Dir ${challenge_dir} not find test file,failed"
  exit 255
fi
test_file=${g_test_file}
get_test_libc_file ${challenge_dir}
test_libc_file=${g_test_libc_file}
init_script_file=${challenge_dir}/init_env.sh
echo "get test_file:      ${test_file}"
echo "get test_libc_file: ${test_libc_file}"
if [ ! -f "${test_libc_file}" ]; then
  echo "Dir ${challenge_dir} not find libc file,failed"
  exit 255
fi

cp ${test_file} ${current_dir}/../out/input_elf
cp ${test_libc_file} ${current_dir}/../out/libc.so

if [ ! -f "${init_script_file}" ]; then
  echo "Dir ${challenge_dir} not find init_env.sh file"
  init_script_file="_______UN_EXIST_FILE______"
fi

docker_image_version=
get_test_libc_version ${test_libc_file}
if [ "${g_libc_version}" == "2.23" ]; then
  docker_image_version="1604"
elif [ "${g_libc_version}" == "2.24" ]; then
  docker_image_version="1610"
elif [ "${g_libc_version}" == "2.26" ]; then
  docker_image_version="1710"
elif [ "${g_libc_version}" == "2.27" ]; then
  docker_image_version="1804"
elif [ "${g_libc_version}" == "2.28" ]; then
  docker_image_version="1810"
elif [ "${g_libc_version}" == "2.29" ]; then
  docker_image_version="1904"
elif [ "${g_libc_version}" == "2.30" ]; then
  docker_image_version="2010"
elif [ "${g_libc_version}" == "2.31" ]; then
  docker_image_version="2004"
elif [ "${g_libc_version}" == "2.32" ]; then
  docker_image_version="2010"
else
  echo "unknown glibc verison: $g_libc_version"
  exit 255
fi

sudo docker stop ${name}1 2>/dev/null
sudo docker rm ${name}1   2>/dev/null

echo "base_port: ${base_port}"
for i in {0..7}
do
  need_check_port=$(expr $base_port + $i )
  check_port ${need_check_port}
  if [ "$?" != "1" ];then
    echo "check_port failed: ${need_check_port}"
    exit 255
  fi
done

cd ${current_dir}/../docker/image_build_script/bin/
./start.sh ${current_dir}/../ ${docker_image_version} $name ${base_port}

if [ $? -ne 0 ]; then
  echo "start.sh exec failed !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  exit 255
fi

cd ${current_dir}/

if [ -f ${init_script_file} ]; then
  sudo docker cp ${init_script_file} ${name}1:/root/init_env.sh
  sudo docker exec -it ${name}1 bash -c "cd /root/;chmod +x ./init_env.sh;./init_env.sh"
else
  echo "init_script_file is not exist, no need to do init"
fi

cp -r ${current_dir}/../out ${challenge_dir}/out




if [ "$#" == "3" ];then
  sudo docker cp ${current_dir}/resource/start_awd.sh ${name}1:/root/start_awd.sh
  sudo docker exec -it ${name}1 bash -c "sed -i \"s/__BASE_PORT__/${base_port}/g\" /root/start_awd.sh "
  sudo docker exec -it ${name}1 bash -c "cd /root/;chmod +x ./start_awd.sh;tmux new-session -s my_session '/root/start_awd.sh' "
fi
if [ "$#" == "5" ];then
  sudo docker cp ${current_dir}/../resource/frp/frp_0.34.2_linux_amd64/frp_0.34.2_linux_amd64/frpc test1:/root/
  sudo docker cp ${current_dir}/../out/frp_config/frpc.ini test1:/root/
  sudo docker cp ${current_dir}/resource/start_awd_frp.sh ${name}1:/root/start_awd_frp.sh
  sudo docker exec -it ${name}1 bash -c "sed -i \"s/__BASE_PORT__/${base_port}/g\" /root/start_awd_frp.sh "
  sudo docker exec -it ${name}1 bash -c "cd /root/;chmod +x ./start_awd_frp.sh;tmux new-session -s my_session '/root/start_awd_frp.sh' "






fi







