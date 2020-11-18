#!/bin/bash


rm -rf ./test_out/ 2>/dev/null
target_out_dir=../out/
test_dir=test_tracffic
test_dir_files=$(ls ./${test_dir}/)
current_dir=$(pwd)
echo 's/\s*"project_root.*$/  "project_root":"'${current_dir//\//\\\/}'\/..\/",/g'
sed 's/\s*"project_root.*$/  "project_root":"'${current_dir//\//\\\/}'\/..\/",/g' -i ../out/normal_config.json
sed 's/\s*"project_root.*$/  "project_root":"'${current_dir//\//\\\/}'\/..\/",/g' -i ../out/sandbox_config.json

g_test_file=
get_test_file(){
  g_test_file=
    files=$(ls ./${1}/)
    for file in ${files};do
      if [[ ${file} == *libc* ]];then
        continue
      fi
      test_execute=$(file ${1}/${file} | grep 80386)
      if [ ! -z "${test_execute}" ];then
        #g_test_file=${1}/${file}
        return 0
      fi
      test_execute=$(file ${1}/${file} | grep x86-64)
      if [ ! -z "${test_execute}" ];then
        g_test_file=${1}/${file}
        return 0
      fi
    done
}

g_test_libc_file=
get_test_libc_file(){
  g_test_file=
    files=$(ls ./${1}/)
    for file in ${files};do
      if [[ ${file} != *libc* ]];then
        continue
      fi
      test_execute=$(file ${1}/${file} | grep 80386)
      if [ ! -z "${test_execute}" ];then
        g_test_libc_file=${1}/${file}
        return 0
      fi
      test_execute=$(file ${1}/${file} | grep x86-64)
      if [ ! -z "${test_execute}" ];then
        g_test_libc_file=${1}/${file}
        return 0
      fi
    done
}

g_libc_version=
get_test_libc_version(){
  g_libc_version=
  libc_file=$1
  echo "strings ${libc_file} 2>/dev/null|grep -v Fatal | grep 'glibc '|awk -F ' ' '{print $2}'"
  g_libc_version=`strings ${libc_file} 2>/dev/null|grep -v Fatal | grep 'glibc '|awk -F ' ' '{print $2}'`
  echo "detect glibc_version: $g_libc_version"
}

for binary_dir in ${test_dir_files};do
  cd ${current_dir}
  if [ "${binary_dir}" != "babyheap" ];then
    continue
  fi
  test_sub_dir=${test_dir}/${binary_dir}
  echo "begin test ${test_sub_dir} ####################################################"

  if [ -f ${test_sub_dir}/ignore ];then
    echo "ignore sub test dir: ${test_sub_dir}"
    continue
  fi

  get_test_file ${test_sub_dir}
  if [ -z "${g_test_file}" ];then
    echo "Dir ${test_sub_dir} not find test file,ignore"
    continue
  fi
  test_file=${g_test_file}
  get_test_libc_file ${test_sub_dir}
  test_libc_file=${g_test_libc_file}
  test_poc_file=${test_sub_dir}/poc.py
  init_script_file=${test_sub_dir}/init_env.sh
  echo "get test_file:      ${test_file}"
  echo "get test_libc_file: ${test_libc_file}"
  echo "get test_poc_file:  ${test_poc_file}"
  if [ ! -f "${test_libc_file}" ];then
    echo "Dir ${test_sub_dir} not find libc file,ignore"
    continue
  fi
  if [ ! -f "${test_poc_file}" ];then
    echo "Dir ${test_sub_dir} not find poc.py file,ignore"
    continue
  fi
  if [ ! -f "${init_script_file}" ];then
    echo "Dir ${test_sub_dir} not find init_env.sh file"
    init_script_file="_______UN_EXIST_FILE______"
  fi

  file=${binary_dir}
  mkdir -p ./test_out/${file}
  cp -f ${test_file} ./test_out/${file}/
  cp -f ${test_file}  ${target_out_dir}/input_elf
  cp -f ${test_libc_file} ./test_out/${file}/
  cp -f ${test_libc_file}  ${target_out_dir}/libc.so
  cp -f ${test_poc_file} ./test_out/${file}/

  #loader_stage_one_positions=(eh_frame)
  loader_stage_one_positions=(new_pt_load eh_frame)
  #loader_stage_other_positions=(memory file share_memory socket)
  loader_stage_other_positions=(socket)
  for loader_stage_one_position in "${loader_stage_one_positions[@]}";do
    for loader_stage_other_position in "${loader_stage_other_positions[@]}";do
      echo "begin test loader_stage_one_position:${loader_stage_one_position}, loader_stage_other_position: ${loader_stage_other_position} ,subdir: ${test_sub_dir}"
      cd ${current_dir}

      echo 's/\s*"loader_stage_one_position.*$/  "loader_stage_one_position":"'${loader_stage_one_position}'",/g'
      sed  's/\s*"loader_stage_one_position.*$/  "loader_stage_one_position":"'${loader_stage_one_position}'",/g' -i ../out/normal_config.json
      sed  's/\s*"loader_stage_one_position.*$/  "loader_stage_one_position":"'${loader_stage_one_position}'",/g' -i ../out/sandbox_config.json
      echo 's/\s*"loader_stage_other_position.*$/  "loader_stage_other_position":"'${loader_stage_other_position}'",/g'
      sed  's/\s*"loader_stage_other_position.*$/  "loader_stage_other_position":"'${loader_stage_other_position}'",/g' -i ../out/normal_config.json
      sed  's/\s*"loader_stage_other_position.*$/  "loader_stage_other_position":"'${loader_stage_other_position}'",/g' -i ../out/sandbox_config.json


      if [ ${loader_stage_other_position} == 'file' ];then
        loader_stage_other_normal_file_path='/tmp/1'
        loader_stage_other_sandbox_file_path='/tmp/2'
        echo 's/\s*"loader_stage_other_file_path.*$/  "loader_stage_other_file_path":"'${loader_stage_other_normal_file_path}'",/g'
        sed  's/\s*"loader_stage_other_file_path.*$/  "loader_stage_other_file_path":"'${loader_stage_other_normal_file_path//\//\\\/}'",/g' -i ../out/normal_config.json
        sed  's/\s*"loader_stage_other_file_path.*$/  "loader_stage_other_file_path":"'${loader_stage_other_sandbox_file_path//\//\\\/}'",/g' -i ../out/sandbox_config.json
      fi
      if [ ${loader_stage_other_position} == 'share_memory' ];then
        loader_stage_other_normal_share_memory_id='123'
        loader_stage_other_sandbox_share_memory_id='124'
        echo 's/\s*"loader_stage_other_share_memory_id.*$/  "loader_stage_other_share_memory_id":"'${loader_stage_other_normal_share_memory_id}'",/g'
        sed  's/\s*"loader_stage_other_share_memory_id.*$/  "loader_stage_other_share_memory_id":"'${loader_stage_other_normal_share_memory_id}'",/g' -i ../out/norml_config.json
        sed  's/\s*"loader_stage_other_share_memory_id.*$/  "loader_stage_other_share_memory_id":"'${loader_stage_other_sandbox_share_memory_id}'",/g' -i ../out/sandbox_config.json
      fi
      if [ ${loader_stage_other_position} == 'socket' ];then
        loader_stage_other_socket_server_ip='127.0.0.1'
        loader_stage_other_socket_normal_server_port='60006'
        loader_stage_other_socket_sandbox_server_port='60007'
        echo 's/\s*"loader_stage_other_socket_server_ip.*$/  "loader_stage_other_socket_server_ip":"'${loader_stage_other_socket_server_ip}'",/g'
        sed  's/\s*"loader_stage_other_socket_server_ip.*$/  "loader_stage_other_socket_server_ip":"'${loader_stage_other_socket_server_ip}'",/g' -i ../out/normal_config.json
        sed  's/\s*"loader_stage_other_socket_server_ip.*$/  "loader_stage_other_socket_server_ip":"'${loader_stage_other_socket_server_ip}'",/g' -i ../out/sandbox_config.json
        echo 's/\s*"loader_stage_other_socket_server_port.*$/  "loader_stage_other_socket_server_port":"'${loader_stage_other_socket_normal_server_port}'",/g'
        sed  's/\s*"loader_stage_other_socket_server_port.*$/  "loader_stage_other_socket_server_port":"'${loader_stage_other_socket_normal_server_port}'",/g' -i ../out/normal_config.json
        sed  's/\s*"loader_stage_other_socket_server_port.*$/  "loader_stage_other_socket_server_port":"'${loader_stage_other_socket_sandbox_server_port}'",/g' -i ../out/sandbox_config.json
      fi

      docker_image_version=
      get_test_libc_version ${target_out_dir}/libc.so
      if [ "${g_libc_version}" == "2.23" ];then
        docker_image_version="1604"
      elif [ "${g_libc_version}" == "2.24" ];then
        docker_image_version="1610"
      elif [ "${g_libc_version}" == "2.26" ];then
        docker_image_version="1710"
      elif [ "${g_libc_version}" == "2.27" ];then
        docker_image_version="1804"
      elif [ "${g_libc_version}" == "2.28" ];then
        docker_image_version="1810"
      elif [ "${g_libc_version}" == "2.29" ];then
        docker_image_version="1904"
      elif [ "${g_libc_version}" == "2.30" ];then
        docker_image_version="2010"
      elif [ "${g_libc_version}" == "2.31" ];then
        docker_image_version="2004"
      elif [ "${g_libc_version}" == "2.32" ];then
        docker_image_version="2010"
      else
        echo "unknown glibc verison: $g_libc_version"
        exit 255
      fi

      cd ${current_dir}/../docker/restrict_image_build_script/bin/
      ./start.sh ${current_dir}/../ ${docker_image_version} test 60000

      if [ $? -ne 0 ]; then
        echo "start.sh exec failed !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        exit 255
      fi

      cd ${current_dir}/

      if [ ${loader_stage_other_position} == 'file' ];then
        loader_stage_other_normal_file_path='/tmp/1'
        loader_stage_other_sandbox_file_path='/tmp/2'
        sudo docker exec -it test1 bash -c "cp /root/normal.datafile /home/ctf/tmp/1;chmod 755 /home/ctf/tmp/1;"
        sudo docker exec -it test1 bash -c "cp /root/sandbox.datafile /tmp/2;chmod 755 /tmp/2;"
      fi
      if [ ${loader_stage_other_position} == 'share_memory' ];then
        loader_stage_other_normal_share_memory_id='123'
        loader_stage_other_sandbox_share_memory_id='124'
        sudo docker cp ../out/stage_server/stage_share_memory_server test1:/root/
        sudo docker exec -d test1 bash -c "/root/stage_share_memory_server 123 /root/normal.datafile"
        sudo docker exec -d test1 bash -c "/root/stage_share_memory_server 124 /root/sandbox.datafile"
      fi
      if [ ${loader_stage_other_position} == 'socket' ];then
        loader_stage_other_socket_server_ip='127.0.0.1'
        loader_stage_other_socket_normal_server_port='60006'
        loader_stage_other_socket_sandbox_server_port='60007'
      fi

      sudo docker cp ${test_poc_file} test1:/root/
      sudo docker cp ${current_dir}/resource/test_poc_restrict.sh test1:/root/test_poc.sh
      if [ -f ${init_script_file} ];then
        sudo docker cp ${init_script_file} test1:/root/init_env.sh
        sudo docker exec -it test1 bash -c "cd /root/;chmod +x ./init_env.sh;./init_env.sh"
      fi
      sudo docker exec -it test1 bash -c "cd /root/;chmod +x ./test_poc.sh;tmux new-session -s my_session './test_poc.sh' "
      if [ ! -z "$(sudo docker exec -it test1 bash -c 'ls -ll /root/verify_success.flag 2>/dev/null')" ];then
        touch ./test_out/${file}/${loader_stage_one_position}_${loader_stage_other_position}_success.flag
        echo "${loader_stage_one_position}_${loader_stage_other_position}_success###############################################"
      else
        if [ ! -z "$(sudo docker exec -it test1 bash -c 'ls -ll /root/verify_failed.flag 2>/dev/null')" ];then
          touch ./test_out/${file}/${loader_stage_one_position}_${loader_stage_other_position}_failed.flag
          echo "${loader_stage_one_position}_${loader_stage_other_position}_failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        else
          echo "something wrong, both file not exist"
        fi
      fi
      sudo docker stop test1
      sudo docker rm test1
    done
  done
  #exit 255
done


for binary_dir in ${test_dir_files};do
  cd ${current_dir}
  test_sub_dir=${test_dir}/${binary_dir}


  if [ -f ${test_sub_dir}/ignore ];then
    continue
  fi

  get_test_file ${test_sub_dir}
  if [ -z "${g_test_file}" ];then
    continue
  fi
  test_file=${g_test_file}
  get_test_libc_file ${test_sub_dir}
  test_libc_file=${g_test_libc_file}
  test_poc_file=${test_sub_dir}/poc.py
  if [ ! -f "${test_libc_file}" ];then
    continue
  fi
  if [ ! -f "${test_poc_file}" ];then
    continue
  fi
  echo "begin test ${test_sub_dir} ####################################################"
  ls -ll ./test_out/${binary_dir}/*.flag
done
