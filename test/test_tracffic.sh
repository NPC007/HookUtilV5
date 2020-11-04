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
      test_execute=$(file ${1}/${file} | grep 80386)
      if [ ! -z "${test_execute}" ];then
        g_test_file=${1}/${file}
        return 0
      fi
      test_execute=$(file ${1}/${file} | grep x86-64)
      if [ ! -z "${test_execute}" ];then
        g_test_file=${1}/${file}
        return 0
      fi
    done
}


for binary_dir in ${test_dir_files};do
  cd ${current_dir}
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
  test_libc_file=${test_sub_dir}/libc.so
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
    init_script_file=
  fi

  file=${binary_dir}
  mkdir -p ./test_out/${file}
  cp -f ${test_file} ./test_out/${file}/
  cp -f ${test_file}  ${target_out_dir}/input_elf
  cp -f ${test_libc_file} ./test_out/${file}/
  cp -f ${test_libc_file}  ${target_out_dir}/libc.so
  cp -f ${test_poc_file} /test_out/${file}/

  loader_stage_one_positions=(new_pt_load)
  #ge_other_positions=(memory file share_memory socket)
  loader_stage_other_positions=(memory)
  for loader_stage_one_position in "${loader_stage_one_positions[@]}";do
    for loader_stage_other_position in "${loader_stage_other_positions[@]}";do
      echo "begin test loader_stage_one_position:${loader_stage_one_position}, loader_stage_other_position: ${loader_stage_other_position} "
      cd ${current_dir}

      echo 's/\s*"loader_stage_one_position.*$/  "loader_stage_one_position":"'${loader_stage_one_position}'",/g'
      sed  's/\s*"loader_stage_one_position.*$/  "loader_stage_one_position":"'${loader_stage_one_position}'",/g' -i ../out/normal_config.json
      sed  's/\s*"loader_stage_one_position.*$/  "loader_stage_one_position":"'${loader_stage_one_position}'",/g' -i ../out/sandbox_config.json
      echo 's/\s*"loader_stage_other_position.*$/  "loader_stage_other_position":"'${loader_stage_other_position}'",/g'
      sed  's/\s*"loader_stage_other_position.*$/  "loader_stage_other_position":"'${loader_stage_other_position}'",/g' -i ../out/normal_config.json
      sed  's/\s*"loader_stage_other_position.*$/  "loader_stage_other_position":"'${loader_stage_other_position}'",/g' -i ../out/sandbox_config.json


      if [ ${loader_stage_other_position} == 'file' ];then
        loader_stage_other_file_path='/tmp/1'
        echo 's/\s*"loader_stage_other_file_path.*$/  "loader_stage_other_file_path":"'${loader_stage_other_file_path}'",/g'
        sed  's/\s*"loader_stage_other_file_path.*$/  "loader_stage_other_file_path":"'${loader_stage_other_file_path}'",/g' -i ../out/normal_config.json
        sed  's/\s*"loader_stage_other_file_path.*$/  "loader_stage_other_file_path":"'${loader_stage_other_file_path}'",/g' -i ../out/sandbox_config.json
      fi
      if [ ${loader_stage_other_position} == 'share_memory' ];then
        loader_stage_other_share_memory_id='123'
        echo 's/\s*"loader_stage_other_share_memory_id.*$/  "loader_stage_other_share_memory_id":"'${loader_stage_other_share_memory_id}'",/g'
        sed  's/\s*"loader_stage_other_share_memory_id.*$/  "loader_stage_other_share_memory_id":"'${loader_stage_other_share_memory_id}'",/g' -i ../out/norml_config.json
        sed  's/\s*"loader_stage_other_share_memory_id.*$/  "loader_stage_other_share_memory_id":"'${loader_stage_other_share_memory_id}'",/g' -i ../out/sandbox_config.json
      fi
      if [ ${loader_stage_other_position} == 'socket' ];then
        loader_stage_other_socket_server_ip='127.0.0.1'
        loader_stage_other_socket_server_port='11111'
        echo 's/\s*"loader_stage_other_socket_server_ip.*$/  "loader_stage_other_socket_server_ip":"'${loader_stage_other_socket_server_ip}'",/g'
        sed  's/\s*"loader_stage_other_socket_server_ip.*$/  "loader_stage_other_socket_server_ip":"'${loader_stage_other_socket_server_ip}'",/g' -i ../out/normal_config.json
        sed  's/\s*"loader_stage_other_socket_server_ip.*$/  "loader_stage_other_socket_server_ip":"'${loader_stage_other_socket_server_ip}'",/g' -i ../out/sandbox_config.json
        echo 's/\s*"loader_stage_other_socket_server_port.*$/  "loader_stage_other_socket_server_port":"'${loader_stage_other_socket_server_port}'",/g'
        sed  's/\s*"loader_stage_other_socket_server_port.*$/  "loader_stage_other_socket_server_port":"'${loader_stage_other_socket_server_port}'",/g' -i ../out/normal_config.json
        sed  's/\s*"loader_stage_other_socket_server_port.*$/  "loader_stage_other_socket_server_port":"'${loader_stage_other_socket_server_port}'",/g' -i ../out/sandbox_config.json
      fi

      cd ${current_dir}/../docker/image_build_script/bin/
      ./start.sh ${current_dir}/../ 1604 test 10000

      cd ${current_dir}/
      sudo docker cp ${test_poc_file} test1:/root/
      sudo docker cp ${current_dir}/resource/test_poc.sh test1:/root/
      if [ -f ${init_script_file} ];then
        sudo docker cp ${init_script_file} test1:/root/init_env.sh
        sudo docker exec -it test1 bash -c "cd /root/;chmod +x ./init_env.sh;./init_env.sh"
      fi
      sudo docker exec -it test1 bash -c "cd /root/;chmod +x ./test_poc.sh;tmux new-session -s my_session './test_poc.sh' "
      sudo docker stop test1
      sudo docker rm test1

      exit 255

    done
  done
done


