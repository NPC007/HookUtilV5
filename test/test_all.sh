#!/bin/bash


rm -rf ./test_out/ 2>/dev/null
target_out_dir=../out/
test_dir=binary
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
        echo "get test_file ${g_test_file}"
        return 0
      fi
      test_execute=$(file ${1}/${file} | grep x86-64)
      if [ ! -z "${test_execute}" ];then
        g_test_file=${1}/${file}
        echo "get test_file ${g_test_file}"
        return 0
      fi
    done
}


wait_port(){
  port=$1
  echo "start wait port ${port}"
  while [ "x" == "x" ]
  do
    sleep 0.1
    if [ ! -z "$(netstat -ltnp 2>/dev/null |grep -v grep|grep ${port})" ];then
      sleep 0.1
      return
    fi
    #echo "netstat -ltnp 2>/dev/null |grep -v grep|grep ${port}"
  done
}


for binary_dir in ${test_dir_files};do
  cd ${current_dir}
  test_sub_dir=${test_dir}/${binary_dir}
  echo "begin test ${test_sub_dir}"

  get_test_file ${test_sub_dir}
  if [ -z "${g_test_file}" ];then
    echo "Dir ${test_sub_dir} not find test file,ignore"
    continue
  fi
  input_file=${test_sub_dir}/input.txt
  if [ ! -f ${input_file} ];then
    echo "Unable find input.ext in Dir: ${test_sub_dir},ignore this DIR"
    continue
  fi

  echo "Input File test ok: ${input_file}"

  test_file=${g_test_file}
  file=${binary_dir}
  mkdir -p ./test_out/${file}
  cp -f ${test_file} ./test_out/${file}/
  cp -f ${test_file}  ${target_out_dir}/input_elf

  TEST_TARGET_ARCH=$(file ${target_out_dir}/input_elf | grep 80386)
  if [ ! -z "${TEST_TARGET_ARCH}" ];then
    TARGET_ARCH=X86
    echo "set TARGET_ARCH: X86"
  fi
  TEST_TARGET_ARCH=$(file ${target_out_dir}/input_elf | grep x86-64)
  if [ ! -z "${TEST_TARGET_ARCH}" ];then
    TARGET_ARCH=X86_64
     echo "set TARGET_ARCH: X86_64"
  fi
  if [ -z "${TARGET_ARCH}" ];then
    echo 'TARGET_ARCH Unknown, failed, exit'
    file ${target_out_dir}/input_elf
    exit 255
  fi

  #loader_stage_one_positions=(eh_frame)
  loader_stage_one_positions=(new_pt_load eh_frame)
  loader_stage_other_positions=(memory file share_memory socket)
  #loader_stage_other_positions=(socket)
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
        echo 's/\s*"loader_stage_other_file_path.*$/  "loader_stage_other_file_path":"'${loader_stage_other_file_path//\//\\\/}'",/g'
        sed  's/\s*"loader_stage_other_file_path.*$/  "loader_stage_other_file_path":"'${loader_stage_other_file_path//\//\\\/}'",/g' -i ../out/normal_config.json
        sed  's/\s*"loader_stage_other_file_path.*$/  "loader_stage_other_file_path":"'${loader_stage_other_file_path//\//\\\/}'",/g' -i ../out/sandbox_config.json
      fi
      if [ ${loader_stage_other_position} == 'share_memory' ];then
        loader_stage_other_share_memory_id='123'
        echo 's/\s*"loader_stage_other_share_memory_id.*$/  "loader_stage_other_share_memory_id":"'${loader_stage_other_share_memory_id}'",/g'
        sed  's/\s*"loader_stage_other_share_memory_id.*$/  "loader_stage_other_share_memory_id":"'${loader_stage_other_share_memory_id}'",/g' -i ../out/normal_config.json
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


      cd ..
      ./build_debug.sh slient
      if [ $? -ne 0 ]; then
        echo "build_debug.sh failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        echo ${test_file}
        exit 255
      fi


      cd ${current_dir}
      mkdir -p ./test_out/${file}/out_debug_${loader_stage_one_position}_${loader_stage_other_position}/
      cp -r ../out/* ./test_out/${file}/out_debug_${loader_stage_one_position}_${loader_stage_other_position}/

      if [ ${loader_stage_other_position} == 'file' ];then
        cp -f ../out/normal/normal.datafile /tmp/1
      fi
      if [ ${loader_stage_other_position} == 'share_memory' ];then
        killall stage_share_memory_server
        ./test_out/${file}/out_debug_${loader_stage_one_position}_${loader_stage_other_position}/stage_server/stage_share_memory_server 123 ../out/normal/normal.datafile  2>&1 >> ./test_out/${file}/out_debug_${loader_stage_one_position}_${loader_stage_other_position}/normal_stage_share_memory_server.log &
        sleep 0.2
      fi
      if [ ${loader_stage_other_position} == 'socket' ];then
        killall stage_socket_server
        ./test_out/${file}/out_debug_${loader_stage_one_position}_${loader_stage_other_position}/stage_server/stage_socket_server 11111 ../out/normal/normal.datafile 2>&1 >> ./test_out/${file}/out_debug_${loader_stage_one_position}_${loader_stage_other_position}/normal_patch_socket_server.log &
        #echo "./test_out/${file}/out_debug_${loader_stage_one_position}_${loader_stage_other_position}/stage_server/stage_socket_server 11111 ../out/normal/normal.datafile 2>&1 >> ./test_out/${file}/out_debug_${loader_stage_one_position}_${loader_stage_other_position}/normal_patch_socket_server.log &"
        wait_port 11111
      fi
      cat ${input_file} | ./test_out/${file}/out_debug_${loader_stage_one_position}_${loader_stage_other_position}/normal/input_elf_normal    > ./test_out/${file}/input_elf_normal_debug_${loader_stage_one_position}_${loader_stage_other_position}.log

      #if [ ${loader_stage_other_position} == 'socket' ];then
      #   exit 255
      #fi

      if [ ${loader_stage_other_position} == 'file' ];then
        cp -f ../out/sandbox/sandbox.datafile /tmp/1
      fi
      if [ ${loader_stage_other_position} == 'share_memory' ];then
        killall stage_share_memory_server
        ./test_out/${file}/out_debug_${loader_stage_one_position}_${loader_stage_other_position}/stage_server/stage_share_memory_server 123 ../out/sandbox/sandbox.datafile  2>&1 >> ./test_out/${file}/out_debug_${loader_stage_one_position}_${loader_stage_other_position}/sandbox_stage_share_memory_server.log &
        sleep 0.2
      fi
      if [ ${loader_stage_other_position} == 'socket' ];then
        killall stage_socket_server
        ./test_out/${file}/out_debug_${loader_stage_one_position}_${loader_stage_other_position}/stage_server/stage_socket_server 11111 ../out/sandbox/sandbox.datafile 2>&1 >> ./test_out/${file}/out_debug_${loader_stage_one_position}_${loader_stage_other_position}/sandbox_patch_socket_server.log &
        wait_port 11111
      fi
      cat ${input_file} | ./test_out/${file}/out_debug_${loader_stage_one_position}_${loader_stage_other_position}/sandbox/input_elf_sandbox  > ./test_out/${file}/input_elf_sandbox_debug_${loader_stage_one_position}_${loader_stage_other_position}.log



      cd ..
      ./build_release.sh slient
      if [ $? -ne 0 ]; then
        echo "build_release.sh failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        echo ${test_file}
        exit 255
      fi
      cd ${current_dir}
      mkdir -p ./test_out/${file}/out_release_${loader_stage_one_position}_${loader_stage_other_position}/
      cp -r ../out/* ./test_out/${file}/out_release_${loader_stage_one_position}_${loader_stage_other_position}/
      if [ ${loader_stage_other_position} == 'file' ];then
        cp -f ../out/normal/normal.datafile /tmp/1
      fi
      if [ ${loader_stage_other_position} == 'share_memory' ];then
        killall stage_share_memory_server
        ./test_out/${file}/out_release_${loader_stage_one_position}_${loader_stage_other_position}/stage_server/stage_share_memory_server 123 ../out/normal/normal.datafile  2>&1 >> ./test_out/${file}/out_release_${loader_stage_one_position}_${loader_stage_other_position}/normal_stage_share_memory_server.log &
        sleep 0.2
      fi
      if [ ${loader_stage_other_position} == 'socket' ];then
        killall stage_socket_server
        ./test_out/${file}/out_release_${loader_stage_one_position}_${loader_stage_other_position}/stage_server/stage_socket_server 11111 ../out/normal/normal.datafile 2>&1 >> ./test_out/${file}/out_release_${loader_stage_one_position}_${loader_stage_other_position}/normal_patch_socket_server.log &
        wait_port 11111
      fi
      cat ${input_file} | ./test_out/${file}/out_release_${loader_stage_one_position}_${loader_stage_other_position}/normal/input_elf_normal    > ./test_out/${file}/input_elf_normal_release_${loader_stage_one_position}_${loader_stage_other_position}.log


      if [ ${loader_stage_other_position} == 'file' ];then
        cp -f ../out/sandbox/sandbox.datafile /tmp/1
      fi
      if [ ${loader_stage_other_position} == 'share_memory' ];then
        killall stage_share_memory_server
        ./test_out/${file}/out_release_${loader_stage_one_position}_${loader_stage_other_position}/stage_server/stage_share_memory_server 123 ../out/sandbox/sandbox.datafile  2>&1 >> ./test_out/${file}/out_release_${loader_stage_one_position}_${loader_stage_other_position}/sandbox_stage_share_memory_server.log &
        sleep 0.2
      fi
      if [ ${loader_stage_other_position} == 'socket' ];then
        killall stage_socket_server
        ./test_out/${file}/out_release_${loader_stage_one_position}_${loader_stage_other_position}/stage_server/stage_socket_server 11111 ../out/sandbox/sandbox.datafile 2>&1 >> ./test_out/${file}/out_release_${loader_stage_one_position}_${loader_stage_other_position}/sandbox_patch_socket_server.log &
        wait_port 11111
      fi
      cat ${input_file} | ./test_out/${file}/out_release_${loader_stage_one_position}_${loader_stage_other_position}/sandbox/input_elf_sandbox  > ./test_out/${file}/input_elf_sandbox_release_${loader_stage_one_position}_${loader_stage_other_position}.log

      killall stage_share_memory_server
      killall stage_socket_server

    done
  done
  #exit 0
done


loader_stage_one_positions=(new_pt_load eh_frame)
loader_stage_other_positions=(memory file share_memory socket)


for file in ${test_dir_files};do
  test_file=${test_dir}/${file}
  for loader_stage_one_position in "${loader_stage_one_positions[@]}";do
    for loader_stage_other_position in "${loader_stage_other_positions[@]}";do
      ls -ll  ./test_out/${file}/input_elf_normal_debug_${loader_stage_one_position}_${loader_stage_other_position}.log
      ls -ll ./test_out/${file}/input_elf_sandbox_debug_${loader_stage_one_position}_${loader_stage_other_position}.log
      ls -ll ./test_out/${file}/input_elf_normal_release_${loader_stage_one_position}_${loader_stage_other_position}.log
      ls -ll ./test_out/${file}/input_elf_sandbox_release_${loader_stage_one_position}_${loader_stage_other_position}.log
      echo ' '
    done
  done
done
