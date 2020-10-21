#!/bin/bash


rm -rf ./test_out/ 2>/dev/null
target_out_dir=../out/
test_dir=binary
test_dir_files=$(ls ./${test_dir}/)
current_dir=$(pwd)
echo 's/\s*"project_root.*$/  "project_root":"'${current_dir//\//\\\/}'\/..\/",/g'
sed 's/\s*"project_root.*$/  "project_root":"'${current_dir//\//\\\/}'\/..\/",/g' -i ../out/config.json

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


for binary_dir in ${test_dir_files};do
  cd ${current_dir}
  test_sub_dir=${test_dir}/${binary_dir}
  echo "begin test ${test_sub_dir}"
  exit -1
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


  rm -rf ./test_out/${file}/build
  mkdir -p ./test_out/${file}/build
  cd ./test_out/${file}/build
  cmake -D CMAKE_BUILD_TYPE=Debug -D TARGET_ARCH=${TARGET_ARCH} ../../../../
  if [ $? -ne 0 ]; then
    echo "cmake failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo ${test_file}
    exit 255
  fi
  make
    if [ $? -ne 0 ]; then
    echo "make failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo ${test_file}
    exit 255
  fi
  cd ${current_dir}
  mkdir -p ./test_out/${file}/out_debug/
  cp -r ../out/* ./test_out/${file}/out_debug/
  cp -f ../out/normal.datafile /tmp/1
  cat ${input_file} | ./test_out/${file}/out_debug/input_elf_normal  > ./test_out/${file}/input_elf_normal_debug.log
  cp -f ../out/sandbox.datafile /tmp/1
  cat ${input_file} | ./test_out/${file}/out_debug/input_elf_sandbox  > ./test_out/${file}/input_elf_sandbox_debug.log



  rm -rf ./test_out/${file}/build
  mkdir -p ./test_out/${file}/build
  cd ./test_out/${file}/build
  cmake -D CMAKE_BUILD_TYPE=Release -D TARGET_ARCH=${TARGET_ARCH} ../../../../
  if [ $? -ne 0 ]; then
    echo "cmake failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo ${test_file}
    exit 255
  fi
  make
    if [ $? -ne 0 ]; then
    echo "make failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo ${test_file}
    exit 255
  fi
  cd ${current_dir}
  mkdir -p ./test_out/${file}/out_release/
  cp -r ../out/* ./test_out/${file}/out_release/
  cp -f ../out/normal.datafile /tmp/1
  cat ${input_file} | ./test_out/${file}/out_release/input_elf_normal  > ./test_out/${file}/input_elf_normal_release.log
  cp -f ../out/sandbox.datafile /tmp/1
  cat ${input_file} | ./test_out/${file}/out_release/input_elf_sandbox  > ./test_out/${file}/input_elf_sandbox_release.log

   #exit 0
done

for file in ${test_dir_files};do
  test_file=${test_dir}/${file}
  ls -ll  ./test_out/${file}/input_elf_normal_debug.log
  ls -ll ./test_out/${file}/input_elf_sandbox_debug.log
  ls -ll ./test_out/${file}/input_elf_normal_release.log
  ls -ll ./test_out/${file}/input_elf_sandbox_release.log
done
