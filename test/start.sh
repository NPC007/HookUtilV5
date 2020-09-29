#!/bin/bash

make clean
make all
rm -rf ./test_out/ 2>/dev/null
target_out_dir=../out/
test_dir=test_target_bin
test_dir_files=$(ls ./${test_dir}/)
current_dir=$(pwd)
for file in ${test_dir_files};do
  cd ${current_dir}
  test_file=${test_dir}/${file}
  echo ${test_file}
  mkdir -p ./test_out/${file}
  cp -f ${test_file} ./test_out/${file}/
  cp -f ${test_file}  ${target_out_dir}/input_elf
  TARGET_ARCH=$(file ${target_out_dir}/input_elf | grep 80386)
  if [ ! -n "${TARGET_ARCH}" ];then
    TARGET_ARCH=X86
  fi
  TARGET_ARCH=$(file ${target_out_dir}/input_elf | grep x86-64)
  if [ ! -n "${TARGET_ARCH}" ];then
    TARGET_ARCH=X86_64
  fi
  echo ${TARGET_ARCH}


  rm -rf ./test_out/${file}/build
  mkdir -p ./test_out/${file}/build
  cd ./test_out/${file}/build
  cmake -D CMAKE_BUILD_TYPE=Debug TARGET_ARCH=${TARGET_ARCH} ../../../../
  if [ $? -ne 0 ]; then
    echo "cmake failed"
    echo ${test_file}
    exit 255
  fi
  make
  cd ${current_dir}
  mkdir -p ./test_out/${file}/out_debug/
  cp -r ../out/* ./test_out/${file}/out_debug/
  echo -e "3\n" | ./test_out/${file}/out_debug/input_elf_normal  > ./test_out/${file}/input_elf_normal_debug.log
  echo -e "3\n" | ./test_out/${file}/out_debug/input_elf_sandbox  > ./test_out/${file}/input_elf_sandbox_debug.log

  exit 0

  rm -rf ./test_out/${file}/build
  mkdir -p ./test_out/${file}/build
  cd ./test_out/${file}/build
  cmake -D CMAKE_BUILD_TYPE=Release TARGET_ARCH=${TARGET_ARCH} ../../../../
  if [ $? -ne 0 ]; then
    echo "cmake failed"
    echo ${test_file}
    exit 255
  fi
  make
  cd ${current_dir}
  mkdir -p ./test_out/${file}/out_release/
  cp -r ../out/* ./test_out/${file}/out_release/
  echo -e "3\n" | ./test_out/${file}/out_release/input_elf_normal  > ./test_out/${file}/input_elf_normal_release.log
  echo -e "3\n" | ./test_out/${file}/out_release/input_elf_sandbox  > ./test_out/${file}/input_elf_sandbox_release.log
done

for file in ${test_dir_files};do
  test_file=${test_dir}/${file}
  ls -ll  ./test_out/${file}/input_elf_normal_debug.log
  ls -ll ./test_out/${file}/input_elf_sandbox_debug.log
  ls -ll ./test_out/${file}/input_elf_normal_release.log
  ls -ll ./test_out/${file}/input_elf_sandbox_release.log
done
