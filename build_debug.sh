#!/bin/bash


TEST_TARGET_ARCH=$(file out/input_elf | grep 80386)
if [ ! -z "${TEST_TARGET_ARCH}" ];then
  TARGET_ARCH=X86
  echo "set TARGET_ARCH: X86"
fi
TEST_TARGET_ARCH=$(file out/input_elf | grep x86-64)
if [ ! -z "${TEST_TARGET_ARCH}" ];then
  TARGET_ARCH=X86_64
  echo "set TARGET_ARCH: X86_64"
fi
if [ -z "${TARGET_ARCH}" ];then
  echo 'TARGET_ARCH Unknown, failed, exit'
  file ${target_out_dir}/input_elf
  exit 255
fi

rm -rf ./build
mkdir -p ./build
cd ./build
cmake -D CMAKE_BUILD_TYPE=Debug -D TARGET_ARCH=${TARGET_ARCH} ../
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