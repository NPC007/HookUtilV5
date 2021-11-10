#!/bin/bash

if [ $# == 1 ];then
  slient=1
else
  slient=0
fi


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
TEST_TARGET_ARCH=$(file out/input_elf | grep ARM)
if [ ! -z "${TEST_TARGET_ARCH}" ];then
  TARGET_ARCH=ARM
  echo "set TARGET_ARCH: ARM"
fi
if [ -z "${TARGET_ARCH}" ];then
  echo 'TARGET_ARCH Unknown, failed, exit'
  file ${target_out_dir}/input_elf
  exit 255
fi

if [ $slient == 0 ];then
  rm -rf ./build
  mkdir -p ./build
  cd ./build
  cmake -D CMAKE_BUILD_TYPE=Release -D TARGET_ARCH=${TARGET_ARCH} ../
  if [ $? -ne 0 ]; then
    echo "cmake failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo ${test_file}
    exit 255
  fi
  make -j8
    if [ $? -ne 0 ]; then
    echo "make failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo ${test_file}
    exit 255
  fi
else
  rm -rf ./build
  mkdir -p ./build
  cd ./build
  cmake -D CMAKE_BUILD_TYPE=Release -D TARGET_ARCH=${TARGET_ARCH} ../ 2>&1 > /tmp/build_release_cmake.log
  if [ $? -ne 0 ]; then
    cat /tmp/build_release_cmake.log
    echo "cmake failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo ${test_file}
    exit 255
  fi
  make -j8 2>&1 > /tmp/build_release_make.log
    if [ $? -ne 0 ]; then
      cat /tmp/build_release_make.log
      echo "make failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
      echo ${test_file}
    exit 255
  fi
fi
