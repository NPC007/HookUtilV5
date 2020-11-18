#!/bin/bash

usage() {
  echo "$0 challenge_dir "
  exit 255
}

challenge_dir=$1
if [ -f "${challenge_dir}" ]; then
  echo "challenge_dir is not exist: ${challenge_dir}"
  usage
fi

challenge_dir_out=${challenge_dir}/generate/
rm -rf ${challenge_dir_out}
current_dir=$(pwd)
normal_config=${challenge_dir}/normal_config.json
sandbox_config=${challenge_dir}/sandbox_config.json
echo 's/\s*"project_root.*$/  "project_root":"'${current_dir//\//\\\/}'\/..\/",/g'
sed 's/\s*"project_root.*$/  "project_root":"'${current_dir//\//\\\/}'\/..\/",/g' -i ${normal_config}
sed 's/\s*"project_root.*$/  "project_root":"'${current_dir//\//\\\/}'\/..\/",/g' -i ${sandbox_config}
cp -f ${normal_config} ${current_dir}/../out/normal_config.json
cp -f ${sandbox_config} ${current_dir}/../out/sandbox_config.json

g_test_file=
get_test_file() {
  g_test_file=
  files=$(ls ./${1}/)
  for file in ${files}; do
    if [[ ${file} == *libc* ]]; then
      continue
    fi
    test_execute=$(file ${1}/${file} | grep 80386)
    if [ ! -z "${test_execute}" ]; then
      g_test_file=${1}/${file}
      return 0
    fi
    test_execute=$(file ${1}/${file} | grep x86-64)
    if [ ! -z "${test_execute}" ]; then
      g_test_file=${1}/${file}
      return 0
    fi
  done
}

g_test_libc_file=
get_test_libc_file() {
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
init_script_file=${test_sub_dir}/init_env.sh
echo "get test_file:      ${test_file}"
echo "get test_libc_file: ${test_libc_file}"
echo "get test_poc_file:  ${test_poc_file}"
if [ ! -f "${test_libc_file}" ]; then
  echo "Dir ${test_sub_dir} not find libc file,failed"
  exit 255
fi
if [ ! -f "${init_script_file}" ]; then
  echo "Dir ${test_sub_dir} not find init_env.sh file"
  init_script_file="_______UN_EXIST_FILE______"
fi
