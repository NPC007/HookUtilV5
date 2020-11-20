#!/bin/bash


libc_file=$(ldd /bin/bash | grep libc.so.6 | awk -F ' ' '{print $3}')
glibc_build_id=$(readelf -n ${libc_file} | grep -i "Build ID:" | awk -F':' '{print $2}' 2>/dev/null | awk '{gsub(/^\s+|\s+$/, "");print}' 2>/dev/null | awk '$1=$1' 2>/dev/null)
if [ -z "$glibc_build_id" ]; then
  echo "Failed to get glibc build_id"
  exit 255
fi
echo "Get Glibc Build_ID: ${glibc_build_id}"
glibc_debug_symbols_file=
glibc_version=
get_test_libc_version() {
  glibc_version=
  libc_file=$1
  echo "strings ${libc_file} 2>/dev/null|grep -v Fatal | grep 'glibc '|awk -F ' ' '{print $2}'"
  glibc_version=$(strings ${libc_file} 2>/dev/null | grep -v Fatal | grep 'glibc ' | awk -F ' ' '{print $2}')
  echo "detect glibc_version: ${glibc_version}"
}
get_test_libc_version ${libc_file}

if [ "${glibc_version}" == "2.23" ]; then
  glibc_debug_symbols_file="/usr/lib/debug/lib/x86_64-linux-gnu/libc-2.23.so"
elif [ "${glibc_version}" == "2.24" ]; then
  glibc_debug_symbols_file="/usr/lib/debug/lib/x86_64-linux-gnu/libc-2.24.so"
elif [ "${glibc_version}" == "2.25" ]; then
  glibc_debug_symbols_file="UN_KNOWN_LIBC_VERSION"
elif [ "${glibc_version}" == "2.26" ]; then
  glibc_debug_symbols_file="/usr/lib/debug/lib/x86_64-linux-gnu/libc-2.26.so"
elif [ "${glibc_version}" == "2.27" ]; then
  glibc_debug_symbols_file="/usr/lib/debug/lib/x86_64-linux-gnu/libc-2.27.so"
elif [ "${glibc_version}" == "2.28" ]; then
  glibc_debug_symbols_file="/usr/lib/debug/lib/x86_64-linux-gnu/libc-2.28.so"
elif [ "${glibc_version}" == "2.29" ]; then
  glibc_debug_symbols_file="/usr/lib/debug/lib/x86_64-linux-gnu/libc-2.29.so"
elif [ "${glibc_version}" == "2.30" ]; then
  glibc_debug_symbols_file="/usr/lib/debug/lib/x86_64-linux-gnu/libc-2.30.so"
elif [ "${glibc_version}" == "2.31" ]; then
  glibc_debug_symbols_file="/usr/lib/debug/lib/x86_64-linux-gnu/libc-2.31.so"
elif [ "${glibc_version}" == "2.32" ]; then
  glibc_debug_symbols_file="/usr/lib/debug/lib/x86_64-linux-gnu/libc-2.32.so"
else
  echo "unknown glibc verison: ${glibc_version}"
  exit 255
fi
if [ ! -f ${glibc_debug_symbols_file} ];then
  echo "glibc_debug_symbols_file not exist, file_path is wrong: ${glibc_debug_symbols_file}"
  exit 255
fi
echo "glibc_debug_symbols_file path: ${glibc_debug_symbols_file}"
system_glibc_build_id=${glibc_build_id}
test_glibc_build_id=$(readelf -n /root/libc.so | grep -i "Build ID:" | awk -F':' '{print $2}' 2>/dev/null | awk '{gsub(/^\s+|\s+$/, "");print}' 2>/dev/null | awk '$1=$1' 2>/dev/null)
if [ "${system_glibc_build_id}" == "${test_glibc_build_id}" ];then
  cp ${glibc_debug_symbols_file} /usr/lib/debug/libc.so
  cp ${glibc_debug_symbols_file} /libc.so
else
  cp /root/libc.so /
fi