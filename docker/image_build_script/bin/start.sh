#!/bin/bash

if [ $# != 3 ];then
echo "usage: $0 WORKSPACE NAME BASE_PORT"
exit 255
fi
CURRENT_DIR=`cd $(dirname $0); pwd`
WORKSPACE=`cd $1; pwd`
cd ${CURRENT_DIR}

ELF_FILE=${WORKSPACE}/out/input_elf
LIBC_FILE=${WORKSPACE}/out/libc.so
ANALYSIS_SERVER_FILE=${WORKSPACE}/tools/analysis_server.py
IO_DECRYPT_SERVER_FILE=${WORKSPACE}/tools/io_decrypt_server.py
VERIFY_FILE=${WORKSPACE}/tools/verify.py
REPEATER_FILE=${WORKSPACE}/tools/repeater.py
BUILD_ROOT=`cd ../build; pwd`
cd ${CURRENT_DIR}

if [ ! -f ${ELF_FILE} ];then
  echo "File: ${ELF_FILE} not exist"
  exit 255
fi
if [ ! -f ${ANALYSIS_SERVER_FILE} ];then
  echo "File: ${ANALYSIS_SERVER_FILE} not exist"
  exit 255
fi
if [ ! -f ${VERIFY_FILE} ];then
  echo "File: ${VERIFY_FILE} not exist"
  exit 255
fi
if [ ! -f ${REPEATER_FILE} ];then
  echo "File: ${REPEATER_FILE} not exist"
  exit 255
fi

chmod +x ${ELF_FILE}
image_name=$2
container_name="${image_name}1"
base_port=$3
analysis_port=$base_port
redirect_port=$base_port
let redirect_port=redirect_port+1
test_port=$base_port
let test_port=test_port+2
io_decrypt_port=$base_port
let io_decrypt_port=io_decrypt_port+3
ssh_server_port=$base_port
let ssh_server_port=base_port+4
local_sandbox_port=base_port
let local_sandbox_port=local_sandbox_port+5
echo "Docker Image Name:        $image_name"
echo "Docker Container Name:    $container_name"
echo "Record Analysis Port:     $analysis_port"
echo "Sandbox Redirect Port:    $redirect_port"
echo "Local Test Port:          $test_port"
echo "IO Decrypt Port:          $io_decrypt_port"
echo "SSH Server Port:          $ssh_server_port"
echo "Local Sandbox Port:       $local_sandbox_port"

#test_port and local_sandbox_port is use for us only

#sandbox_mode:        gamebox  -->  $io_decrypt_port  --> $redirect_port(true ELF) -->  $analysis_port
#non-sandbox_mode:    gamebox  -->  $analysis_port

BUILD_PROJECT=${BUILD_ROOT}/$image_name
if [ ! -d ${BUILD_PROJECT} ];then
  mkdir -p ${BUILD_PROJECT}
else
  rm -rf ${BUILD_PROJECT}
  mkdir -p ${BUILD_PROJECT}
fi

cp -r ../resource ${BUILD_PROJECT}
cp ${ELF_FILE} ${BUILD_PROJECT}/resource/
cp ${LIBC_FILE} ${BUILD_PROJECT}/resource/
cp ${ANALYSIS_SERVER_FILE} ${BUILD_PROJECT}/resource/
cp ${IO_DECRYPT_SERVER_FILE} ${BUILD_PROJECT}/resource/
cp ${VERIFY_FILE} ${BUILD_PROJECT}/resource/
cp ${REPEATER_FILE} ${BUILD_PROJECT}/resource/


ELF_FILE=${BUILD_PROJECT}/resource/input_elf
LIBC_FILE=${BUILD_PROJECT}/resource/libc.so
ANALYSIS_SERVER_FILE=${BUILD_PROJECT}/resource/analysis_server.py
IO_DECRYPT_SERVER_FILE=${BUILD_PROJECT}/resource/io_decrypt_server.py
VERIFY_FILE=${BUILD_PROJECT}/resource/verify.py
REPEATER_FILE=${BUILD_PROJECT}/resource/repeater.py


DOCKER_START_FILE=${BUILD_PROJECT}/resource/docker_start.sh
CTF_XINEDT_CONF=${BUILD_PROJECT}/resource/ctf/ctf.xinetd
CTF_XINEDT_TEST_CONF=${BUILD_PROJECT}/resource/ctf_test/ctf.xinetd.test
CTF_XINEDT_TEST_SANDBOX_CONF=${BUILD_PROJECT}/resource/sandbox/sandbox.xinetd
CONFIG_JSON=${WORKSPACE}/out/config.json

sed -i "s/IO_DECRYPT_LISTEN_HOST/0.0.0.0/g" ${DOCKER_START_FILE}
sed -i "s/IO_DECRYPT_LISTEN_PORT/${io_decrypt_port}/g" ${DOCKER_START_FILE}
sed -i "s/IO_DECRYPT_UPSTREAM_HOST/127.0.0.1/g" ${DOCKER_START_FILE}
sed -i "s/IO_DECRYPT_UPSTREAM_PORT/${redirect_port}/g" ${DOCKER_START_FILE}

if [ ! -z "$(cat ${DOCKER_START_FILE}|grep ${io_decrypt_port})" ];then
    echo "success set ${DOCKER_START_FILE} io_decrypt_listen port:      ${io_decrypt_port}"
else
    echo "failed  set ${DOCKER_START_FILE} io_decrypt_listen port:      ${io_decrypt_port}"
    exit 255
fi


if [ ! -z "$(cat ${DOCKER_START_FILE}|grep ${redirect_port})" ];then
    echo "success set ${DOCKER_START_FILE} io_decrypt_upstream port:    ${redirect_port}"
else
    echo "failed  set ${DOCKER_START_FILE} io_decrypt_upstream port:    ${redirect_port}"
    exit 255
fi

sed -i "s/ANALYSIS_SERVER_HOST/0.0.0.0/g" ${DOCKER_START_FILE}
sed -i "s/ANALYSIS_SERVER_PORT/${analysis_port}/g" ${DOCKER_START_FILE}
if [ ! -z "$(cat ${DOCKER_START_FILE}|grep ${analysis_port})" ];then
    echo "success set ${DOCKER_START_FILE} analysis_server listen:      ${analysis_port}"
else
    echo "failed  set ${DOCKER_START_FILE} analysis_server listen:      ${analysis_port}"
    exit 255
fi



sed -i "s/    port        = .*/    port        = ${redirect_port}/g" ${CTF_XINEDT_CONF}
if [ ! -z "$(cat ${CTF_XINEDT_CONF}|grep ${redirect_port})" ];then
    echo "success set ${CTF_XINEDT_CONF} to listen:                    ${redirect_port}"
else
    echo "failed  set ${CTF_XINEDT_CONF} to listen:                    ${redirect_port}"
    exit 255
fi

sed -i "s/    port        = .*/    port        = $test_port/g" ${CTF_XINEDT_TEST_CONF}
if [ ! -z "$(cat ${CTF_XINEDT_TEST_CONF}|grep ${test_port})" ];then
    echo "success set ${CTF_XINEDT_TEST_CONF} to listen:          ${test_port}"
else
    echo "failed  set ${CTF_XINEDT_TEST_CONF} to listen:          ${test_port}"
    exit 255
fi

sed -i "s/    port        = .*/    port        = ${local_sandbox_port}/g" ${CTF_XINEDT_TEST_SANDBOX_CONF}
if [ ! -z "$(cat ${CTF_XINEDT_TEST_SANDBOX_CONF}|grep ${local_sandbox_port})" ];then
    echo "success set ${CTF_XINEDT_TEST_SANDBOX_CONF} to listen:            ${local_sandbox_port}"
else
    echo "failed  set ${CTF_XINEDT_TEST_SANDBOX_CONF} to listen:            ${local_sandbox_port}"
    exit 255
fi

#echo "[ATTENTION]:You need manuls set config.json: sandbox_server_port  to --> ${io_decrypt_port}"
#echo "[ATTENTION]:You need manuls set config.json: analysis_server_port to --> ${analysis_port}"

sed -i "s/\"sandbox_server_port\":.*/\"sandbox_server_port\": \"${io_decrypt_port}\",/g" ${CONFIG_JSON}
if [ ! -z "$(cat ${CONFIG_JSON}|grep ${io_decrypt_port})" ];then
    echo "success set ${CONFIG_JSON} to listen:            ${io_decrypt_port}"
else
    echo "failed  set ${CONFIG_JSON} to listen:            ${io_decrypt_port}"
    exit 255
fi

sed -i "s/\"analysis_server_port\":.*/\"analysis_server_port\": \"${analysis_port}\",/g" ${CONFIG_JSON}
if [ ! -z "$(cat ${CONFIG_JSON}|grep ${analysis_port})" ];then
    echo "success set ${CONFIG_JSON} to listen:            ${analysis_port}"
else
    echo "failed  set ${CONFIG_JSON} to listen:            ${analysis_port}"
    exit 255
fi




mkdir ${BUILD_PROJECT}/cmake_build_release


if [ ! -z "$(file ${ELF_FILE}|grep 80386)" ];then
    echo "target is i386"
    cd ${BUILD_PROJECT}/cmake_build_release
    cmake -D CMAKE_BUILD_TYPE=Release -D TARGET_ARCH=X86 ${WORKSPACE}
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

elif [ ! -z "$(file ${ELF_FILE}|grep x86-64)" ];then
    echo "target is amd64"
    cd ${BUILD_PROJECT}/cmake_build_release
    cmake -D CMAKE_BUILD_TYPE=Release -D TARGET_ARCH=X86_64 ${WORKSPACE}
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
elif [ ! -z "$(file ${ELF_FILE}|grep arm)" ];then
    echo "target is arm,not support yet"
    exit 255
else
    echo "unknown file type: $(file ${ELF_FILE})"
    exit 255
fi

cp -r ${WORKSPACE}/out ${BUILD_PROJECT}/



docker stop $container_name
docker rm $container_name
docker rmi $image_name
exit 255

docker build ./ -t $image_name
docker run -d -p 0.0.0.0:$analysis_port:$analysis_port -p 0.0.0.0:$redirect_port:$redirect_port -p 0.0.0.0:$test_port:$test_port -p 0.0.0.0:$io_decrypt_port:$io_decrypt_port -p 0.0.0.0:$ssh_server_port:22 -p 0.0.0.0:$local_sandbox_port:$local_sandbox_port --name $container_name --privileged=true $image_name