#!/bin/bash

docker pull ubuntu:16.04
docker pull ubuntu:18.04
docker pull ubuntu:19.04
docker pull ubuntu:20.04

cd ctf_tools_1604 && ./build.sh
cd ..
cd ctf_tools_1804 && ./build.sh
cd ..
cd ctf_tools_1904 && ./build.sh
cd ..
cd ctf_tools_2004 && ./build.sh

