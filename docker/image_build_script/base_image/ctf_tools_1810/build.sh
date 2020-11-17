#!/bin/bash

docker pull ubuntu:18.10
cp -r ../common ./
docker build ./ -t ubuntu:ctf_tools_1810
rm -rf common
