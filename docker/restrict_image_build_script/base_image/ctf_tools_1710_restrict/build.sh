#!/bin/bash

docker pull ubuntu:17.10
cp -r ../common ./
docker build ./ -t ubuntu:ctf_tools_1710_restrict
rm -rf common
