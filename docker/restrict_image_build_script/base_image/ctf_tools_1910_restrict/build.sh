#!/bin/bash

docker pull ubuntu:19.10
cp -r ../common ./
docker build ./ -t ubuntu:ctf_tools_1910_restrict
rm -rf common
