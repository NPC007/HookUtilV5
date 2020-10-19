#!/bin/bash

docker pull ubuntu:19.04
cp -r ../common ./
docker build ./ -t ubuntu:ctf_tools_1904_restrict
rm -rf common
