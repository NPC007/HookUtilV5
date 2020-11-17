#!/bin/bash

docker pull ubuntu:16.10
cp -r ../common ./
docker build ./ -t ubuntu:ctf_tools_1610_restrict
rm -rf common
