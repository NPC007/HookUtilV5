#!/bin/bash

docker pull ubuntu:18.04
cp -r ../common ./
docker build ./ -t ubuntu:ctf_tools_1804
rm -rf common
