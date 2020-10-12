#!/bin/bash

docker pull ubuntu:16.04
cp -r ../common ./
docker build ./ -t ubuntu:ctf_tools_1604
rm -rf common
