#!/bin/bash

docker pull ubuntu:17.04
cp -r ../common ./
docker build ./ -t ubuntu:ctf_tools_1704_restrict
rm -rf common
