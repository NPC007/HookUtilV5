#!/bin/bash

docker pull ubuntu:20.04
cp -r ../common ./
docker build ./ -t ubuntu:ctf_tools_2004_restrict
rm -rf common
