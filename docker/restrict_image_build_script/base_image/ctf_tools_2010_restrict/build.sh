#!/bin/bash

docker pull ubuntu:20.10
cp -r ../common ./
docker build ./ -t ubuntu:ctf_tools_2010_restrict
rm -rf common
