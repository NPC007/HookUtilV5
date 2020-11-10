#!/bin/bash

SHELL_FOLDER=$(cd "$(dirname "$0")";pwd)
cd $SHELL_FOLDER
rm -f generate
rm -f stage_one_normal
rm -f stage_one_sandbox
rm -f stage_one_pre_generate
rm -f stage_two
rm -f stage_three_normal
rm -f stage_three_sandbox
rm -f sandbox.datafile
rm -f normal.datafile
rm -f datafile_generate
rm -f pre_generate
rm -f input_elf_normal
rm -f input_elf_sandbox
rm -f stage_share_memory_server
rm -f stage_socket_server


cd normal
rm * -rf
cd ../sandbox
rm * -rf
cd ../tools
rm * -rf
cd ../stage_server
rm * -rf