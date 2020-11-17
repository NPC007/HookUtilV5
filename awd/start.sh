#!/bin/bash

usage(){
  echo "$0 challenge_dir "
  exit 255
}

challenge_dir=$1
if [ -f "${target}" ];then
  echo "challenge_dir is not exist: ${challenge}"
  usage
fi

challenge_dir_out=${challenge}/generate/
rm -rf ${challenge_dir_out}
current_dir=$(pwd)
echo 's/\s*"project_root.*$/  "project_root":"'${current_dir//\//\\\/}'\/..\/",/g'
sed 's/\s*"project_root.*$/  "project_root":"'${current_dir//\//\\\/}'\/..\/",/g' -i ../out/normal_config.json
sed 's/\s*"project_root.*$/  "project_root":"'${current_dir//\//\\\/}'\/..\/",/g' -i ../out/sandbox_config.json



