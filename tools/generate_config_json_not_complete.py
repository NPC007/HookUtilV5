import os,re,sys
os.environ['PWNLIB_NOTERM']='1'
from pwn import *
import json


def get_config_from_elf(elf_file,base_json_config):
    elf = ELF(elf_file)
    print elf


if __name__ == "__main__":
    elf_file = "babyheap"
    source_dir = "/home/runshine/HookUtilV3"
    os.chdir(source_dir)
    base_json_config = json.loads("".join(open(os.path.join(source_dir,"config.json"),"r").readlines()))
    get_config_from_elf(elf_file,base_json_config)
