#! /usr/bin/python3
import sys
import json
import os
import mmap
import ctypes
from pwn import *
from pwnlib.elf.datatypes import generate_prpsinfo
import socket
from file.file_utils import *

global config
global arch

def usage(file_name):
    print("usage: {} config.json\n".format(file_name))
    print("     : mode is: normal, sandbox\n")

def generate_data_file(data_file_path, libloader_stage_two, libloader_stage_three):
    stage_two = ELF(libloader_stage_two)
    stage_three = ELF(libloader_stage_three)
    libloader_stage_two_buf = stage_two.get_section_by_name('.text').data()
    libloader_stage_two_len = len(libloader_stage_two_buf)
    target_fd = os.open(data_file_path, os.O_RDWR|os.O_TRUNC|os.O_CREAT, 0o777)
    entry_offset = stage_two.entry - stage_two.get_section_by_name('.text').header.sh_addr
    if entry_offset != 0:
        logger("stage two elf error: _start not in first text bytesm we need it to be first bytes to decrease stage_one bytes\n")
        exit(255)
    
    os.write(target_fd, p32(libloader_stage_two_len)) #length
    os.write(target_fd, p32(entry_offset)) #entry_offset
    os.write(target_fd, b'\x00\x00\x00\x00') #patch_data_len
    if arch == 'i386':
        os.write(target_fd, b'\x00\x00\x00\x00')
    elif arch == 'amd64':
        os.write(target_fd, b'\x00'*0xc) # 4 align 8 void*
    os.write(target_fd ,libloader_stage_two_buf)
    logger("libloader_stage_two TLV structure values:\n");
    logger("\tlength:                     {}\n".format(hex(libloader_stage_two_len)));
    logger("\tentry_offset:               {}\n".format(entry_offset));

    import hashlib
    if 'shell_password' in config:
        logger("generate md5 password")
        shell_password = hashlib.md5(bytes(config['shell_password'], encoding='utf-8')).hexdigest()
        shell_password = bytes.fromhex(shell_password)
    
    three_entry_offset = stage_three.entry
    three_length = get_file_size(libloader_stage_three)

    three_analysis_server_sin_addr = b'\x00'*4
    three_analysis_server_sin_port = 0
    three_sandbox_server_sin_addr = b'\x00'*4
    three_sandbox_server_sin_port = 0
    

    if 'analysis_server_ip' in config and 'analysis_server_port' in config:
        three_analysis_server_sin_addr = socket.inet_aton(config['analysis_server_ip'])
        three_analysis_server_sin_port = socket.htons(int(config['analysis_server_port']))
    


    if 'sandbox_server_ip' in config and 'sandbox_server_port' in config:
        three_sandbox_server_sin_addr = socket.inet_aton(config['sandbox_server_ip'])
        three_sandbox_server_sin_port = socket.htons(int(config['sandbox_server_port']))
    
    logger("libloader_stage_three TLV structure values:\n");
    logger("\tentry_offset:                     {}\n".format(hex(three_entry_offset)))
    logger("\tlength:                           {}\n".format(hex(three_length)))
    logger("\tanalysis_server_ip:               {}\n".format(socket.inet_ntoa(three_analysis_server_sin_addr)))
    logger("\tanalysis_server_port:             {}\n".format(socket.htons(int(three_analysis_server_sin_port))))
    logger("\tsandbox_server_ip:                {}\n".format(socket.inet_ntoa(three_sandbox_server_sin_addr)))
    # logger("\tsandbox_server_port:              {}\n".foramt(socket.htons(int(three_sandbox_server_sin_port))))
    
    os.write(target_fd, p32(three_length))
    os.write(target_fd, p32(three_entry_offset))
    if arch=='i386':
        os.write(target_fd, b'\x00'*0x14)
        os.write(target_fd, shell_password)
    elif arch=='amd64':
        os.write(target_fd, b'\x00'*0x20)
        os.write(target_fd, shell_password)
    os.write(target_fd, b'\x00'*0x30)
    os.write(target_fd, p16(2)) # af_inet
    print(type(three_analysis_server_sin_port))
    os.write(target_fd, p16(three_analysis_server_sin_port))
    os.write(target_fd, three_analysis_server_sin_addr)
    os.write(target_fd, b'\x00'*8) #padding for struct(heap align)
    os.write(target_fd, p16(2)) # af_inet
    os.write(target_fd, p16(three_sandbox_server_sin_port))
    os.write(target_fd, three_sandbox_server_sin_addr)
    os.write(target_fd, b'\x00'*8)

    xor_data = ['\x45','\xf8','\x66','\xab','\x55']
    encry_data = get_file_content(libloader_stage_three)
    xor_buf = b''
    for i in range(len(encry_data)):
        xor_buf += bytes([encry_data[i] ^ ord(xor_data[i%len(xor_data)])])
    
    os.write(target_fd, xor_buf)
    os.chmod(data_file_path,0o777)

def check_libloader_stage_two(libloader_stage_two):
    elf = ELF(libloader_stage_two)
    if elf.load_addr != 0:
        logger("check_so_file_is_pie_execute_file failed, loader should be PIE compiled : {}\n".format(libloader_stage_two))
        exit(-1)
    if elf.dynamic_value_by_tag('DT_PLTGOT') != None:
        logger("so file check error, should not have DT_PLTGOT : {}\n".format(libloader_stage_two))
    if elf.dynamic_value_by_tag('DT_RELA') != None or elf.dynamic_value_by_tag('DT_REL') != None:
        logger("so file check error, should not have DT_RELA or DT_REL: {}\n".format(libloader_stage_two))
    
    sections_black = ['.rodata', '.data', '.gotplt', '.plt', '.bss']
    for i in sections_black:
        if elf.get_section_by_name(i) != None:
            logger("so file check error, shoud not have {} section: {}\n".format(i, libloader_stage_two))
    logger("check {} end".format(libloader_stage_two))

def check_libloader_staget_three(libloader_stage_three):
    elf = ELF(libloader_stage_three)
    if elf.load_addr != 0:
        logger("check_so_file_is_pie_execute_file failed, loader should be PIE compiled : {}\n".format(libloader_stage_three))
        exit(-1)
    
    if elf.dynamic_value_by_tag('DT_PLTGOT') != None:
        logger("so file check error, should not have DT_PLTGOT : {}\n".format(libloader_stage_three))
    if elf.dynamic_value_by_tag('DT_RELA') != None or elf.dynamic_value_by_tag('DT_REL') != None:
        logger("so file check error, should not have DT_RELA or DT_REL: {}\n".format(libloader_stage_three))
            

def generate_stage_two_parameter(elf_path, data_file_path):
    fd, mmap_tmp, size = open_mmap_check(data_file_path, os.O_RDWR, mmap.PROT_READ|mmap.PROT_WRITE,mmap.MAP_SHARED)
    mmap_tmp.seek(8)
    logger("patch size {}\n".format(hex(size)) )
    mmap_tmp.write(p32(size))
    if arch == 'i386':
        mmap_tmp.write(p32(ELF(elf_path).load_addr))
    elif arch == 'amd64':
        mmap_tmp.write(p64(ELF(elf_path).load_addr))

if __name__ == '__main__':
    g_logger_fd = -1
    if len(sys.argv) != 3:
        usage(sys.argv[0])
    mode = sys.argv[2]
    if mode != 'normal' or mode != 'sandbox':
        usage(sys.argv[0])
    config_file_name = sys.argv[1]
    print("config file : {}".format(config_file_name))
    with open(config_file_name, 'r') as f:
        config = json.load(f)
    
    project_root = config['project_root']
    logger_file = os.path.join(project_root, 'out', 'build.log')
    init_logger(logger_file, 0)
    logger("MODE : {}\n".format(mode))

    libloader_stage_one = "{}/out/{}/stage_one".format(project_root, mode)
    libloader_stage_two = "{}/out/{}/stage_two".format(project_root, mode)
    libloader_stage_three = "{}/out/{}/stage_three".format(project_root, mode)
    input_elf = config['input_elf']
    target_dir = config['target_dir']
    input_elf_path = os.path.join(project_root, target_dir, input_elf)
    arch = get_arch(input_elf_path)

    logger("stage_one: {}\n".format(libloader_stage_one))
    logger("stage_two: {}\n".format(libloader_stage_two))
    logger("stage_three: {}\n".format(libloader_stage_three))
    logger("input_elf: {}\n".format(input_elf))
    logger("target_elf: {}\n".format(target_dir))
    logger("arch: {}".format(arch))

    if os.access(input_elf_path, os.R_OK) == False:
        logger("Input ELF not exist : {}\n", input_elf_path)
        exit(-1)

    # check_elf_arch(libloader_stage_two)
    # check_elf_arch(libloader_stage_three)
    # 本来是检查编译时的arch和elf的arch是不是一样
    check_libloader_stage_two(libloader_stage_two)
    check_libloader_staget_three(libloader_stage_three)

    if mode == 'normal':
        normal_data_file = config['data_file_path']
        normal_data_file_path = os.path.join(project_root, target_dir, mode, normal_data_file)

        logger("generate normal_data_file:{}\n".format(normal_data_file))
        generate_data_file(normal_data_file_path, libloader_stage_two, libloader_stage_three)
        generate_stage_two_parameter(input_elf_path, normal_data_file_path)
    elif mode == 'sandbox':
        sandbox_data_file = config['data_file_path']
        sandbox_data_file_path = os.path.join(project_root, target_dir, mode, sandbox_data_file)

        logger("generate sandbox_data_file:{}\n".format(sandbox_data_file_path))
        generate_data_file(sandbox_data_file_path, libloader_stage_two, libloader_stage_three)
        generate_stage_two_parameter(input_elf_path,sandbox_data_file_path)
        


        

    




