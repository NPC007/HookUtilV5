import os
from pwn import *
import mmap

global g_logger_fd


def get_file_size(file):
    statbuf = os.stat(file)
    # todo: handle error 
    return statbuf.st_size

def get_file_content(file_name):
    f = open(file_name, 'rb')
    data_buf = f.read()
    return data_buf

def get_arch(file_name):
    return ELF(file_name).arch

# def check_file_exist(file_name):
#     if os.access(file_name, os.R_OK) == 0:
#         return 0
#     else:
#         return -1 

def open_mmap_check(file_name, mode, prot, flag):
    fd = os.open(file_name, mode, 777)
    if fd < 0:
        print("unable open file: {}, error:{}\n".format(file_name,os.strerror(os.errno)))
        os.exit(-1)
    file_size = get_file_size(file_name)
    print(hex(file_size))
    size = 0
    if file_size %0x1000 != 0:
        size = int(file_size/0x1000)
        size += 1
        size *=0x1000
        # size = ((file_size/0x1000)+1)*0x1000
        # size = int(size)
    mmap_tmp = mmap.mmap(fd, file_size, flag, prot)
    return fd, mmap_tmp, size


def logger(format_str):
    global g_logger_fd
    if type(format_str) != str:
        print("format should be str")
        exit(-1)
    if g_logger_fd != -1:
        os.write(g_logger_fd, bytes(format_str, encoding='utf-8'))
    os.write(1, bytes(format_str, encoding='utf-8'))

def init_logger(name, re_create):
    global g_logger_fd
    if re_create != 0:
        g_logger_fd = os.open(name, os.O_RDWR | os.O_CREAT|os.O_TRUNC, 0o777)
    else:
        g_logger_fd = os.open(name, os.O_RDWR | os.O_APPEND, 0o777)
    if g_logger_fd < 0:
        print("unable to init logger: {} success, fd={}".format(name, g_logger_fd))