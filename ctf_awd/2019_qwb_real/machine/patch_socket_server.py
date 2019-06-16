# coding:utf-8
import SocketServer
import os,re,sys
os.environ['PWNLIB_NOTERM']='1'
from pwn import *
import copy
from elftools.elf.elffile import ELFFile
import re
import uuid,os
import traceback
import json
import datetime
import base64

RecvBufferSize = 1024 * 128

'''
enum PACKET_TYPE{
    DATA_IN = 1,
    DATA_OUT,
    DATA_ERR,
    BASE_ELF,
    BASE_LIBC,
    BASE_STACK,
    BASE_HEAP,
    MAP_ADD,
    MAP_DELETE
};
PT_LOAD
'''


# 8uuid 1type 4length
class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

IN_DATA = 1
OUT_DATA = 2
ERR_DATA = 3

class TCPHandler(SocketServer.BaseRequestHandler):
    def read_all(self,file_name):
        with open(file_name,"rb") as f:
            buf = f.read(os.path.getsize(file_name))
            return buf

    def handle(self):
        global patch_data
        remote_addr,port = self.request.getpeername()
        logging.debug("Accept connection from : " + str(remote_addr) +":"+ str(port))
        data = self.read_all(patch_data)
        ret = self.request.send(data)
        print "send size: " + str(ret) + " file_size:" + str(os.path.getsize(patch_data))


def usage():
    print "Usage " + sys.argv[0] + " IP PORT PATCH_DATA"
    exit(-1)


if __name__ == "__main__":
    if len(sys.argv)!=4:
        usage()
        exit(-1)
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)
    HOST, PORT = sys.argv[1],int(sys.argv[2])
    print "Listen   : " + HOST +":" + str(PORT)
    patch_data = sys.argv[3]
    print "Patch_file: " + patch_data
    try:
        SocketServer.TCPServer.allow_reuse_address = True
        server = ThreadedTCPServer((HOST, PORT), TCPHandler)
        server.serve_forever()
    except Exception as e:
        logging.error(e.message)
