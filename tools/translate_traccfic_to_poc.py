import re 
from elftools.elf.elffile import ELFFile
import json
import sys



def string_escape_decode(byte_array):
    return (byte_array.decode('latin1')         # To bytes, required by 'unicode-escape'
            .encode('unicode-escape') # Perform the actual octal-escaping decode
            .decode('latin1'))         # 1:1 mapping back to bytes

def string_escape_encode(s):
    return (s.encode('latin1')         # To bytes, required by 'unicode-escape'
            .decode('unicode-escape') # Perform the actual octal-escaping decode
            .encode('latin1'))

re_str = r'{{{(?P<content>.+?)}}}'
    
#LIBC_BASE:456336:6:ORI:138:0x7fdbcb79b690

type_encaddress = {
    'LIBC_BASE' : 'libc_address',
    'ELF_BASE' : 'elf_address',
    'STACK_BASE' : 'stack_address',
    'HEAP_BASE' : 'heap_address'
    }
type_encbase = {
    'LIBC_BASE' : 'libc_base',
    'ELF_BASE' : 'elf_base',
    'STACK_BASE' : 'stack_base',
    'HEAP_BASE' : 'heap_base'
    }

# dec int(buf,10)
# hex int(buf,16)
# ori u64(recv(6).ljust(8,0))

def recv_value(d):
    #print (d)
    t = ''
    #     xx_address = recv()
    leak_name = type_encaddress[d['type']]
    base_name = type_encbase[d['type']]
    length = int(d['length'])
    value_type = d['value_type']
    offset = int(d['offset'])

    buf = 'p.recv(' + str(length) + ')'
    t += "recv_traffic += '$'*{}\n".format(length)
    t += leak_name + ' = '
    if value_type == 'HEX' or value_type == '0XHEX':
        t += 'int( ' + buf + ', 16)\n'
    elif value_type == 'HEX':
        t += 'int( ' + buf + ', 10)\n'
    elif value_type == 'ORI':
        if length == 6:
            t += 'u64(' + buf + '.ljust(8,\'\\x00\'))\n'
        elif length == 4:
            t += 'u32(' + buf + ')'
        
    t += base_name + ' = ' + leak_name + ' - ' + str(offset) + '\n'
    return t

    
def recv_until(str_tmp):
    t = ''
    t += 'p.recv_until(\'' + str_tmp + '\')\n'
    return t
        
    

def parse_content(content):
    d = {}
    t = content.split(':')
    d['type'] = t[0]
    d['offset'] = int(t[1])
    d['length'] = int(t[2])
    d['value_type'] = t[3]
    d['position'] = int(t[4])
    return d

def recv_n(length):
    t = ''
    t += 'recv_traffic += p.recvn({})\n'.format(length)
    return t

def func2(m):
    n = m.string[m.start():m.end()]
    content = m.group('content')
    parse_d = parse_content(content)
    length = parse_d['length']
    return '$' * length
    

def gen_in(str_tmp, fd, step):
    t = "recv_traffic = b''\n"
    str_tmp = string_escape_encode(str_tmp).decode('latin1')
    rest_str = str_tmp
    is_var = False
    
    while match := re.search(re_str, rest_str):
        is_var = True
        
        start = match.start()
        if start !=0:
            #t += recv_until(rest_str[:start])
            t += recv_n(len(rest_str[:start]))
        end = match.end()
        rest_str = rest_str[end:]
        content = match.group('content')
        parse_d = parse_content(content)
        t += recv_value(parse_d)
        
    #t += recv_until(rest_str)
    t += recv_n(len(rest_str))
    t += '# ---------step {}-----------\n'.format(step)
    if is_var:
        check_str = str_tmp
    else:
        check_str = re.sub(re_str, func2, str_tmp)
    t += 'check_step({}, recv_traffic)\n\n\n'.format(step)
    fd.write(t)
        

def send(str_tmp):
    t = ''
    t += 'p.send(b\'' + str_tmp + '\')\n'
    return t

def gen_value(d):
    t = ''
    base_name = type_encaddress[d['type']]
    length = int(d['length'])
    offset = int(d['offset'])
    if length == 4:
        t += ' p32(' + base_name + '+' + str(offset) + ') '
    elif length == 8:
        t += ' p64(' + base_name + '+' + str(offset) + ') '
    return t



def gen_const(str_tmp):
    t = ''
    t += " b'{}' ".format(str_tmp)
    return t

    

def func(m):
    n=m.string[m.start():m.end()]
    if len(n) >= 8:
        return '{{{{{{REPEAT:{}:{}}}}}}}'.format(n[0],len(n))
    else:
        return n


def check_repeat(str_tmp):
    return re.sub(r'(.)\1+', func, str_tmp)
    
def gen_repeat(str_tmp):
    split_tmp = str_tmp.split(':')
    char_tmp = split_tmp[1]
    length = int(split_tmp[2])
    t = ''
    t += " '{}'*{} ".format(char_tmp, length)
    return t

def send_offset(str_tmp):
    rest_str = check_repeat(str_tmp)
    # print(rest_str)
    t = 'payload = '
    flag = True
    while match:=re.search(re_str, rest_str):
        start = match.start()
        if start != 0:
            t += gen_const(rest_str[:start]) + '+'
            flag = False
        end = match.end()
        rest_str = rest_str[end:]
        content = match.group('content')
        if content[:6] == 'REPEAT':
            t += gen_repeat(content) + '+'
        else:
            parse_d = parse_content(content)
            t += gen_value(parse_d) + '+'
    t += gen_const(rest_str)
    t += '\n'
    t += "p.send(payload)\n"
    return t
        
        

def gen_out(str_tmp, fd):
    t = ''
    rest_str = str_tmp
    if re.search(re_str, rest_str) == None:
        t += send(rest_str)
    else:
        t += send_offset(str_tmp)
    fd.write(t)

    
    
def gen_header(host, port, fd):
    t = 'import os\n'
    t += "os.environ['PWNLIB_NOTERM']='1'\n"
    t += 'from pwn import *\n'
    t += 'context.log_level = \'debug\'\n'
    t += 'p = remote( \'' + host +'\', ' + str(port) + ')\n'
    fd.write(t)
    
def gen_check_str(data, fd):
    t = '\n\ncheck_str = []\n'
    for i in data:
        type_t = i[0]
        if type_t == '1' or type_t == '2':
            i = i[1:]
            if re.search(re_str, i):
                t += "check_str.append(b'{}')\n".format(re.sub(re_str,func2,i))
            else:
                t += "check_str.append(b'{}')\n".format(i)
    t += '''
def check_step(step, traffic):
    if check_str[step] != traffic:
        print('check step {} ...fail'.format(step))
    else:
        print('check step {} ...ok'.format(step))
    '''
    t+= '\n\n'
    fd.write(t)
        

def generate_poc_from_json_data(json_data,poc_file_name,host,port, elf_base=0, libc_base=0, stack_base=0, heap_base=0):
    fd = open(poc_file_name, 'w')
    gen_header(host, port, fd)

    recv_step = []
    step = 0
    
    gen_check_str(json_data, fd)

    for each_str in json_data:
        t = each_str[0]
        if t == '1' or t == '2':
            gen_in( each_str[1:], fd, step)
            step += 1
        elif t == '0':
            gen_out(each_str[1:], fd)
    fd.write('p.interactive()\n')


if __name__ == '__main__':
    pfile = open(sys.argv[1],'rb')
    json_datas = json.load(pfile)
    pfile.close()
    generate_poc_from_json_data(json_datas, 'out.py', '127.0.0.1', 10001)

 