import os,re,sys
os.environ['PWNLIB_NOTERM']='1'
from pwn import *
import shutil
import json
context.terminal = ['tmux', 'splitw', '-h']

ERROR_VALUE = 0x94ac411122323232332
context(log_level='DEBUG')
SLEEP_TIME = 0.1

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
        if length == 4:
            return u32(value)
        if length == 6:
            return u64(value+'\x00\x00')
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



if __name__ == "__main__":
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)
    workspace = '/tmp/babyheap/'
    scan_dir = workspace + 'raw/'
    verify_success_dir = workspace + 'local_verify_success/'
    verify_failed_dir = workspace + 'local_verify_failed/'
    if not os.path.exists(scan_dir):
        logging.info('create scan dir: ' + scan_dir)
        os.mkdir(scan_dir)
    if not os.path.exists(verify_success_dir):
        logging.info('create scan dir: ' + verify_success_dir)
        os.mkdir(verify_success_dir)
    if not os.path.exists(verify_failed_dir):
        logging.info('create scan dir: ' + verify_failed_dir)
        os.mkdir(verify_failed_dir)

    while True:
        logging.debug('scan dir......................')
        for file_name in os.listdir(scan_dir):
            if file_name.find('.')!=-1:
                continue
            continue_process_flag = True
            libc_base = 0
            heap_base = 0
            elf_base = 0
            stack_base = 0
            #con = process(['/opt/HookUtilV2/input_elf'],env={"LD_PRELOAD": "/opt/ctf/2017/0ctf/babyheap/libc.so.6"})
            con = process('/home/runshine/HookUtilV3/babyheap',env={"LD_PRELOAD":"/home/runshine/HookUtilV3/analysis_repeater_test/write-ups-2017/0ctf-quals-2017/pwn/Baby-Heap-2017-255/libc.so"})
            # commands = ['break execve', 'commands 1','!touch '+verify_success_dir+'/'+file_name+'.flag','quit','end',
            #             'break system','commands 2','!touch '+verify_success_dir+'/'+file_name+'.flag','quit','end',
            #             'catch syscall execve','commands 3','!touch '+verify_success_dir+'/'+file_name+'.flag','quit','end',
            #             'set follow-fork-mode child',
            #             'handle SIGSEGV nostop',
            #             'handle SIGFPE nostop',
            #             'handle SIGABRT nostop',
            #             'handle SIGHUP nostop',
            #             'set disable-randomization on',
            #             'continue']
            #gdb_pid = gdb.attach(con,'\n'.join(commands))
            sleep(0.5)
            pfile = open(os.path.join(scan_dir,file_name),'r')
            json_datas = json.load(pfile)
            pfile.close()
            logging.debug('process file: ' + file_name)
            logging.debug('process pid : ' + str(con.pid))
            #logging.debug('gdb_pid: ' + str(gdb_pid) + '   -->  ' + os.path.join(scan_dir,file_name))
            try:
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
                                    logging.error('Error, unable to convert record to Value: ' + result)
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
                    time.sleep(0.05)
            except Exception as e:
                print e.message
                exit(-1)
            con.close()
            sleep(2)
            if os.path.exists(verify_success_dir+'/'+file_name+'.flag'):
                logging.info('local verify success')
                shutil.move(os.path.join(scan_dir,file_name),os.path.join(verify_success_dir,file_name))
            else:
                logging.info('local verify failed')
                os.system('killall gdb')
                logging.debug('try to kill gdb : ' + 'kill -9 ' + str(gdb_pid))
                shutil.move(os.path.join(scan_dir,file_name),os.path.join(verify_failed_dir,file_name))
        sleep(10)
