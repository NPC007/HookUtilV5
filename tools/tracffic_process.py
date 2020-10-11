import re
from pwn import *
from elftools.elf.elffile import ELFFile

ERROR_VALUE = 0x94ac411122323232332

def string_escape_decode(byte_array):
    return (byte_array.decode('latin1')         # To bytes, required by 'unicode-escape'
            .encode('unicode-escape') # Perform the actual octal-escaping decode
            .decode('latin1'))         # 1:1 mapping back to bytes

def string_escape_encode(s):
    return (s.encode('latin1')         # To bytes, required by 'unicode-escape'
            .decode('unicode-escape') # Perform the actual octal-escaping decode
            .encode('latin1'))         # 1:1 mapping back to bytes

def get_record_length(buffer):
    res = buffer.split(b':')
    record_type = res[0]
    record_offset = int(res[1])
    record_length = int(res[2])
    record_value_type = res[3]
    return record_length


def get_record_value_type(buffer):
    res = buffer.split(b':')
    record_type = res[0]
    record_offset = int(res[1])
    record_length = int(res[2])
    record_value_type = res[3]
    return record_value_type


def get_record_position(buffer):
    res = buffer.split(b':')
    record_type = res[0]
    record_offset = int(res[1])
    record_length = int(res[2])
    record_value_type = res[3]
    record_position = int(res[4])
    return record_position

def get_record_type(buffer):
    res = buffer.split(b':')
    record_type = res[0]
    record_offset = int(res[1])
    record_length = int(res[2])
    record_value_type = res[3]
    record_position = int(res[4])
    return record_type


def get_record_offset(buffer):
    res = buffer.split(b':')
    record_type = res[0]
    record_offset = int(res[1])
    record_length = int(res[2])
    record_value_type = res[3]
    record_position = int(res[4])
    return record_offset


def get_data_value_by_type(value,value_type,length):
    if value_type == b'DEC':
        return str(value).encode('ascii')
    if value_type == b'HEX':
        return hex(value)[2:].encode('ascii')
    if value_type == b'0XHEX':
        return hex(value).encode('ascii')
    if value_type == b'ORI':
        return p64(value)[:length]


def get_num_value_by_type(value,value_type,length):
    if value_type == b'DEC':
        return int(value)
    if value_type == b'HEX':
        return int(value,16)
    if value_type == b'0XHEX':
        return int(value, 16)
    if value_type == b'ORI':
        if length == 3:
            return u32(value+b'\x00')
        if length == 4:
            return u32(value)
        if length == 5:
            return u32(value+b'\x00'*3)
        if length == 6:
            return u64(value+b'\x00\x00')
        if length == 7:
            return u64(value + b'\x00')
        if length == 8:
            return u64(value)


class SegmentInfo(object):
    """docstring for SegmentInfo"""

    def __init__(self, segment):
        self.start = segment.header['p_vaddr'] - segment.header['p_vaddr'] % 0x1000
        self.end = (segment.header['p_vaddr'] + segment.header['p_memsz']) - (
                segment.header['p_vaddr'] + segment.header['p_memsz']) % 0x1000 + 0x1000

    def dump(self):
        logging.debug(hex(self.start) + '-' * 20 + hex(self.end))


def get_elf_base(elf_path):
    segmentinfo = []
    elf = ELFFile(open(elf_path, 'rb'))
    for index in range(0, elf.num_segments()):
        if elf.get_segment(index).header['p_type'] == 'PT_LOAD':
            segmentinfo.append(SegmentInfo(elf.get_segment(index)))
    elf_base_static = min([seg.start for seg in segmentinfo])
    return elf_base_static


def record_to_value(buffer,libc_base,elf_base,heap_base,stack_base):
    res = buffer.split(b':')
    record_type = res[0]
    record_offset = int(res[1])
    record_length = int(res[2])
    record_value_type = res[3]
    if record_type.find(b'LIBC_BASE') != -1:
        if libc_base==0:
            #return ERROR_VALUE
            value = int(res[5],16)
            logging.warn('[LIBC_BASE]: faild to convert record to value, try to use ori value')
        else:
            value = libc_base + record_offset
        buffer = buffer.replace(buffer,get_data_value_by_type(value,record_value_type,record_length) )

    elif record_type.find(b'ELF_BASE') != -1:
        if elf_base == 0:
            #return ERROR_VALUE
            value = int(res[5],16)
            logging.warn('[ELF_BASE]: faild to convert record to value, try to use ori value')
        else:
            value = elf_base + record_offset
        buffer = buffer.replace(buffer, get_data_value_by_type(value, record_value_type, record_length))

    elif record_type.find(b'STACK_BASE') != -1:
        if stack_base == 0:
            #return ERROR_VALUE
            value = int(res[5],16)
            logging.warn('[STACK_BASE]: faild to convert record to value, try to use ori value')
        else:
            value = stack_base + record_offset
        buffer = buffer.replace(buffer, get_data_value_by_type(value, record_value_type, record_length))

    elif record_type.find(b'HEAP_BASE') != -1:
        if heap_base == 0:
            #return ERROR_VALUE
            value = int(res[5],16)
            logging.warn('[HEAP_BASE]: faild to convert record to value, try to use ori value')
        else:
            value = heap_base + record_offset
        buffer = buffer.replace(buffer, get_data_value_by_type(value, record_value_type, record_length))
    return buffer


def tracffic_main_process(con,json_data, callback = None, elf_base=0, libc_base=0, stack_base=0, heap_base=0):
    total_step = 0
    current_step = 0
    rebuild_json = []
    try:
        SLEEP_TIME = 0.1
        RECEIVE_TIMEOUT = 5
        continue_process_flag = True
        for tracfic_info in json_data:
            type = int(tracfic_info[0])
            if type == 1 or type == 2:
                total_step = total_step + 1
        for tracfic_info in json_data:
            if not continue_process_flag:
                break
            if callback != None:
                continue_process_flag = callback()
            if not continue_process_flag:
                break
            rebuild_json.append(tracfic_info)
            type = int(tracfic_info[0])
            value = string_escape_encode(tracfic_info[1:])
            if type == 0:
                if value.find(b'{{{') == -1:
                    con.write(value)
                    continue
                else:
                    results = re.findall(b'\{\{\{(.+?)\}\}\}', value)
                    for result in results:
                        result_value = record_to_value(result, libc_base, elf_base, heap_base, stack_base)
                        if result_value == ERROR_VALUE:
                            logging.error( 'Error, unable to convert record to Value: ' + string_escape_decode(result))
                            continue_process_flag = False
                            break
                        value = value.replace(b'{{{' + result + b'}}}', result_value)
                    con.write(value)

            elif type == 1 or type == 2:
                current_step = current_step + 1
                if value.find(b'{{{') == -1:
                    sleep(SLEEP_TIME)
                    data = con.recvn(len(value),timeout=RECEIVE_TIMEOUT)
                    if len(data) == 0:
                        data =  con.recv(len(value),timeout=RECEIVE_TIMEOUT)
                    if data != value:
                        logging.error("[STEP][%02d/%02d][without_variable]:Failed, receive not same, we try to continue"%(current_step,total_step))
                    else:
                        logging.info("[STEP][%02d/%02d][without_variable]:Success, check ok"%(current_step,total_step))
                    continue
                else:
                    results = re.findall(b'\{\{\{(.+?)\}\}\}', value)
                    value_copy = value
                    for result in results:
                        value_copy = value_copy.replace(b"{{{"+result+b"}}}", b'A' * get_record_length(result))
                    total_length = len(value_copy)
                    sleep(SLEEP_TIME)
                    data = con.recvn(total_length,timeout=RECEIVE_TIMEOUT)
                    if len(data)!=total_length:
                        logging.error("[STEP][%02d/%02d][with_variable]:Failed, receive not same, we must give up"%(current_step,total_step))
                        continue
                    data_check = data
                    for result in results:
                        process_data = data_check[
                                       get_record_position(result):get_record_position(result) + get_record_length(result)]
                        data_check = data_check.replace(process_data,b'A' * get_record_length(result))
                    if data_check == value_copy:
                        logging.info("[STEP][%02d/%02d][with_variable]:Success, check ok"%(current_step,total_step))
                    else:
                        logging.info("[STEP][%02d/%02d][with_variable]:Failed, check failed, but we can try to continue"%(current_step,total_step))
                    for result in results:
                        process_data = data[
                                       get_record_position(result):get_record_position(result) + get_record_length(result)]
                        record_type = get_record_type(result)
                        if record_type == b'LIBC_BASE':
                            tmp_libc_base = get_num_value_by_type(process_data, get_record_value_type(result),
                                                              get_record_length(result)) - get_record_offset(result)
                            if libc_base!=0 and tmp_libc_base != libc_base:
                                logging.error("[STEP][%02d/%02d]:Get libc_base not same, before: %s, after: %s"%(current_step,total_step,hex(libc_base),hex(tmp_libc_base)))
                            else:
                                libc_base = tmp_libc_base

                            if libc_base%0x1000 == 0:
                                logging.info("[STEP][%02d/%02d]:Get libc_base success: %s"%(current_step,total_step,hex(libc_base)))
                            else:
                                logging.info("[STEP][%02d/%02d]:Get libc_base failed: %s"%(current_step,total_step,hex(libc_base)))
                                continue_process_flag = False

                        elif record_type == b'ELF_BASE':
                            tmp_elf_base = get_num_value_by_type(process_data, get_record_value_type(result),
                                                             get_record_length(result)) - get_record_offset(result)

                            if elf_base!=0 and tmp_elf_base != elf_base:
                                logging.error("[STEP][%02d/%02d]:Get elf_base not same, before: %s, after: %s"%(current_step,total_step,hex(elf_base),hex(tmp_elf_base)))
                            else:
                                elf_base = tmp_elf_base

                            if elf_base%0x1000 == 0:
                                logging.info("[STEP][%02d/%02d]:Get elf_base success: %s"%(current_step,total_step,hex(elf_base)))
                            else:
                                logging.info("[STEP][%02d/%02d]:Get elf_base failed: %s"%(current_step,total_step,hex(elf_base)))
                                continue_process_flag = False

                        elif record_type == b'STACK_BASE':
                            tmp_stack_base = get_num_value_by_type(process_data, get_record_value_type(result),
                                                               get_record_length(result)) - get_record_offset(result)

                            if stack_base!=0 and tmp_stack_base != stack_base:
                                logging.error("[STEP][%02d/%02d]:Get stack_base not same, before: %s, after: %s"%(current_step,total_step,hex(stack_base),hex(tmp_stack_base)))
                            else:
                                stack_base = tmp_stack_base

                            if stack_base%0x1000 == 0:
                                logging.info("[STEP][%02d/%02d]:Get stack_base success: %s"%(current_step,total_step,hex(stack_base)))
                            else:
                                logging.info("[STEP][%02d/%02d]:Get stack_base failed: %s"%(current_step,total_step,hex(stack_base)))
                                continue_process_flag = False

                        elif record_type == b'HEAP_BASE':
                            tmp_heap_base = get_num_value_by_type(process_data, get_record_value_type(result),
                                                              get_record_length(result)) - get_record_offset(result)
                            if heap_base!=0 and tmp_heap_base != heap_base:
                                logging.error("[STEP][%02d/%02d]:Get stack_base not same, before: %s, after: %s"%(current_step,total_step,hex(heap_base),hex(tmp_heap_base)))
                            else:
                                heap_base = tmp_heap_base

                            if heap_base%0x1000 == 0:
                                logging.info("[STEP][%02d/%02d]:Get heap_base success: %s"%(current_step,total_step,hex(heap_base)))
                            else:
                                logging.info("[STEP][%02d/%02d]:Get heap_base failed: %s"%(current_step,total_step,hex(heap_base)))
                                continue_process_flag = False

                        else:
                            logging.info("[STEP][%02d/%02d]:Unknown record type:  %s"%(current_step,total_step))
            sleep(SLEEP_TIME)
    except Exception as e:
        if len(str(e)) == 0:
            logging.error("[STEP][%02d/%02d]: Error happen, we must give up this tracffic:  %s"%(current_step,total_step,e.__class__.__name__))
        else:
            logging.error("[STEP][%02d/%02d]: Error happen, we must give up this tracffic:  %s"%(current_step,total_step,str(e)))
    return rebuild_json
    #con.interactive()