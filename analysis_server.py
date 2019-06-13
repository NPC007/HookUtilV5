# coding:utf-8
import SocketServer
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

    def handle(self):
        global elf_info, libc_info,workspace
        remote_addr,port = self.request.getpeername()
        logging.debug("Accept connection from : " + str(remote_addr) +":"+ str(port))
        self.env_info = EnvInfo(elf_info, libc_info)
        self.data_file_name = re.sub(r'[^0-9]','_',str(datetime.datetime.now()))+"_" + hex(random.randint(0,65535))[2:]
        self.data_file = open(workspace+'/raw/'+self.data_file_name+'.txt','wb')
        logging.info( 'new connection: ' + workspace+'/raw/'+self.data_file_name+'.txt')
        self.json_data = []
        buffer = ""
        last_p = 0
        avaiable =  0
        self.index = 0
        self.data = []
        while 1:
            try:
                if avaiable == 0:
                    tmp_buf = self.request.recv(RecvBufferSize)
                    if len(tmp_buf) == 0:
                        logging.info('recv length is 0, connection closed!')
                        break
                    buffer += tmp_buf
                    avaiable = 1
                else:
                    last_p,avaiable = self.processRequest(buffer)
                    buffer = buffer[last_p:]
            except Exception as e:
                logging.info(e.message)
                break
        logging.info('connect close: ')
        json.dump(self.json_data,self.data_file,encoding='ascii', indent=4)
        self.data_file.flush()
        self.data_file.close()
        os.rename(workspace+'/raw/'+self.data_file_name+'.txt',workspace+'/raw/'+self.data_file_name)
        logging.info('rename : ' + workspace + '/raw/' + self.data_file_name + '.txt' + '  -->  ' + workspace + '/raw/' + self.data_file_name)



    def processRequest(self, buffer):
        # print 'buffer : ' + buffer.encode('hex')
        if len(buffer)<=13:
            return 0,0
        uuid = buffer[:8]
        pkType = u8(buffer[8:9])
        pkLength = u32(buffer[9:13])
        if len(buffer) < 13 + pkLength:
            return 0,0
        data = buffer[13:(13 + pkLength)]
        if pkType == 1:#stdint
            sys.stdout.write(data)
            tracffic_info = TracfficInfo(IN_DATA,data,self.index,self.env_info)
            self.data.append(tracffic_info)
            self.index += 1
            pattern = tracffic_info.generate()
            self.json_data.append(b'0'+pattern.encode('string-escape'))
            #self.data_file.write('\x00'+p32(len(pattern))+pattern)
            #self.data_file.flush()
        elif pkType == 2:#strerr && stdout
            sys.stdout.write(data)
            tracffic_info = TracfficInfo(OUT_DATA, data, self.index, self.env_info)
            self.data.append(tracffic_info)
            self.index += 1
            pattern = tracffic_info.generate()
            self.json_data.append(b'1' + pattern.encode('string-escape'))
            #self.data_file.write('\x01' + p32(len(pattern)) + pattern)
            #self.data_file.flush()
        elif pkType == 3:#strerr && stdout
            sys.stdout.write(data)
            tracffic_info = TracfficInfo(ERR_DATA, data, self.index, self.env_info)
            self.data.append(tracffic_info)
            self.index += 1
            pattern = tracffic_info.generate()
            self.json_data.append('2' + pattern.encode('string-escape'))
            #self.data_file.write('\x02' + p32(len(pattern)) + pattern)
            #self.data_file.flush()
        elif pkType == 4:
            if self.env_info.is_64:
                self.env_info.elf_info.elf_base_dynamic = u64(data)
            else:
                self.env_info.elf_info.elf_base_dynamic = u32(data)
            print 'elf : elf_base_dynamic: ' + hex(self.env_info.elf_info.elf_base_dynamic)
        elif pkType == 5:
            if self.env_info.is_64:
                if u64(data) == 0:
                    self.env_info.libc_info.elf_base_dynamic = 0
                else:
                    self.env_info.libc_info.elf_base_dynamic = u64(data) - self.env_info.libc_info.libc_start_main
            else:
                if u32(data) == 0:
                    self.env_info.libc_info.elf_base_dynamic = 0
                else:
                    self.env_info.libc_info.elf_base_dynamic = u32(data) - self.env_info.libc_info.libc_start_main
            print 'libc : elf_base_dynamic: ' + hex(self.env_info.libc_info.elf_base_dynamic)
        elif pkType == 6:
            if self.env_info.is_64:
                self.env_info.stack_base = u64(data)
                self.env_info.stack_end = u64(data) - 2 * 1024 * 1024
            else:
                self.env_info.stack_base = u32(data)
                self.env_info.stack_end = u32(data) - 2 * 1024 * 1024
            print 'stack: ' + hex(self.env_info.stack_base) + " --> " + hex(self.env_info.stack_end)
        elif pkType == 7:
            if self.env_info.is_64:
                self.env_info.heap_base = u64(data)
                self.env_info.heap_end = u64(data) + 132 * 1024
            else:
                self.env_info.heap_base = u32(data)
                self.env_info.heap_end = u32(data) + 132 * 1024
            print 'heap: ' + hex(self.env_info.heap_base) + " --> " + hex(self.env_info.heap_end)
        return 13+pkLength,1

class SegmentInfo(object):
    """docstring for SegmentInfo"""

    def __init__(self, segment):
        self.start = segment.header['p_vaddr'] - segment.header['p_vaddr'] % 0x1000
        self.end = (segment.header['p_vaddr'] + segment.header['p_memsz']) - (
                segment.header['p_vaddr'] + segment.header['p_memsz']) % 0x1000 + 0x1000

    def dump(self):
        print hex(self.start) + '-' * 20 + hex(self.end)


class ELFInfo(object):
    """docstring for ELFInfo"""

    def __init__(self, path):
        self.path = path
        self.segmentinfo = []
        elf = ELFFile(open(path, 'rb'))
        for index in xrange(elf.num_segments()):
            if elf.get_segment(index).header['p_type'] == 'PT_LOAD':
                self.segmentinfo.append(SegmentInfo(elf.get_segment(index)))
        self.elf_base_static = min([seg.start for seg in self.segmentinfo])
        self.elf_base_dynamic = 0
        self.libc_start_main = ELF(path).sym.get('__libc_start_main', 0)
        self.is_64 = True if elf.header['e_machine'] == 'EM_X86_64' else False

    def dump(self):
        print self.path
        print '__libc_start_main is : ' + hex(self.libc_start_main)
        print 'elf base is 		    : ' + hex(self.elf_base_static)
        print 'elf dynmaic is 	    : ' + hex(self.elf_base_dynamic)
        print 'elf pt_load section  : start'
        for i in self.segmentinfo:
            i.dump()
        print 'elf pt_load section  : end'

    def is_valid(self,addr):
        if self.elf_base_dynamic == 0:
            return False
        if addr < self.elf_base_dynamic :
            return False
        for seg in self.segmentinfo:
            if seg.start + self.elf_base_dynamic <= addr <= seg.end + self.elf_base_dynamic:
                return True
        return False


INVALID_ADDR = 0
ELF_ADDR = 1
LIBC_ADDR = 2
HEAP_ADDR = 3
STACK_ADDR =4

class EnvInfo(object):
    """docstring for EnvInfo"""

    def __init__(self, elf_info, libc_info, elf_base=0, libc_base=0, stack_base=0, heap_base=0):
        self.elf_info = copy.deepcopy(elf_info)
        self.libc_info = copy.deepcopy(libc_info)
        self.is_64 = self.elf_info.is_64

        self.elf_info.elf_base_dynamic = elf_base
        self.libc_info.elf_base_dynamic = libc_base - self.libc_info.libc_start_main

        self.stack_base = stack_base
        self.stack_end = self.stack_base - 2 * 1024 * 1024

        self.heap_base = heap_base
        self.heap_end = self.heap_base + 132 * 1024

    def dump(self):
        print 'Elf  dump : '
        self.elf_info.dump()
        print 'Libc dump : '
        self.libc_info.dump()
        print 'libc_base: ' + hex(self.stack_base) + '-' * 20 + hex(self.stack_end)
        print 'heap_base: ' + hex(self.heap_base) + '-' * 20 + hex(self.heap_end)

    def is_valid(self,addr):
        if self.elf_info.is_valid(addr):
            return ELF_ADDR,self.elf_info.elf_base_dynamic,addr-self.elf_info.elf_base_dynamic

        if self.libc_info.is_valid(addr):
            return LIBC_ADDR,self.libc_info.elf_base_dynamic,addr-self.libc_info.elf_base_dynamic

        if self.stack_end<= addr <= self.stack_base:
            return STACK_ADDR,self.stack_base,addr-self.stack_base

        if self.heap_base <= addr <= self.heap_end:
            return HEAP_ADDR, self.heap_base, addr - self.heap_base

        return INVALID_ADDR,INVALID_ADDR,INVALID_ADDR


class Record(object):

    def __init__(self,type,base,offset,position,length,value,value_type):
        self.type = type
        self.base = base
        self.offset = offset
        self.position = position
        self.length = length
        self.value = value
        self.value_type = value_type

    def dump(self):
        return 'Type: ' + hex(self.type) + ', position: ' + hex(self.position) + ', offset: ' + hex(self.offset) + ', len:' + hex(self.length) +', base:' + hex(self.base)+', value_type: ' + self.value_type


class TracfficInfo(object):
    def __init__(self,type,oriData,index,env_info):
        self.type = type
        self.oriData = oriData
        self.index = index
        self.addr_record = []
        self.env_info = env_info
        self.process_traffic();

    def generate(self):
        res = self.oriData
        for i in range(0,len(self.addr_record)):
            for j in range(0,len(self.addr_record)):
                if self.addr_record[i].position >= self.addr_record[j].position:
                    tmp = self.addr_record[i]
                    self.addr_record[i] = self.addr_record[j]
                    self.addr_record[j] = tmp
        tmp_records = []
        for record in self.addr_record:
            tmp_records.append((self.oriData[record.position:record.position+record.length],record))
        for replace_data,record in tmp_records:
            if record.type == ELF_ADDR:
                type = 'ELF_BASE'
            elif record.type == LIBC_ADDR:
                type = 'LIBC_BASE'
            elif record.type == STACK_ADDR:
                type = 'STACK_BASE'
            elif record.type == HEAP_ADDR:
                type = 'HEAP_BASE'
            res = res.replace(replace_data,"{{{"+type+":"+str(record.offset)+":"+str(record.length)+":"+str(record.value_type)+":"+str(record.position)+":"+hex(record.value)+"}}}" )

        return res


    def process_traffic(self):
        self.find_all_addr()


    def find_all_addr(self):
        buffer = self.oriData
        real_position = 0
        while True:
            position,length,value =  self.process_dec_addr(buffer)
            if length == 0:
                break

            type,base,offset = self.env_info.is_valid(value)
            if type != INVALID_ADDR:
                record = Record(type,base,offset,real_position+position,length,value,'DEC')
                if not self.is_duplicate_record(record):
                    logging.info( 'New_Record: ' + record.dump())
                    self.addr_record.append(record)
                real_position = real_position + position+length
                buffer = buffer[position+length:]
            else:
                real_position = real_position + 1
                buffer = buffer[1:]

        buffer = self.oriData
        real_position = 0
        while True:
            position, length, value = self.process_hex_addr(buffer)
            if length == 0:
                break
            type, base, offset = self.env_info.is_valid(value)
            if type != INVALID_ADDR:
                record = Record(type, base, offset, real_position+position, length, value,'HEX')
                if not self.is_duplicate_record(record):
                    logging.info( 'New_Record: ' + record.dump())
                    self.addr_record.append(record)
                real_position = real_position + position + length
                buffer = buffer[position+length:]
            else:
                real_position = real_position + 1
                buffer = buffer[1:]

        buffer = self.oriData
        real_position = 0
        while True:
            position, length, value = self.process_0x_hex_addr(buffer)
            if length == 0:
                break
            type, base, offset = self.env_info.is_valid(value)
            if type != INVALID_ADDR:
                record = Record(type, base, offset, real_position + position, length, value, '0XHEX')
                if not self.is_duplicate_record(record):
                    logging.info( 'New_Record: ' + record.dump())
                    self.addr_record.append(record)
                real_position = real_position + position + length
                buffer = buffer[position + length:]
            else:
                real_position = real_position + 1
                buffer = buffer[1:]

        if self.env_info.is_64:
            buffer = self.oriData
            real_position = 0
            while True:
                position, length, value = self.process_invisible_addr_8_byte(buffer)
                if length == 0:
                    break
                type, base, offset = self.env_info.is_valid(value)
                if type != INVALID_ADDR:
                    record = Record(type, base, offset, real_position+position, length, value,'ORI')
                    if not self.is_duplicate_record(record):
                        logging.info( 'New_Record: ' + record.dump())
                        self.addr_record.append(record)
                    real_position = real_position + position + length
                    buffer = buffer[position + length:]
                else:
                    real_position = real_position + 1
                    buffer = buffer[1:]

            buffer = self.oriData
            real_position = 0
            while True:
                position, length, value = self.process_invisible_addr_6_byte(buffer)
                if length == 0:
                    break
                type, base, offset = self.env_info.is_valid(value)
                if type != INVALID_ADDR:
                    record = Record(type, base, offset, real_position+position, length, value,'ORI')
                    if not self.is_duplicate_record(record):
                        logging.info( 'New_Record: ' + record.dump())
                        self.addr_record.append(record)
                    buffer = buffer[position + length:]
                    real_position = real_position + position + length
                else:
                    buffer = buffer[1:]
                    real_position = real_position + 1

            buffer = self.oriData
            real_position = 0
            while True:
                position, length, value = self.process_invisible_addr_5_byte(buffer)
                if length == 0:
                    break
                type, base, offset = self.env_info.is_valid(value)
                if type != INVALID_ADDR:
                    record = Record(type, base, offset, real_position+position, length, value,'ORI')
                    if not self.is_duplicate_record(record):
                        logging.info( 'New_Record: ' + record.dump())
                        self.addr_record.append(record)
                    buffer = buffer[position + length:]
                    real_position = real_position + position + length
                else:
                    buffer = buffer[1:]
                    real_position = real_position + 1

            buffer = self.oriData
            real_position = 0
            while True:
                position, length, value = self.process_invisible_addr_4_byte(buffer)
                if length == 0:
                    break
                type, base, offset = self.env_info.is_valid(value)
                if type != INVALID_ADDR:
                    record = Record(type, base, offset, real_position+position, length, value,'ORI')
                    if not self.is_duplicate_record(record):
                        logging.info( 'New_Record: ' + record.dump())
                        self.addr_record.append(record)
                    buffer = buffer[position + length:]
                    real_position = real_position + position + length
                else:
                    buffer = buffer[1:]
                    real_position = real_position + 1

            buffer = self.oriData
            real_position = 0
            while True:
                position, length, value = self.process_invisible_addr_3_byte(buffer)
                if length == 0:
                    break
                type, base, offset = self.env_info.is_valid(value)
                if type != INVALID_ADDR:
                    record = Record(type, base, offset, real_position+position, length, value,'ORI')
                    if not self.is_duplicate_record(record):
                        logging.info( 'New_Record: ' + record.dump())
                        self.addr_record.append(record)
                    buffer = buffer[position + length:]
                    real_position = real_position + position + length
                else:
                    buffer = buffer[1:]
                    real_position = real_position + 1

        else:
            buffer = self.oriData
            real_position = 0
            while True:
                position, length, value = self.process_invisible_addr_4_byte(buffer)
                if length == 0:
                    break
                type, base, offset = self.env_info.is_valid(value)
                if type != INVALID_ADDR:
                    record = Record(type, base, offset, real_position+position, length, value,'ORI')
                    if not self.is_duplicate_record(record):
                        logging.info( 'New_Record: ' + record.dump())
                        self.addr_record.append(record)
                    buffer = buffer[position + length:]
                    real_position = real_position + position + length
                else:
                    buffer = buffer[1:]
                    real_position = real_position + 1

            buffer = self.oriData
            real_position = 0
            while True:
                position, length, value = self.process_invisible_addr_3_byte(buffer)
                if length == 0:
                    break
                type, base, offset = self.env_info.is_valid(value)
                if type != INVALID_ADDR:
                    record = Record(type, base, offset, real_position+position, length, value,'ORI')
                    if not self.is_duplicate_record(record):
                        logging.info( 'New_Record: ' + record.dump())
                        self.addr_record.append(record)
                    buffer = buffer[position + length:]
                    real_position = real_position + position + length
                else:
                    buffer = buffer[1:]
                    real_position = real_position + 1


    def process_dec_addr(self, buffer):
        res = re.findall('([\d]{6,})', buffer)
        if len(res) == 0:
            return 0, 0, 0
        res = res[0]
        return buffer.find(res), len(res), int(res,10)

    def process_0x_hex_addr(self, buffer):
        res = re.findall('(0x[a-f0-9A-F]{5,})', buffer)
        if len(res) != 0:
            res = res[0]
            return buffer.find(res), len(res), int(res,16)
        else:
            res = re.findall('(0X[a-f0-9A-F]{5,})', buffer)
            if len(res) != 0:
                res = res[0]
                return buffer.find(res), len(res), int(res, 16)
        return 0, 0, 0


    def process_hex_addr(self,buffer):
        res = re.findall('([a-f0-9A-F]{5,})', buffer)
        if len(res) == 0:
            return 0, 0, 0
        res = res[0]
        return buffer.find(res), len(res), int(res, 16)

    def process_invisible_addr_8_byte(self, buffer):
        if len(buffer) < 8:
            return 0, 0, 0
        return 0, 8, u64(buffer[0:8])

    def process_invisible_addr_7_byte(self, buffer):
        if len(buffer) < 7:
            return 0, 0, 0
        return 0, 7, u64(buffer[0:7]+'\x00')

    def process_invisible_addr_6_byte(self, buffer):
        if len(buffer)< 6:
            return 0,0,0
        return 0, 6, u64( buffer[0:6]+'\x00\x00')

    def process_invisible_addr_5_byte(self, buffer):
        if len(buffer) < 5:
            return 0, 0, 0
        return 0, 5, u64(buffer[0:5]+'\x00\x00\x00')

    def process_invisible_addr_4_byte(self, buffer):
        if len(buffer) < 4:
            return 0, 0, 0
        return 0, 4, u32(buffer[0:4])

    def process_invisible_addr_3_byte(self, buffer):
        if len(buffer) < 3:
            return 0, 0, 0
        return 0, 3, u32(buffer[0:3]+'\x00')

    def is_duplicate_record(self,new_record):
        for record in self.addr_record:
            if new_record.position == record.position:
                if new_record.value!=record.value:
                    logging.info( "Address May Be Guess Error: ")
                    logging.info( "OLD: ")
                    logging.info( record.dump())
                    logging.info( "NEW,")
                    logging.info( new_record.dump())
                return True
            if new_record.position == record.position + 2 and new_record.value_type == 'HEX' and record.value_type == '0XHEX':
                return True
            if new_record.position == record.position - 2 and new_record.value_type == '0XHEX' and record.value_type == 'HEX':
                return True
        return False


def usage():
    print sys.argv[0] + " SERVER PORT WORKSPACE ELF_PATH LIB_PATH"
    exit(-1)


if __name__ == "__main__":
    if len(sys.argv)!=6:
        usage()
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)
    HOST, PORT = sys.argv[1],int(sys.argv[2])
    workspace = sys.argv[3]
    elf_path = sys.argv[4]
    libc_path = sys.argv[5]
    if not os.path.exists(workspace + '/raw'):
        os.system("mkdir -p " + workspace + '/raw')
    logging.info( 'start auto_tracfic_analysis')
    elf_info = ELFInfo(elf_path)
    libc_info = ELFInfo(libc_path)
    print "Listen   : " + HOST +":" + str(PORT)
    print "Workspace: " + workspace
    print "Elf_Path : " + elf_path
    print "Libc_Path: " + libc_path
    if os.path.isfile(elf_path) == False:
        print "ELF File Not Exist"
        exit(-1)
    if os.path.isfile(libc_path) == False:
        print "Libc File Not Exist"
    try:
        SocketServer.TCPServer.allow_reuse_address = True
        server = ThreadedTCPServer((HOST, PORT), TCPHandler)
        server.serve_forever()
    except Exception as e:
        logging.error(e.message)

def test_analysis_server(argv,time_out,callback):
    if len(argv)!=6:
        usage()
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)
    HOST, PORT = argv[1],int(argv[2])
    workspace = argv[3]
    elf_path = argv[4]
    libc_path = argv[5]
    if not os.path.exists(workspace + '/raw'):
        os.mkdirs(workspace + '/raw')
    logging.info( 'start auto_tracfic_analysis')
    elf_info = ELFInfo(elf_path)
    libc_info = ELFInfo(libc_path)
    try:
        SocketServer.TCPServer.allow_reuse_address = True
        server = ThreadedTCPServer((HOST, PORT), TCPHandler)
        server.timeout = time_out
        server.handle_request()
    except Exception as e:
        logging.error(e.message)