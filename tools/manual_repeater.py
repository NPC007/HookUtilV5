import os,re,sys
os.environ['PWNLIB_NOTERM']='1'
from pwn import *
import shutil
import json
from tracffic_process import tracffic_main_process,get_elf_base

context(log_level='INFO')

#from flag_util import teams
#from flag_util import submit_flag

ip_list = ['127.0.0.1']
port = 13002


def usage():
    logging.error ("usage: " +sys.argv[0] + " TRACFFIC_FILE ELF_FILE")
    exit(-1)


if __name__ == "__main__":
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)
    if len(sys.argv) != 3:
        usage()
    tracffic_file = sys.argv[1]
    elf_file = sys.argv[2]
    if elf_file.find("/") == -1:
        elf_file = "./"+ elf_file
    if len(sys.argv) == 3:
        libc_file = None
    else:
        libc_file = sys.argv[3]
        if libc_file.find("/") == -1:
            libc_file = "./"+libc_file
    if not os.path.isfile(elf_file):
        logging.error( "ELF FILE NOT EXIST: " + elf_file)
        usage()
    elf_base = get_elf_base(elf_file)
    total_verify_file_count = 0
    success_verify_file_cout = 0

    while True:
        for ip in ip_list:
            try:
                continue_process_flag = True
                con = remote(ip, port, level='ERROR')
                gdb.log.setLevel(logging.ERROR)
                pwnlib.util.misc.log.setLevel(logging.ERROR)
                pfile = open(tracffic_file, 'r')
                json_datas = json.load(pfile)
                pfile.close()
                tracffic_main_process(con, json_datas, elf_base=elf_base)
                con.recv(timeout=2)
                con.sendline('id')
                data = con.recv(timeout=2)
                # logging.debug(data)
                if data.find(b'id: not found') != -1:
                    logging.info(
                        'remote verify success#############################################################################################################################')
                    success_flag = True
                else:
                    logging.info(
                        'remote verify failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                    success_flag = False
                con.close()
            except Exception as e:
                if len(str(e)) == 0:
                    logging.error("Error happen, we must give up this traffic:  %s" % (e.__class__.__name__))
                else:
                    logging.error("Error happen, we must give up this traffic:  %s" % (str(e)))
                logging.error(str(e))
                logging.info(
                    'remote verify failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                con.close()

    sleep(10)
