import os,re,sys
os.environ['PWNLIB_NOTERM']='1'
from pwn import *
import shutil
import json
from tracffic_process import tracffic_main_process,get_elf_base

context(log_level='DEBUG')


#from flag_util import teams
#from flag_util import submit_flag


ip_list = ['127.0.0.1']
port = 20002


def usage():
    for i in range(0,len(sys.argv)):
        logging.error( "sys.argv["+str(i)+"]: " + sys.argv[i])
    logging.error ("usage: 1. " +sys.argv[0] + " one_file file_name ")
    exit(-1)


if __name__ == "__main__":
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)
    if len(sys.argv) < 3:
        usage()
    workspace =  sys.argv[2]
    scan_dir = workspace + '/local_verify_success/'
    verify_success_dir = workspace + '/remote_verify_success/'
    verify_failed_dir = workspace + '/remote_verify_failed/'
    if not os.path.exists(scan_dir):
        logging.info ("local workspace must start analysis server first")
        usage()
    if not os.path.exists(verify_success_dir):
        logging.info( 'create remote verify success dir: ' + scan_dir)
        os.mkdir(verify_success_dir)
    if not os.path.exists(verify_failed_dir):
        logging.info( 'create remote verify failed dir: ' + scan_dir)
        os.mkdir(verify_failed_dir)

    elf_file = sys.argv[3]
    if elf_file.find("/") == -1:
        elf_file = "./"+ elf_file
    if len(sys.argv) == 3:
        libc_file = None
    else:
        libc_file = sys.argv[3]
        if libc_file.find("/") == -1:
            libc_file = "./"+libc_file
    if os.path.isfile(elf_file) == False:
        logging.error(  "ELF FILE NOT EXIST: " + elf_file)
        usage()
    elf_base = get_elf_base(elf_file)
    while True:
        logging.debug( 'scan dir......................')
        for file_name in os.listdir(scan_dir):
            success_flag = False
            if file_name.find('.') != -1:
                continue
            for ip in ip_list:
                try:
                    continue_process_flag = True
                    con = remote(ip,port)
                    pfile = open(os.path.join(scan_dir,file_name),'r')
                    json_datas = json.load(pfile)
                    pfile.close()
                    tracffic_main_process(con,json_datas, elf_base = elf_base)
                    con.sendline('id')
                    data = con.recv(timeout=2)
                    logging.debug(data)
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
