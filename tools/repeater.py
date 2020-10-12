import os,re,sys
os.environ['PWNLIB_NOTERM']='1'
from pwn import *
import shutil
import json
from tracffic_process import tracffic_main_process,get_elf_base

context(log_level='INFO')


#from flag_util import teams
#from flag_util import submit_flag


ip_list = ['192.168.12.42']
port = 10002


def usage():
    logging.error ("usage: " +sys.argv[0] + " WORKSPACE ELF_FILE")
    exit(-1)


if __name__ == "__main__":
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)
    if len(sys.argv) != 3:
        usage()
    workspace =  sys.argv[1]
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

    elf_file = sys.argv[2]
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
            if not file_name.endswith(".rebuild"):
                continue
            success_flag = False
            for ip in ip_list:
                try:
                    continue_process_flag = True
                    con = remote(ip,port,level='ERROR')
                    gdb.log.setLevel(logging.ERROR)
                    pwnlib.util.misc.log.setLevel(logging.ERROR)
                    pfile = open(os.path.join(scan_dir,file_name),'r')
                    json_datas = json.load(pfile)
                    pfile.close()
                    tracffic_main_process(con,json_datas, elf_base = elf_base)
                    con.sendline('id')
                    data = con.recv(timeout=2)
                    #logging.debug(data)
                    if data.find(b'id: not found')!=-1:
                        logging.info('remote verify success#############################################################################################################################')
                        success_flag = True
                    else:
                        logging.info('remote verify failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                        success_flag = False
                    con.close()
                except Exception as e:
                    if len(str(e)) == 0:
                        logging.error("Error happen, we must give up this traffic:  %s"%(e.__class__.__name__))
                    else:
                        logging.error("Error happen, we must give up this traffic:  %s"%(str(e)))
                    logging.error(str(e))
                    con.close()

            if success_flag:
                shutil.move(os.path.join(scan_dir,file_name),os.path.join(verify_success_dir,file_name))
                shutil.move(os.path.join(scan_dir,file_name.replace('.rebuild','.flag')),os.path.join(verify_success_dir,file_name.replace('.rebuild','.flag')))
                shutil.move(os.path.join(scan_dir,file_name.replace('.rebuild','')),os.path.join(verify_success_dir,file_name.replace('.rebuild','')))
                #logging.info('remote verify ' + ip + ' succeed: ' + file_name)
            else:
                shutil.move(os.path.join(scan_dir,file_name),os.path.join(verify_failed_dir,file_name))
                shutil.move(os.path.join(scan_dir,file_name.replace('.rebuild','.flag')),os.path.join(verify_success_dir,file_name).replace('.rebuild','.flag'))
                shutil.move(os.path.join(scan_dir,file_name.replace('.rebuild','')),os.path.join(verify_success_dir,file_name.replace('.rebuild','')))
                #logging.info( 'remote verify ' + ip + ' failed: ' + file_name)
        sleep(10)
