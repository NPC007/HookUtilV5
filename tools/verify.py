import os,re,sys
import logging
os.environ['PWNLIB_NOTERM']='1'
from pwn import *
import pwnlib
import shutil
import json

from tracffic_process import tracffic_main_process,get_elf_base
context.terminal = ['tmux', 'splitw', '-h']

context(log_level='INFO')
#context(log_level='DEBUG')

def usage():
    logging.error("Usage: " + sys.argv[0] +" WORKSPACE ELF_FILE LIBC_PATH")
    exit(-1)




if __name__ == "__main__":
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)
    if len(sys.argv)!= 3 and len(sys.argv)!=4:
        usage()
    workspace = sys.argv[1]
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
    if libc_file != None:
        if os.path.isfile(libc_file) == False:
            logging.error(  "LIC FILE NOT EXIST" + libc_file)
            usage()
    scan_dir = workspace + '/raw/'
    verify_success_dir = workspace + '/local_verify_success/'
    verify_failed_dir = workspace + '/local_verify_failed/'
    if not os.path.exists(scan_dir):
        logging.error("analysis server should start before")
        exit(-1)
    if not os.path.exists(verify_success_dir):
        logging.info('create scan dir: ' + verify_success_dir)
        os.mkdir(verify_success_dir)
    if not os.path.exists(verify_failed_dir):
        logging.info('create scan dir: ' + verify_failed_dir)
        os.mkdir(verify_failed_dir)

    elf_base = get_elf_base(elf_file)
    while True:
        logging.info('[verify]:scan dir: %s......................'%scan_dir)
        for file_name in os.listdir(scan_dir):
            if file_name.find('.')!=-1:
                continue
            continue_process_flag = True

            if libc_file == None:
                logging.debug(  "process: " + elf_file + " libc: None")
                con = process(elf_file,level='ERROR')
            else:
                logging.debug( "process: " + elf_file + " libc: " + libc_file)
                con = process(elf_file,level='ERROR',env={"LD_PRELOAD": libc_file})
            gdb.log.setLevel(logging.ERROR)
            pwnlib.util.misc.log.setLevel(logging.ERROR)
            commands = ['break execve', 'commands 1','!touch '+verify_success_dir+'/'+file_name+'.flag','quit','end',
                        'break system','commands 2','!touch '+verify_success_dir+'/'+file_name+'.flag','quit','end',
                        'catch syscall execve','commands 3','!touch '+verify_success_dir+'/'+file_name+'.flag','quit','end',
                        'catch syscall fork','commands 4','!touch '+verify_success_dir+'/'+file_name+'.flag','quit','end',
                        #'hbreak execve', 'commands 4','!touch '+verify_success_dir+'/'+file_name+'.flag','quit','end',
                        'set follow-fork-mode child',
                        'handle SIGSEGV nostop',
                        'handle SIGFPE nostop',
                        'handle SIGABRT nostop',
                        'handle SIGALRM nostop ignore',
                        'handle SIGHUP nostop',
                        'set disable-randomization on',
                        'info break',
                        '!touch ' + workspace + '/.gdb_start',
                        'continue']
            gdb_pid = gdb.attach(con,'\n'.join(commands))
            while True:
                if os.path.exists(workspace + '/.gdb_start'):
                    os.unlink(workspace + '/.gdb_start')
                    break
                else:
                    sleep(0.1)
            logging.info('process file: ' + file_name)
            pfile = open(os.path.join(scan_dir,file_name),'r')
            json_datas = json.load(pfile)
            pfile.close()
            #logging.debug('gdb_pid: ' + str(gdb_pid) + '   -->  ' + os.path.join(scan_dir,file_name))
            def check_callback():
                if os.path.exists(verify_success_dir+'/'+file_name+'.flag'):
                    return False
                return True
            rebuild_json = tracffic_main_process(con,json_datas,callback= check_callback, elf_base = elf_base)
            #con.interactive()
            sleep(0.5)
            try:
                if len(rebuild_json)!=0:
                    logging.info('[success]:closing connection...............................................')
                else:
                    logging.info('[failed]:closing connection................................................')
                os.system('killall gdb')
                logging.debug('try to kill gdb : ' + 'kill -9 ' + str(gdb_pid))
                con.close()
            except Exception as e:
                logging.error("close connection failed, ignore: %s"%(str(e)))
            if os.path.exists(verify_success_dir+'/'+file_name+'.flag'):
                logging.info('local verify success#############################################################################################################################')
                #exit(-1)
                shutil.move(os.path.join(scan_dir,file_name),os.path.join(verify_success_dir,file_name))
                pfile = open(os.path.join(verify_success_dir,file_name+'.rebuild'),'w')
                json_datas = json.dump(rebuild_json,pfile,indent=4)
                pfile.close()
            else:
                logging.info('local verify failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')

                #exit(-1)
                shutil.move(os.path.join(scan_dir,file_name),os.path.join(verify_failed_dir,file_name))
            #sleep(1)
        sleep(10)
