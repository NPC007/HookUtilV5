import os,re,sys,time
import logging
import shutil
import json
os.environ["PWNLIB_NOTERM"] = "1"
from pwn import *
context(log_level='INFO')

def usage():
    logging.error("Usage: " + sys.argv[0] +" WORKSPACE ANALYSIS_SERVER_HOST ANALYSIS_SERVER_PORT")
    exit(-1)


if __name__ == "__main__":
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)
    if len(sys.argv)!=4:
        usage()
    workspace = sys.argv[1]
    analysis_server_host = sys.argv[2]
    analysis_server_port = sys.argv[3]
    scan_dir = workspace + '/log_raw/'
    process_dir = workspace + '/log_process/'
    if not os.path.exists(scan_dir):
        logging.error("%scan_dir not exist, analysis server should start before"%scan_dir)
        exit(-1)
    if not os.path.exists(process_dir):
        logging.info('create process dir: ' + process_dir)
        os.mkdir(process_dir)

    while True:
        logging.info('[logger]:scan dir: %s......................' % scan_dir)
        for file_name in os.listdir(scan_dir):
            if not file_name.endswith('.log'):
                continue
            logging.debug("process log file: " + file_name)
            pfile = open(os.path.join(scan_dir,file_name),'rb')
            con = remote(analysis_server_host,int(analysis_server_port),level='ERROR')
            while True:
                buf = pfile.read(4096)
                if len(buf) == 0:
                    break
                con.send(buf)
            con.close()
            pfile.close()
            shutil.move(os.path.join(scan_dir,file_name),os.path.join(process_dir,file_name))
            time.sleep(1)
        time.sleep(5)
