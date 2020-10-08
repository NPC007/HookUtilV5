import socket
import time
import threading

nc_address = '192.168.43.105:10001'
teams = ['172.29.9.4', '172.29.8.4', '172.29.18.4', '172.29.19.4', '172.29.5.4', '172.29.4.4', '172.29.24.4', '172.29.7.4', '172.29.3.4', '172.29.6.4', '172.29.25.4', '172.29.1.4', '172.29.17.4', '172.29.23.4', '172.29.14.4', '172.29.22.4', '172.29.15.4', '172.29.10.4', '172.29.11.4', '172.29.21.4', '172.29.20.4', '172.29.16.4', '172.29.12.4', '172.29.13.4']


def flag_heander(ip,flag):
    try:
        if not flag: return
        flag = flag.strip()
        logging.debug( "%s flag:  %s" % (ip, flag))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host, port = nc_address.split(":")
        s.connect((host, int(port)))
        s.send(ip + "@" + flag)
        s.close()
        logging.debug( ip + ' send flag success.')
    except Exception as e:
        logging.debug( 'ip (%s) get flag fail.' % ip, e)

def submit_flag(ip,flag):
    flag_heander(ip,flag)


