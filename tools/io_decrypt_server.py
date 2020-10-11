# coding:utf-8
import socketserver,socket
import re,sys,logging,os,time


xor_key = b"\xf5\xe4\xd2\xc9\xb2\xa9\xd0\x9f\xa3\xf5\xd9"


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        current_read_index = 0
        current_write_index = 0
        remote_addr,port = self.request.getpeername()
        logging.debug("Accept connection from " + str(remote_addr) +":"+ str(port))
        self.request.setblocking(False)
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            up_stream_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            up_stream_socket.connect((UPSTREAM_HOST,UPSTREAM_PORT))
            up_stream_socket.setblocking(False)
            up_stream_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            logging.debug("Connect to upstream server " + str(UPSTREAM_HOST) +":"+ str(UPSTREAM_PORT) + " success")
        except Exception as e:
            logging.error("Connect to upstream server " + str(UPSTREAM_HOST) +":"+ str(UPSTREAM_PORT) + " failed")
            logging.error(e.message)
            self.request.close()
            return
        while 1:
            try:
                recv_client_data = self.request.recv(4096)
                if len(recv_client_data) != 0:
                    res = b''
                    for i in range(0,len(recv_client_data)):
                        res += ((recv_client_data[i]) ^ (xor_key[current_read_index%len(xor_key)])).to_bytes(1,byteorder='little')
                        current_read_index += 1
                    up_stream_socket.send(res)
                    logging.debug("write "+str(len(res))+" bytes to upstream server")
                else:
                    break
            except BlockingIOError as e:
                #print e.message
                time.sleep(0.05)
            try:
                recv_server_data = up_stream_socket.recv(4096)
                if len(recv_server_data) != 0:
                    res = b''
                    for i in range(0,len(recv_server_data)):
                        res += ((recv_server_data[i])^(xor_key[current_write_index%len(xor_key)])).to_bytes(1,byteorder='little')
                        current_write_index += 1
                    self.request.send(res)
                    logging.debug("write "+str(len(res))+" bytes to client")
                else:
                    break
            except BlockingIOError as e:
                #print e.message
                time.sleep(0.05)
        logging.debug("close socket from " + remote_addr +":" +str(port))
        up_stream_socket.close()
        self.request.close()


def usage():
    logging.error(sys.argv[0] + " IO_DECRYPT_LISTEN_HOST IO_DECRYPT_LISTEN_PORT IO_DECRYPT_UPSTREAM_HOST IO_DECRYPT_UPSTREAM_PORT")
    exit(-1)


if __name__ == "__main__":
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)
    if len(sys.argv) != 5:
        usage()
    HOST, PORT = sys.argv[1], int(sys.argv[2])
    UPSTREAM_HOST,UPSTREAM_PORT = sys.argv[3], int(sys.argv[4])
    try:
        socketserver.TCPServer.allow_reuse_address = True
        server = ThreadedTCPServer((HOST, PORT), TCPHandler)
        logging.debug("Start decrypt server :" +HOST + ":" + str(PORT) )
        logging.debug("Upstream      server :" +UPSTREAM_HOST + ":" + str(UPSTREAM_PORT) )
        server.serve_forever()
    except Exception as e:
        logging.error(e.message)