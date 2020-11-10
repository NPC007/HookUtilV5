#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

char * file_buf;
int file_size;
int send_all(int sock, const void *buf, int len)
{
    const char *pbuf = (const char *) buf;

    while (len > 0)
    {
        int sent = send(sock, pbuf, len, 0);
        if (sent < 1)
        {
            // if the socket is non-blocking, then check
            // the socket error for WSAEWOULDBLOCK/EAGAIN
            // (depending on platform) and if true then
            // use select() to wait for a small period of
            // time to see if the socket becomes writable
            // again before failing the transfer...

            printf("Can't write to socket");
            return -1;
        }

        pbuf += sent;
        len -= sent;
    }
    return 0;
}

void usage(char* program){
    printf("Usage: %s port file_name\n",program);
    exit(0);
}

int should_stop = 0;


void* client_thread(void* pfd){
    int fd = (int)(unsigned long)pfd;
    send_all(fd,file_buf,file_size);
    close(fd);
}


int main(int argc,char* argv[]){
    if(argc !=3){
        usage(argv[0]);
    }
    setvbuf(stdout,NULL,0,0);
    setvbuf(stderr,NULL,0,0);
    char *filename = argv[2];
    struct stat s;
    if (stat(filename, &s) == -1)
    {
        printf("Can't get file info");
        return -1;
    }
    int port  = atoi(argv[1]);
    printf("Start Stage Socket Server at 0.0.0.0:%d, filename: %s, size:%ld\n",port,filename,s.st_size);
    fflush(stdout);
    file_size = s.st_size;
    file_buf = malloc(file_size);
    memset(file_buf,0,file_size);
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        printf("Can't open file for reading");
        return -1;
    }
    int need_read_size = file_size;
    while(need_read_size){
        int ret = fread(file_buf + (file_size - need_read_size), 1, need_read_size, file);
        if (ret < 1)
        {
            printf("Can't read from file");
            break;
        }
        need_read_size -= ret;
    }
    fclose(file);


    int sockfd, connfd;
    struct sockaddr_in servaddr,client_addr;

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (struct sockaddr * restrict)&servaddr, sizeof(servaddr))) != 0) {
        printf("socket bind failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully binded..\n");

    // Now server is ready to listen and verification
    if ((listen(sockfd, 500)) != 0) {
        printf("Listen failed...\n");
        exit(0);
    }
    else
        printf("Server listening..\n");

    int client_addr_size = 0;
    fflush(stdout);
    while(!should_stop){
        connfd = accept(sockfd, (struct sockaddr * restrict)&client_addr, &client_addr_size);
        if (connfd < 0) {
            printf("server acccept failed...\n");
            exit(0);
        }
        else
            printf("server acccept the client: %s:%d\n",inet_ntoa(client_addr.sin_addr),htons(client_addr.sin_port));

        // Function for chatting between client and server
        pthread_t client_tid;
        pthread_create(&client_tid,NULL,client_thread,(void*)(unsigned long)connfd);
        fflush(stdout);
    }

}