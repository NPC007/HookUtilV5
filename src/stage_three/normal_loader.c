#include "common.h"
#include "config.h"
#include "debug_config.h"



IN_LINE void print_banner(){
    SHELL_LOG("........[DEBUG_SHELL]....");
    SHELL_LOG("Version: %s %s",__DATE__,__TIME__);
    SHELL_LOG("1.       test syscall");
    SHELL_LOG("98.      enter system shell");
    SHELL_LOG("99.      exit debug_shell");
}



IN_LINE void test_syscall(int save_stdin,int save_stdout,int save_stderr){
    for(int i=0;i<200;i++){
        _test_syscall(i);
    }
}

IN_LINE void debug_shell(int save_stdin,int save_stdout,int save_stderr){
    //my_alarm(0x1000);
    char buf[16];
    long index;
    char *argv[] = {"/bin/sh", NULL};
    g_loader_param.enable_debug = 1;
    while(1) {
        print_banner();
        my_memset(buf,0,sizeof(buf));
        my_read(save_stdin,buf,sizeof(buf));
        index = my_strtol(buf,NULL,10);
        switch(index){
            case 1:
                test_syscall(save_stdin,save_stdout,save_stderr);
                break;
            case 98:
                my_execve("/bin/sh", (char**)argv, NULL);
                break;
            case 99:
                return;
        }
    }
}

IN_LINE void filter_black_words_in_noblock(char* buf,int buf_len,int save_stdin,int save_stdout,int save_stderr){
    //DEBUG_LOG("call filter_black_words_in: %s, len: %d",buf,buf_len);
    if(my_strstr(buf,"__debug_shell__")!=NULL){
        //my_alarm(1000);
        if(save_stdin!=-1 && save_stdout!= -1 && save_stderr!=-1){
            int flag = my_fcntl(save_stdin,F_GETFL,0);
            SHELL_LOG("set stdin with out NONBLOCK");
            my_fcntl(save_stdin,F_SETFL,flag^O_NONBLOCK);
            flag = my_fcntl(save_stdout,F_GETFL,0);
            my_fcntl(save_stdout,F_SETFL,flag^O_NONBLOCK);
            flag = my_fcntl(save_stderr,F_GETFL,0);
            my_fcntl(save_stderr,F_SETFL,flag^O_NONBLOCK);
            my_close(STDERR_FILENO);
            my_close(STDOUT_FILENO);
            my_close(STDIN_FILENO);
            int ret = 0;
            ret = my_copyfd(save_stdin,STDIN_FILENO);
            if(ret < 0)return;
            ret = my_copyfd(save_stdout,STDOUT_FILENO);
            if(ret < 0)return;
            ret = my_copyfd(save_stderr,STDERR_FILENO);
            if(ret < 0)return;
            debug_shell(save_stdin,save_stdout,save_stderr);
        }
        else{
            debug_shell(0,1,2);
        }
        my_exit(0);
    }
}


IN_LINE void filter_black_words_in(char* buf,int buf_len,int save_stdin,int save_stdout,int save_stderr){
    //DEBUG_LOG("call filter_black_words_in: %s, len: %d",buf,buf_len);
    int ret = 0;
    if(my_strstr(buf,"__debug_shell__")!=NULL){
        //my_alarm(1000);
        if(save_stdin!=-1 && save_stdout!= -1 && save_stderr!=-1){
            SHELL_LOG("set stdin with out NONBLOCK");
            my_close(STDERR_FILENO);
            my_close(STDOUT_FILENO);
            my_close(STDIN_FILENO);
            ret = my_copyfd(save_stdin,STDIN_FILENO);
            if(ret < 0)return;
            ret = my_copyfd(save_stdout,STDOUT_FILENO);
            if(ret < 0)return;
            ret = my_copyfd(save_stderr,STDERR_FILENO);
            if(ret < 0)return;
            debug_shell(save_stdin,save_stdout,save_stderr);
        }
        else{
            debug_shell(0,1,2);
        }
        my_exit(0);
    }
}
IN_LINE void filter_black_words_out(char* buf,int buf_len,int save_stdin,int save_stdout,int save_stderr){

}



IN_LINE void start_shell_io_inline(char* buf,int buf_len){
    char *argv[] = {"/bin/sh", NULL};
    MD5_CTX md5;
    my_memset((char*)&md5,0,sizeof(MD5_CTX));
    unsigned char decrypt[16];
    if(buf_len == sizeof(SHELL_PASSWD)){
        MD5Init(&md5);
        MD5Update(&md5,buf,sizeof(SHELL_PASSWD)-1);
        MD5Final(&md5,decrypt);
        if(my_strcmp(decrypt,g_loader_param.shell_password) == 0){
            my_execve("/bin/sh", (char**)argv, NULL);
        }
    }
}


IN_LINE void start_shell(char* buf,int buf_len,int child_pid,int save_stdin,int save_stdout,int save_stderr){
    char *argv[] = {"/bin/sh", NULL};
    MD5_CTX md5;
    my_memset((char*)&md5,0,sizeof(MD5_CTX));
    unsigned char decrypt[16];
    if(buf_len == sizeof(SHELL_PASSWD)){
        MD5Init(&md5);
        MD5Update(&md5,buf,sizeof(SHELL_PASSWD)-1);
        MD5Final(&md5,decrypt);
        if(my_strcmp(decrypt,g_loader_param.shell_password) == 0){
            my_kill(child_pid,9);
            my_close(STDIN_FILENO);
            my_close(STDOUT_FILENO);
            my_close(STDERR_FILENO);
            int ret = 0;
            ret = my_copyfd(save_stdin,STDIN_FILENO);
            if(ret < 0)return;
            ret = my_copyfd(save_stdout,STDOUT_FILENO);
            if(ret < 0)return;
            ret = my_copyfd(save_stderr,STDERR_FILENO);
            if(ret < 0)return;
            pid_t pid = 0;
            if(pid == 0) {
                my_execve("/bin/sh", (char**)argv, NULL);
            }
        }
    }
}

IN_LINE int MAX_FD(int file1,int file2,int file3){
    int tmp = file1;
    if(file1>file2)
        tmp = file1;
    else tmp = file2;
    if(tmp<file3)
        tmp = file3;
    return tmp;
}

static char UUID[0x08];




IN_LINE void start_io_redirect_udp(int send_sockfd,struct sockaddr_in serveraddr,char* libc_start_main_addr,char* stack_on_entry){
    int fd_hook_stdin[2];
    int fd_hook_stdout[2];
    int fd_hook_stderr[2];
    int save_stdin = 240;
    int save_stdout = 241;
    int save_stderr = 242;

    int ret = 0;
    ret = my_copyfd(STDIN_FILENO,save_stdin);
    if(ret < 0)return;
    ret = my_copyfd(STDOUT_FILENO,save_stdout);
    if(ret < 0)return;
    ret = my_copyfd(STDERR_FILENO,save_stderr);
    if(ret < 0)return;

    my_pipe(fd_hook_stdin);
    my_pipe(fd_hook_stdout);
    my_pipe(fd_hook_stderr);

    my_close(STDIN_FILENO);
    my_close(STDOUT_FILENO);
    my_close(STDERR_FILENO);

    ret = my_copyfd(fd_hook_stdin[0],STDIN_FILENO);
    if(ret < 0)return;
    ret = my_copyfd(fd_hook_stdout[1],STDOUT_FILENO);
    if(ret < 0)return;
    ret = my_copyfd(fd_hook_stderr[1],STDERR_FILENO);
    if(ret < 0)return;

    pid_t child_pid = my_fork();
    char buf[131072];
    char packet[131082];
    int packet_len;
    my_memset(buf,0,sizeof(buf));

    if(child_pid==0){
        //child process
    }
    else if(child_pid<=0){

    }
    else{
        destory_patch_data();
        int flag = my_fcntl(save_stdin,F_GETFL,0);
        my_fcntl(save_stdin,F_SETFL,flag|O_NONBLOCK);
        flag = my_fcntl(fd_hook_stdout[0],F_GETFL,0);
        my_fcntl(fd_hook_stdout[0],F_SETFL,flag|O_NONBLOCK);
        flag = my_fcntl(fd_hook_stderr[0],F_GETFL,0);
        my_fcntl(fd_hook_stderr[0],F_SETFL,flag|O_NONBLOCK);

        int read_length = 0;
        int child_stat;
        while(1){
            // use fd_hook_stdin[1] to write
            // use fd_hook_stdout[0] to read
            // use fd_hook_stderr[0] to read
            //my_memzero(buf,8192);

            char* elf_base = (char*)get_elf_base();
            char* heap_base = (char*)get_heap_base();
            char* stack_base = (char*)stack_on_entry;
            build_packet(BASE_ELF,(char*)&elf_base,sizeof(char*),packet,&packet_len);
            my_sendto(send_sockfd,packet,packet_len,0,&serveraddr,sizeof(serveraddr));
            build_packet(BASE_LIBC,(char*)&libc_start_main_addr,sizeof(char*),packet,&packet_len);
            my_sendto(send_sockfd,packet,packet_len,0,&serveraddr,sizeof(serveraddr));
            build_packet(BASE_STACK,(char*)&stack_base,sizeof(char*),packet,&packet_len);
            my_sendto(send_sockfd,packet,packet_len,0,&serveraddr,sizeof(serveraddr));
            build_packet(BASE_HEAP,(char*)&heap_base,sizeof(char*),packet,&packet_len);
            my_sendto(send_sockfd,packet,packet_len,0,&serveraddr,sizeof(serveraddr));

            DEBUG_LOG("elf_base:         0x%lx",elf_base);
            DEBUG_LOG("libc_start_main:  0x%lx",libc_start_main_addr);
            DEBUG_LOG("stack_base:       0x%lx",stack_base);
            DEBUG_LOG("heap_base:        0x%lx",heap_base);

            read_length = my_read(fd_hook_stdout[0],buf,sizeof(buf));
            if(read_length>0){
                build_packet(DATA_OUT, buf, read_length, packet, &packet_len);
                my_sendto(send_sockfd,packet,packet_len,0,&serveraddr,sizeof(serveraddr));
                filter_black_words_out(buf,read_length,save_stdin,save_stdout,save_stderr);
                my_write(save_stdout,buf,read_length);
            }else if(read_length == -1) {
                int error_code = get_errno();
                if (error_code != EAGAIN)
                    break;
            }else if(read_length == 0)
                break;

            read_length = my_read(fd_hook_stderr[0],buf,sizeof(buf));
            if(read_length>0){
                build_packet(DATA_ERR, buf, read_length, packet, &packet_len);
                my_sendto(send_sockfd,packet,packet_len,0,&serveraddr,sizeof(serveraddr));
                filter_black_words_out(buf,read_length,save_stdin,save_stdout,save_stderr);
                my_write(save_stderr,buf,read_length);
            }else if(read_length == -1){
                int error_code = get_errno();
                if(error_code != EAGAIN)
                    break;
            }else if(read_length == 0)
                break;

            read_length = my_read(save_stdin,buf,sizeof(buf));
            if(read_length>0){
                build_packet(DATA_IN, buf, read_length, packet, &packet_len);
                my_sendto(send_sockfd,packet,packet_len,0,&serveraddr,sizeof(serveraddr));
                start_shell(buf,read_length,child_pid,save_stdin,save_stdout,save_stderr);
                filter_black_words_in(buf,read_length,save_stdin,save_stdout,save_stderr);
                my_write(fd_hook_stdin[1],buf,read_length);
            }else if(read_length == -1){
                int error_code = get_errno();
                if(error_code != EAGAIN)
                    break;
            }else if(read_length == 0)
                break;

            if(my_waitpid(child_pid,0,WNOHANG)!=0){

                break;
            }
            my_sleep(10);
        }
    }
    if(child_pid>0) {
        my_kill(child_pid, 9);
        my_close(send_sockfd);
        my_exit(0);
    }

}

IN_LINE void start_io_redirect_tcp_with_select(int send_sockfd, char* libc_start_main_addr,char* stack_on_entry){
    int fd_hook_stdin[2];
    int fd_hook_stdout[2];
    int fd_hook_stderr[2];
    int save_stdin = 240;
    int save_stdout = 241;
    int save_stderr = 242;
    int ret = 0;
    ret = my_copyfd(STDIN_FILENO,save_stdin);
    if(ret < 0)return;
    ret = my_copyfd(STDOUT_FILENO,save_stdout);
    if(ret < 0)return;
    ret = my_copyfd(STDERR_FILENO,save_stderr);
    if(ret < 0)return;

    my_pipe(fd_hook_stdin);
    my_pipe(fd_hook_stdout);
    my_pipe(fd_hook_stderr);

    my_close(STDIN_FILENO);
    my_close(STDOUT_FILENO);
    my_close(STDERR_FILENO);

    ret = my_copyfd(fd_hook_stdin[0],STDIN_FILENO);
    ret = my_copyfd(fd_hook_stdout[1],STDOUT_FILENO);
    ret = my_copyfd(fd_hook_stderr[1],STDERR_FILENO);
    char* heap_base = (char*)get_heap_base();
    pid_t child_pid = my_fork();
    char buf[131072];
    char packet[131082];
    int packet_len;
    my_memset(buf,0,sizeof(buf));
    if(child_pid==0){
        //child process
    }
    else if(child_pid<=0){

    }
    else{
        int need_try_again = 1;
        struct sigaction ignore;
        ignore.sa_handler = SIG_IGN;
        //todo FIX rg_sigaction
        //my_rt_sigaction(SIGPIPE,&ignore,NULL);
        destory_patch_data();
        my_memcpy(UUID,(void*)&fd_hook_stderr,8);


//        int flag = my_fcntl(save_stdin,F_GETFL,0);
//        my_fcntl(save_stdin,F_SETFL,flag|O_NONBLOCK);
//        flag = my_fcntl(fd_hook_stdout[0],F_GETFL,0);
//        my_fcntl(fd_hook_stdout[0],F_SETFL,flag|O_NONBLOCK);
//        flag = my_fcntl(fd_hook_stderr[0],F_GETFL,0);
//        my_fcntl(fd_hook_stderr[0],F_SETFL,flag|O_NONBLOCK);


        int read_length = 0;

        int child_stat;
        char* elf_base = (char*)get_elf_base();
        char* stack_base = (char*)stack_on_entry;
        build_packet(BASE_ELF,(char*)&elf_base,sizeof(char*),packet,&packet_len);
        my_write_packet(send_sockfd,packet,packet_len);
        build_packet(BASE_LIBC,(char*)&libc_start_main_addr,sizeof(char*),packet,&packet_len);
        my_write_packet(send_sockfd,packet,packet_len);
        build_packet(BASE_STACK,(char*)&stack_base,sizeof(char*),packet,&packet_len);
        my_write_packet(send_sockfd,packet,packet_len);
        build_packet(BASE_HEAP,(char*)&heap_base,sizeof(char*),packet,&packet_len);
        my_write_packet(send_sockfd,packet,packet_len);
        DEBUG_LOG("elf_base:         0x%lx",elf_base);
        DEBUG_LOG("libc_start_main:  0x%lx",libc_start_main_addr);
        DEBUG_LOG("stack_base:       0x%lx",stack_base);
        DEBUG_LOG("heap_base:        0x%lx",heap_base);

        fd_set read_events;
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        int rc = 0;
        int max_fd = 0;
        if(fd_hook_stdout[0] > fd_hook_stderr[0])
            max_fd = fd_hook_stdout[0];
        else
            max_fd = fd_hook_stderr[0];
        if (max_fd < save_stdin)
            max_fd = save_stdin;
        while(1){
            FD_ZERO(&read_events);
            FD_SET(fd_hook_stdout[0], &read_events);
            FD_SET(fd_hook_stderr[0], &read_events);
            FD_SET(save_stdin, &read_events);

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            rc = my_select(max_fd + 1, &read_events, NULL, NULL, &timeout);
            if (rc < 0) {
                break;
            } else if (rc == 0) {
                if(my_waitpid(child_pid,0,WNOHANG)!=0){
                    break;
                }
                continue;
            }
            if (FD_ISSET(fd_hook_stdout[0], &read_events)){
                read_length = my_read(fd_hook_stdout[0], buf, sizeof(buf));
                if (read_length > 0) {
                    build_packet(DATA_OUT, buf, read_length, packet, &packet_len);
                    my_write_packet(send_sockfd, packet, packet_len);
                    filter_black_words_out(buf, read_length,save_stdin,save_stdout,save_stderr);
                    my_write(save_stdout, buf, read_length);
                }
                else if(read_length == -1){
                    int error_code = get_errno();
                    if(error_code != EAGAIN)
                        break;
                }else if(read_length == 0){
                    if(need_try_again){
                        my_sleep(2000);
                        need_try_again = 0;
                        continue;
                    }else{
                        break;
                    }
                }
            }
            if (FD_ISSET(fd_hook_stderr[0], &read_events)){
                read_length = my_read(fd_hook_stderr[0], buf, sizeof(buf));
                if (read_length > 0) {
                    build_packet(DATA_ERR, buf, read_length, packet, &packet_len);
                    my_write_packet(send_sockfd, packet, packet_len);

                    filter_black_words_out(buf, read_length,save_stdin,save_stdout,save_stderr);
                    my_write(save_stderr, buf, read_length);
                }
                else if(read_length == -1){
                    int error_code = get_errno();
                    if(error_code != EAGAIN)
                        break;
                }else if(read_length == 0)
                {
                    if(need_try_again){
                        my_sleep(2000);
                        need_try_again = 0;
                        continue;
                    }else{
                        break;
                    }
                }
            }
            if (FD_ISSET(save_stdin, &read_events)){
                read_length = my_read(save_stdin, buf, sizeof(buf));
                if (read_length > 0) {
                    build_packet(DATA_IN, buf, read_length, packet, &packet_len);
                    my_write_packet(send_sockfd, packet, packet_len);
                    start_shell(buf, read_length, child_pid, save_stdin, save_stdout, save_stderr);
                    filter_black_words_in(buf, read_length,save_stdin,save_stdout,save_stderr);
                    my_write(fd_hook_stdin[1], buf, read_length);
                }
                else if(read_length == -1){
                    int error_code = get_errno();
                    if(error_code != EAGAIN)
                        break;
                }
                else if(read_length == 0) {
                    if(need_try_again){
                        my_sleep(2000);
                        need_try_again = 0;
                        continue;
                    }else{
                        break;
                    }
                }
            }
        }
    }
    if(child_pid>0) {
        my_kill(child_pid, 9);
        my_close(send_sockfd);
        my_exit(0);
    }
}


IN_LINE void start_io_redirect_tcp(int send_sockfd, char* libc_start_main_addr,char* stack_on_entry){
    int fd_hook_stdin[2];
    int fd_hook_stdout[2];
    int fd_hook_stderr[2];
    int save_stdin = 240;
    int save_stdout = 241;
    int save_stderr = 242;
    int ret = 0;
    ret = my_copyfd(STDIN_FILENO,save_stdin);
    if(ret < 0)return;
    ret = my_copyfd(STDOUT_FILENO,save_stdout);
    if(ret < 0)return;
    ret = my_copyfd(STDERR_FILENO,save_stderr);
    if(ret < 0)return;

    my_pipe(fd_hook_stdin);
    my_pipe(fd_hook_stdout);
    my_pipe(fd_hook_stderr);

    my_close(STDIN_FILENO);
    my_close(STDOUT_FILENO);
    my_close(STDERR_FILENO);

    ret = my_copyfd(fd_hook_stdin[0],STDIN_FILENO);
    if(ret < 0)return;
    ret = my_copyfd(fd_hook_stdout[1],STDOUT_FILENO);
    if(ret < 0)return;
    ret = my_copyfd(fd_hook_stderr[1],STDERR_FILENO);
    if(ret < 0)return;
    char* heap_base = (char*)get_heap_base();
    pid_t child_pid = my_fork();
    char buf[131072];
    char packet[131082];
    int packet_len;
    my_memset(buf,0,sizeof(buf));
    if(child_pid==0){
        //child process
    }
    else if(child_pid<=0){

    }
    else{
        struct sigaction ignore;
        ignore.sa_handler = SIG_IGN;
        //todo FIX rg_sigaction
        //my_rt_sigaction(SIGPIPE,&ignore,NULL);
        destory_patch_data();
        my_memcpy(UUID,(void*)&fd_hook_stderr,8);
        int flag = my_fcntl(save_stdin,F_GETFL,0);
        my_fcntl(save_stdin,F_SETFL,flag|O_NONBLOCK);
        flag = my_fcntl(fd_hook_stdout[0],F_GETFL,0);
        my_fcntl(fd_hook_stdout[0],F_SETFL,flag|O_NONBLOCK);
        flag = my_fcntl(fd_hook_stderr[0],F_GETFL,0);
        my_fcntl(fd_hook_stderr[0],F_SETFL,flag|O_NONBLOCK);


        int read_length = 0;

        int child_stat;
        char* elf_base = (char*)get_elf_base();
        char* stack_base = (char*)stack_on_entry;
        build_packet(BASE_ELF,(char*)&elf_base,sizeof(char*),packet,&packet_len);
        my_write_packet(send_sockfd,packet,packet_len);
        build_packet(BASE_LIBC,(char*)&libc_start_main_addr,sizeof(char*),packet,&packet_len);
        my_write_packet(send_sockfd,packet,packet_len);
        build_packet(BASE_STACK,(char*)&stack_base,sizeof(char*),packet,&packet_len);
        my_write_packet(send_sockfd,packet,packet_len);
        build_packet(BASE_HEAP,(char*)&heap_base,sizeof(char*),packet,&packet_len);
        my_write_packet(send_sockfd,packet,packet_len);
        DEBUG_LOG("elf_base:         0x%lx",elf_base);
        DEBUG_LOG("libc_start_main:  0x%lx",libc_start_main_addr);
        DEBUG_LOG("stack_base:       0x%lx",stack_base);
        DEBUG_LOG("heap_base:        0x%lx",heap_base);

        while(1){
            {
                read_length = my_read(fd_hook_stdout[0], buf, sizeof(buf));
                if (read_length > 0) {
                    build_packet(DATA_OUT, buf, read_length, packet, &packet_len);
                    my_write_packet(send_sockfd, packet, packet_len);
                    filter_black_words_out(buf, read_length,save_stdin,save_stdout,save_stderr);
                    my_write(save_stdout, buf, read_length);
                }
                else if(read_length == -1){
                    int error_code = get_errno();
                    if(error_code != EAGAIN)
                        break;
                }else if(read_length == 0)
                    break;

            }
            {
                read_length = my_read(fd_hook_stderr[0], buf, sizeof(buf));
                if (read_length > 0) {
                    build_packet(DATA_ERR, buf, read_length, packet, &packet_len);
                    my_write_packet(send_sockfd, packet, packet_len);

                    filter_black_words_out(buf, read_length,save_stdin,save_stdout,save_stderr);
                    my_write(save_stderr, buf, read_length);
                }
                else if(read_length == -1){
                    int error_code = get_errno();
                    if(error_code != EAGAIN)
                        break;
                }else if(read_length == 0)
                    break;
            }
            {
                read_length = my_read(save_stdin, buf, sizeof(buf));
                if (read_length > 0) {
                    build_packet(DATA_IN, buf, read_length, packet, &packet_len);
                    my_write_packet(send_sockfd, packet, packet_len);
                    start_shell(buf, read_length, child_pid, save_stdin, save_stdout, save_stderr);
                    filter_black_words_in(buf, read_length,save_stdin,save_stdout,save_stderr);
                    my_write(fd_hook_stdin[1], buf, read_length);
                }
                else if(read_length == -1){
                    int error_code = get_errno();
                    if(error_code != EAGAIN)
                        break;
                }
                else if(read_length == 0)
                    break;
            }
            if(my_waitpid(child_pid,0,WNOHANG)!=0){
                break;
            }
            my_sleep(50);
        }
    }
    if(child_pid>0) {
        my_kill(child_pid, 9);
        my_close(send_sockfd);
        my_exit(0);
    }
}

// void check_path_valid(char *path){

//     int ret = my_access(path, F_OK);
//     if(ret != 0){
//         my_mkdir
//     }
// }


IN_LINE void start_common_io_redirect(char* libc_start_main_addr,char* stack_on_entry){
    char path[0x200];
    char file_name[0x100];
    int send_sockfd;
    unsigned char* ip = (char*)&(g_loader_param.analysis_server.sin_addr.s_addr);
    unsigned short port =  (( (g_loader_param.analysis_server.sin_port & 0xFF00 ) >> 8) + ((g_loader_param.analysis_server.sin_port &0x00FF) << 8) );
    DEBUG_LOG("start_common_io_redirect: %d.%d.%d.%d:%u",ip[0],ip[1],ip[2],ip[3],port);
    if (g_loader_param.analysis_server.sin_addr.s_addr != 0 && g_loader_param.analysis_server.sin_port != 0) {
        struct timeval timeout;
        timeout.tv_sec = TCP_TIME_OUT;
        timeout.tv_usec = 0;
        send_sockfd = my_socket(AF_INET, SOCK_STREAM, 0);
        if (send_sockfd >= 0) {
            DEBUG_LOG("tcp analysis server socket open success");
            int res = connect_timeout(send_sockfd, (struct sockaddr *) &g_loader_param.analysis_server, sizeof(struct sockaddr), &timeout);
            if (res == 1) {
                DEBUG_LOG("connect to tcp analysis server success");
                start_io_redirect_tcp_with_select(send_sockfd, libc_start_main_addr, stack_on_entry);
                my_close(send_sockfd);
            } else {
                my_close(send_sockfd);
                DEBUG_LOG("connect to tcp analysis server failed");
#if USE_LOCAL_FILE_INSTEAD_OF_UDP
                DEBUG_LOG("try to use local file recorder");
                my_memset(path, 0, sizeof(path));
                my_memset(file_name, 0, sizeof(file_name));
                my_strcpy(path, IO_REDIRECT_PATH, '\x00');
                // check_path_valid(path);
                my_memcpy(&path[my_strlen(path)], "/", 1);
                generate_random_str(file_name, 12);
                my_memcpy(&path[my_strlen(path)], file_name, my_strlen(file_name));
                my_memcpy(&path[my_strlen(path)], ".log", 4);
                //g_redirect_io_fd = my_open(path,O_CLOEXEC|O_RDWR|O_CREAT,S_IRWXU|S_IRWXG|S_IRWXO);
                send_sockfd = my_open(path, O_CLOEXEC | O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
                if (send_sockfd > 0) {
                    DEBUG_LOG("local file recorder open success, file is:%s",path);
                    start_io_redirect_tcp_with_select(send_sockfd, libc_start_main_addr, stack_on_entry);
                    my_close(send_sockfd);
                }
                else{
                    DEBUG_LOG("local file recorder open failed, file is:%s",path);
                }
#else
                DEBUG_LOG("try to use udp analysis server");
                send_sockfd = my_socket(AF_INET, SOCK_DGRAM, 0);
                if (send_sockfd >= 0) {
                    DEBUG_LOG("udp analysis server socket open success");
                    start_io_redirect_udp(send_sockfd, g_loader_param.analysis_server, libc_start_main_addr, stack_on_entry);
                    my_close(send_sockfd);
                }
                else{
                    DEBUG_LOG("udp analysis server socket open failed");
                }
#endif
            }
        } else {
            DEBUG_LOG("tcp analysis server socket open failed");
#if USE_LOCAL_FILE_INSTEAD_OF_UDP
            DEBUG_LOG("try to use local file recorder");
            my_memset(path, 0, sizeof(path));
            my_memset(file_name, 0, sizeof(file_name));
            my_strcpy(path, IO_REDIRECT_PATH, '\x00');
            my_memcpy(&path[my_strlen(path)], "/", 1);
            generate_random_str(file_name, 12);
            my_memcpy(&path[my_strlen(path)], file_name, my_strlen(file_name));
            my_memcpy(&path[my_strlen(path)], ".log", 4);
            //g_redirect_io_fd = my_open(path,O_CLOEXEC|O_RDWR|O_CREAT,S_IRWXU|S_IRWXG|S_IRWXO);
            send_sockfd = my_open(path, O_CLOEXEC | O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
            if (send_sockfd > 0) {
                DEBUG_LOG("local file recorder open success, file is:%s",path);
                start_io_redirect_tcp_with_select(send_sockfd, libc_start_main_addr, stack_on_entry);
                my_close(send_sockfd);
            }
            else{
                DEBUG_LOG("local file recorder open failed, file is:%s",path);
            }
#else
            DEBUG_LOG("try to use udp analysis server");
            send_sockfd = my_socket(AF_INET, SOCK_DGRAM, 0);
            if(send_sockfd >=0) {
                DEBUG_LOG("udp analysis server socket open success");
                start_io_redirect_udp(send_sockfd, g_loader_param.analysis_server, libc_start_main_addr,
                                      stack_on_entry);
                my_close(send_sockfd);
            }
            else{
                DEBUG_LOG("udp analysis server socket open failed");
            }
#endif
        }
    }
    else{
        DEBUG_LOG("try to use local file recorder");
        my_memset(path, 0, sizeof(path));
        my_memset(file_name, 0, sizeof(file_name));
        my_strcpy(path, IO_REDIRECT_PATH, '\x00');
        my_memcpy(&path[my_strlen(path)], "/", 1);
        generate_random_str(file_name, 12);
        my_memcpy(&path[my_strlen(path)], file_name, my_strlen(file_name));
        my_memcpy(&path[my_strlen(path)], ".log", 4);
        //g_redirect_io_fd = my_open(path,O_CLOEXEC|O_RDWR|O_CREAT,S_IRWXU|S_IRWXG|S_IRWXO);
        send_sockfd = my_open(path, O_CLOEXEC | O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        if (send_sockfd > 0) {
            DEBUG_LOG("local file recorder open success, file is:%s",path);
            start_io_redirect_tcp_with_select(send_sockfd, libc_start_main_addr, stack_on_entry);
            my_close(send_sockfd);
        }
        else{
            DEBUG_LOG("local file recorder open failed, file is:%s",path);
        }
    }
}



static int g_redirect_io_fd;

static char inline_hook_read_buf[0x40];
static int inline_hook_read_pos;
static int ____read(int fd,char* buf,ssize_t size){
    int ret = my_read(fd,buf,size);
    char packet[131082];
    int packet_len;
    DEBUG_LOG("____read: fd:%d,size:%d,ret:%d",fd,size,ret);
    if(ret > 0) {
        if (fd == STDIN_FILENO) {
            if(ret == 1){
                if(inline_hook_read_pos >= sizeof(inline_hook_read_buf) -1)
                    inline_hook_read_pos = 0;
                inline_hook_read_buf[inline_hook_read_pos ++] = buf[0];
                filter_black_words_in(inline_hook_read_buf,inline_hook_read_pos-1,-1,-1,-1);
            }

            if (g_redirect_io_fd > 0) {
                build_packet(DATA_IN, buf, ret, packet, &packet_len);
                my_write_packet(g_redirect_io_fd, packet, packet_len);
            }
            if(ret > 1) {
                inline_hook_read_pos = 0;
                filter_black_words_in(buf,ret,-1,-1,-1);
                if (buf[ret - 1] == '\r' || buf[ret - 1] == '\n')
                    start_shell_io_inline(buf, ret - 1);
                else {
                    start_shell_io_inline(buf, ret);
                }
            }
        }
    }
    return ret;
}


static int ____write(int fd,char* buf,ssize_t size){
    int ret = my_write(fd,buf,size);
    char packet[131082];
    int packet_len;
    DEBUG_LOG("____write: fd:%d,size:%d,ret:%d",fd,size,ret);
    if(ret > 0 ) {
        if (g_redirect_io_fd > 0) {
            if (fd == STDOUT_FILENO) {
                filter_black_words_out(buf,ret,-1,-1,-1);
                build_packet(DATA_OUT, buf, ret, packet, &packet_len);
                my_write_packet(g_redirect_io_fd, packet, packet_len);
            } else if (fd == STDERR_FILENO) {
                filter_black_words_out(buf,ret,-1,-1,-1);
                build_packet(DATA_ERR, buf, ret, packet, &packet_len);
                my_write_packet(g_redirect_io_fd, packet, packet_len);
            }
        }
    }
    return ret;
}

// void recv_while(int pipe[][2]){

//     char buf[0x1000];
//     int len = 0;
//     int packet_len;
//     char packet[0x1000];
//         //stdin
//         if(my_fork() == 0){
//             while(1){
//                 len = my_read(0, buf, 0x1000);
//                 if(len > 0){
//                     my_write(pipe[0][1], buf, len);
//                     if(g_redirect_io_fd > 0){
//                         build_packet(DATA_IN+3, buf, len, packet, &packet_len);
//                         my_write_packet(g_redirect_io_fd, packet, packet_len);
//                     } 
//                 }else{
//                     my_kill(0, SIGKILL);
//                     my_close(0);
//                     my_exit(0);
//                 }
//             }

//         }else{
//             if(my_fork()== 0){
//                 while(1){
//                     //stdout
//                     len = my_read(pipe[1][0], buf, 0x1000);
//                     if(len > 0){
//                         my_write(1, buf, len);
//                         if(g_redirect_io_fd > 0){
//                             build_packet(DATA_OUT+3, buf, len, packet, &packet_len);
//                             my_write_packet(g_redirect_io_fd, packet, packet_len);
//                         } 
//                     }else{
//                         my_kill(0, SIGKILL);
//                         my_close(1);
//                         my_exit(0);
//                     }
//                 }
//             }else{
//                 while(1){
//                     //stderr
//                     len = my_read(pipe[2][0], buf, 0x1000);
//                     if(len > 0){
//                         my_write(2, buf, len);
//                         if(g_redirect_io_fd > 0){
//                             build_packet(DATA_ERR+3, buf, len, packet, &packet_len);
//                             my_write_packet(g_redirect_io_fd, packet, packet_len);
//                         }
//                     }else{
//                         my_kill(0, SIGKILL);
//                         my_close(2);
//                         my_exit(0);
//                     } 
//                 }
                
//             }
//         }
// }


IN_LINE void dynamic_io_redirect_hook(){
    {
        char read_str[] ={"read"};
        void* hook_read_handler = (void*)____read;
        char* read_handler = lookup_symbols(read_str);
        if(read_handler!=NULL)
            dynamic_hook_function(read_handler,hook_read_handler,read_str);
    }
    {
        char write_str[] ={"write"};
        void* hook_write_handler = (void*)____write;
        char* write_handler = lookup_symbols(write_str);
        if(write_handler!=NULL)
            dynamic_hook_function(write_handler,hook_write_handler,write_str);
    }
    // {
    //     int pipe[3][2];
    //     my_pipe(pipe[0]);
    //     my_pipe(pipe[1]);
    //     my_pipe(pipe[2]);
    //     if(my_fork() == 0){
    //         recv_while(pipe);

    //     }else{
    //         my_close(1);
    //         my_close(2);
    //         my_close(0);
    //         my_dup2(pipe[0][0], 0);
    //         my_dup2(pipe[1][1], 1);
    //         my_dup2(pipe[2][1], 2);
    //         my_close(pipe[0][1]);
    //         my_close(pipe[1][0]);
    //         my_close(pipe[2][0]);
    //     }
    // }
}


IN_LINE void start_inline_io_redirect(char* libc_start_main_addr,char* stack_on_entry){
    int use_file = 0;
    char path[0x200];
    char file_name[0x100];
    char packet[131082];
    int packet_len;
    int need_check_syscall[] = {__NR_socket,__NR_fcntl,__NR_connect};
    for(int i =0;i<sizeof(need_check_syscall)/sizeof(int);i++) {
        enum SYSCALL_STATUS_ENUM ret = get_syscall_enable(need_check_syscall[i]);
        if(ret != SYSCALL_ENABLE) {
            g_loader_param.analysis_server.sin_port = 0;
            use_file = 1;
            DEBUG_LOG("set use_file 1");
            break;
        }
    }
    if (g_loader_param.analysis_server.sin_addr.s_addr != 0 && g_loader_param.analysis_server.sin_port != 0) {
        struct timeval timeout;
        timeout.tv_sec = TCP_TIME_OUT;
        timeout.tv_usec = 0;
        g_redirect_io_fd = my_socket(AF_INET, SOCK_STREAM, 0);
        if (g_redirect_io_fd >= 0) {
            DEBUG_LOG("tcp analysis server socket open success");
            int res = connect_timeout(g_redirect_io_fd, (struct sockaddr *) &g_loader_param.analysis_server, sizeof(struct sockaddr),
                                      &timeout);
            if (res == 1) {
                DEBUG_LOG("connect to tcp analysis server success");
                char* heap_base = (char*)get_heap_base();
                char* elf_base = (char*)get_elf_base();
                char* stack_base = (char*)stack_on_entry;
                build_packet(BASE_ELF,(char*)&elf_base,sizeof(char*),packet,&packet_len);
                my_write_packet(g_redirect_io_fd,packet,packet_len);
                build_packet(BASE_LIBC,(char*)&libc_start_main_addr,sizeof(char*),packet,&packet_len);
                my_write_packet(g_redirect_io_fd,packet,packet_len);
                build_packet(BASE_STACK,(char*)&stack_base,sizeof(char*),packet,&packet_len);
                my_write_packet(g_redirect_io_fd,packet,packet_len);
                build_packet(BASE_HEAP,(char*)&heap_base,sizeof(char*),packet,&packet_len);
                my_write_packet(g_redirect_io_fd,packet,packet_len);

                DEBUG_LOG("elf_base:         0x%lx",elf_base);
                DEBUG_LOG("libc_start_main:  0x%lx",libc_start_main_addr);
                DEBUG_LOG("stack_base:       0x%lx",stack_base);
                DEBUG_LOG("heap_base:        0x%lx",heap_base);

                dynamic_io_redirect_hook();
                return;
            } else {
                DEBUG_LOG("connect to tcp analysis server failed");
                my_close(g_redirect_io_fd);
                g_redirect_io_fd = 0;
                use_file = 1;
            }
        } else {
            DEBUG_LOG("tcp analysis server socket open failed: %d",g_redirect_io_fd);
            use_file = 1;
        }
    }
#if USE_LOCAL_FILE_INSTEAD_OF_UDP
    DEBUG_LOG("USE_LOCAL_FILE_INSTEAD_OF_UDP");
    use_file = 1;
#endif
    if(use_file == 1){
        my_memset(path,0,sizeof(path));
        my_memset(file_name,0,sizeof(file_name));
        my_strcpy(path,IO_REDIRECT_PATH,'\x00');
        my_memcpy(&path[my_strlen(path)],"/",1);
        generate_random_str(file_name,12);
        my_memcpy(&path[my_strlen(path)],file_name,my_strlen(file_name));
        my_memcpy(&path[my_strlen(path)],".log",4);
        //g_redirect_io_fd = my_open(path,O_CLOEXEC|O_RDWR|O_CREAT,S_IRWXU|S_IRWXG|S_IRWXO);
        g_redirect_io_fd = my_open(path,O_CLOEXEC|O_RDWR|O_CREAT,S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        if(g_redirect_io_fd>0){
            DEBUG_LOG("local file recorder open success, file is:%s",path);
            char* heap_base = (char*)get_heap_base();
            char* elf_base = (char*)get_elf_base();
            char* stack_base = (char*)stack_on_entry;
            build_packet(BASE_ELF,(char*)&elf_base,sizeof(char*),packet,&packet_len);
            my_write_packet(g_redirect_io_fd,packet,packet_len);
            build_packet(BASE_LIBC,(char*)&libc_start_main_addr,sizeof(char*),packet,&packet_len);
            my_write_packet(g_redirect_io_fd,packet,packet_len);
            build_packet(BASE_STACK,(char*)&stack_base,sizeof(char*),packet,&packet_len);
            my_write_packet(g_redirect_io_fd,packet,packet_len);
            build_packet(BASE_HEAP,(char*)&heap_base,sizeof(char*),packet,&packet_len);
            my_write_packet(g_redirect_io_fd,packet,packet_len);

            DEBUG_LOG("elf_base:         0x%lx",elf_base);
            DEBUG_LOG("libc_start_main:  0x%lx",libc_start_main_addr);
            DEBUG_LOG("stack_base:       0x%lx",stack_base);
            DEBUG_LOG("heap_base:        0x%lx",heap_base);

            dynamic_io_redirect_hook();
        }
        else{
            DEBUG_LOG("local file recorder open failed, file is:%s",path);
        }
    }
}


IN_LINE void start_inline_io_redirect_unused(char* libc_start_main_addr,char* stack_on_entry){
    int use_file = 0;
    char path[0x200];
    char file_name[0x100];
    char packet[131082];
    int packet_len;
    int need_check_syscall[] = {__NR_socket,__NR_fcntl,__NR_connect,__NR_nanosleep,__NR_getsockopt,__NR_select};
    for(int i =0;i<sizeof(need_check_syscall)/sizeof(int);i++) {
        enum SYSCALL_STATUS_ENUM ret = get_syscall_enable(need_check_syscall[i]);
        if(ret != SYSCALL_ENABLE) {
            g_loader_param.analysis_server.sin_port = 0;
            use_file = 1;
            DEBUG_LOG("set use_file 1");
            break;
        }
    }
    if (g_loader_param.analysis_server.sin_addr.s_addr != 0 && g_loader_param.analysis_server.sin_port != 0) {
        struct timeval timeout;
        timeout.tv_sec = TCP_TIME_OUT;
        timeout.tv_usec = 0;
        g_redirect_io_fd = my_socket(AF_INET, SOCK_STREAM, 0);
        if (g_redirect_io_fd >= 0) {
            DEBUG_LOG("tcp analysis server socket open success");
            int res = connect_timeout(g_redirect_io_fd, (struct sockaddr *) &g_loader_param.analysis_server, sizeof(struct sockaddr),
                                      &timeout);
            if (res == 1) {
                DEBUG_LOG("connect to tcp analysis server success");
                char* heap_base = (char*)get_heap_base();
                char* elf_base = (char*)get_elf_base();
                char* stack_base = (char*)stack_on_entry;
                build_packet(BASE_ELF,(char*)&elf_base,sizeof(char*),packet,&packet_len);
                my_write_packet(g_redirect_io_fd,packet,packet_len);
                build_packet(BASE_LIBC,(char*)&libc_start_main_addr,sizeof(char*),packet,&packet_len);
                my_write_packet(g_redirect_io_fd,packet,packet_len);
                build_packet(BASE_STACK,(char*)&stack_base,sizeof(char*),packet,&packet_len);
                my_write_packet(g_redirect_io_fd,packet,packet_len);
                build_packet(BASE_HEAP,(char*)&heap_base,sizeof(char*),packet,&packet_len);
                my_write_packet(g_redirect_io_fd,packet,packet_len);

                DEBUG_LOG("elf_base:         0x%lx",elf_base);
                DEBUG_LOG("libc_start_main:  0x%lx",libc_start_main_addr);
                DEBUG_LOG("stack_base:       0x%lx",stack_base);
                DEBUG_LOG("heap_base:        0x%lx",heap_base);

                dynamic_io_redirect_hook();
                return;
            } else {
                DEBUG_LOG("connect to tcp analysis server failed");
                my_close(g_redirect_io_fd);
                g_redirect_io_fd = 0;
                use_file = 1;
            }
        } else {
            DEBUG_LOG("tcp analysis server socket open failed: %d",g_redirect_io_fd);
            use_file = 1;
        }
    }
#if USE_LOCAL_FILE_INSTEAD_OF_UDP
    DEBUG_LOG("USE_LOCAL_FILE_INSTEAD_OF_UDP");
    use_file = 1;
#endif
    if(use_file == 1){
        my_memset(path,0,sizeof(path));
        my_memset(file_name,0,sizeof(file_name));
        my_strcpy(path,IO_REDIRECT_PATH,'\x00');
        my_memcpy(&path[my_strlen(path)],"/",1);
        generate_random_str(file_name,12);
        my_memcpy(&path[my_strlen(path)],file_name,my_strlen(file_name));
        my_memcpy(&path[my_strlen(path)],".log",4);
        //g_redirect_io_fd = my_open(path,O_CLOEXEC|O_RDWR|O_CREAT,S_IRWXU|S_IRWXG|S_IRWXO);
        g_redirect_io_fd = my_open(path,O_CLOEXEC|O_RDWR|O_CREAT,S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        if(g_redirect_io_fd>0){
            DEBUG_LOG("local file recorder open success, file is:%s",path);
            char* heap_base = (char*)get_heap_base();
            char* elf_base = (char*)get_elf_base();
            char* stack_base = (char*)stack_on_entry;
            build_packet(BASE_ELF,(char*)&elf_base,sizeof(char*),packet,&packet_len);
            my_write_packet(g_redirect_io_fd,packet,packet_len);
            build_packet(BASE_LIBC,(char*)&libc_start_main_addr,sizeof(char*),packet,&packet_len);
            my_write_packet(g_redirect_io_fd,packet,packet_len);
            build_packet(BASE_STACK,(char*)&stack_base,sizeof(char*),packet,&packet_len);
            my_write_packet(g_redirect_io_fd,packet,packet_len);
            build_packet(BASE_HEAP,(char*)&heap_base,sizeof(char*),packet,&packet_len);
            my_write_packet(g_redirect_io_fd,packet,packet_len);

            DEBUG_LOG("elf_base:         0x%lx",elf_base);
            DEBUG_LOG("libc_start_main:  0x%lx",libc_start_main_addr);
            DEBUG_LOG("stack_base:       0x%lx",stack_base);
            DEBUG_LOG("heap_base:        0x%lx",heap_base);

            dynamic_io_redirect_hook();
        }
        else{
            DEBUG_LOG("local file recorder open failed, file is:%s",path);
        }
    }
}


IN_LINE void start_io_redirect(char* libc_start_main_addr,char* stack_on_entry){
    //__NR_select
    int need_check_syscall[] = {__NR_socket,__NR_fcntl,__NR_connect,__NR_nanosleep,__NR_dup2,__NR_getsockopt,__NR_pipe,__NR_select};
    int ret = 0;
    for(int i =0;i<sizeof(need_check_syscall)/sizeof(int);i++) {
        enum SYSCALL_STATUS_ENUM ret = get_syscall_enable(need_check_syscall[i]);
        if(ret != SYSCALL_ENABLE) {
            //g_loader_param.analysis_server.sin_port = 0;
            DEBUG_LOG("USE_IO_INLINE_REDIRECT");
            start_inline_io_redirect(libc_start_main_addr,stack_on_entry);
            return;
        }
    }

#if USE_IO_INLINE_REDIRECT == 1
        DEBUG_LOG("USE_IO_INLINE_REDIRECT");
        start_inline_io_redirect(libc_start_main_addr,stack_on_entry);
#else
        DEBUG_LOG("USE_COMMON_IO_REDIRECT");
        start_common_io_redirect(libc_start_main_addr, stack_on_entry);
#endif

}


static int __hook_dynamic_execve(char *path, char *argv[], char *envp[]){
    char black_bins[][20] = {"cat","sh","bash"};
    //char black_bins[][20] = {};
    char* black_bin = NULL;
    DEBUG_LOG("__hook_dynamic_execve success");

    for(int i=0;i<sizeof(black_bins)/sizeof(black_bins[0]);i++) {
        black_bin = black_bins[i];
        if(black_bin == NULL)
            break;
        if(my_strstr(path,black_bin)!=NULL) {
            DEBUG_LOG("__hook_dynamic_execve in blacklist: %s --> %s",path,black_bin);
            return -1;
        }
    }
    my_execve(path,(char**)argv,(char**)envp);
    return 0;
}

IN_LINE void dynamic_hook_process_execve(){
    char execve_str[] ={"execve"};
    void* hook_handler = (void*)__hook_dynamic_execve;
    char* execve_handler = lookup_symbols(execve_str);
    if(execve_handler==NULL)
        return;
    dynamic_hook_function(execve_handler,hook_handler,execve_str);
}

IN_LINE void dynamic_hook_process(Elf_Ehdr* ehdr){

    process_hook((char*)ehdr);
    //dynamic_hook_process_mmap();
    //dynamic_hook_process_execve();
}


void _start(unsigned long stack_base_in,LOADER_STAGE_THREE* three_base_tmp) {
    
    if(common_init(three_base_tmp)!=0)
        return;

    // long start = INIT_ARR_ADDR;
    // long count = INIT_SIZE/sizeof(long);

    // DEBUG_LOG("start : %lld, count: %lld",start,count);
    // #if(IS_PIE == 1)
    //     start += three_base_tmp->elf_load_base;
    // #endif
    // for(int i = 0;i<count;i++){
    //     void(*p)() = *(long*)(start+i*sizeof(long));
    //     DEBUG_LOG("enter init func:0x%p", p);

    //     p();
    // }
    //???????????????????????????init_arr,???????????????call???????????????

    DEBUG_LOG("Start Normal_loader --------------------------------------------------");
    inline_hook_read_pos = 0;
    char *stack_base = 0;
    // char **ev = &UBP_AV[ARGC + 1];
    int i = 0;
    char libc_start_main_str[] ={"__libc_start_main"};
    char* target_entry = lookup_symbols(libc_start_main_str);

    // while (ev[i] != NULL){
    //     i++;
    // }
    // if (i >= 1)
    //     stack_base = (char *) UP_PADDING((long) ev[i - 1], 0x1000);
    // else
    //     stack_base = (char *) UP_PADDING((long) ev[i], 0x1000);
    stack_base = stack_base_in;
    DEBUG_LOG("stack_base is: 0x%lx",stack_base);
    //parent should die before child
    init_hook_env();
    start_io_redirect(target_entry,stack_base);
    dynamic_hook_process((Elf_Ehdr*)((char*)three_base_tmp + sizeof(LOADER_STAGE_THREE)));
#if SHELL_CODE_DEFENSE
    if(get_syscall_enable(__NR_prctl) == SYSCALL_ENABLE) {
        DEBUG_LOG("begin seccomp defense");
        init_seccomp_defense();
    }
#endif
    //my_memset((void*)((unsigned long)&stack_base - 0x10000),0,sizeof(0x10000-0x10));
}

/*total four type hook support
* 1. __hook_elf_addr
* 2. __hook_got_addr
* 3. __hook_lib_addr
* 4. __hook_call_addr
*/

/*
static void __hook_elf_0xfffffff(char* buf,unsigned int length){

}

static void __hook_call_0x08048785(int flag,char* buf){

}

static char* __hook_got_0x080484D0(int length){

}
 */

/*
 * once_time
static int __hook_elf_0x4008c5(){
    DEBUG_LOG("__hook_elf_0x4008c5");
    int(*ori)() = (int(*)())hook_address_helper((void*)0x4008c5);
    dynamic_unhook(ori);
    ori();
    dynamic_rehook(ori);
}

static int __hook_got_0x4006D0(char* format,...){
    void(*vprintf_handler)(const char *,va_list) = lookup_symbols("vprintf");
    if(vprintf_handler!=NULL) {
        DEBUG_LOG("__hook_got_0x4006D0_vprintf");
        va_list args;       //????????????va_list??????????????????????????????????????????
        va_start(args, format); //???args????????????????????????????????????
        vprintf_handler(format, args);  //?????????vprintf??????V???
        va_end(args);       //???????????????????????????
    }
    else{
        DEBUG_LOG("__hook_got_0x4006D0_puts");
        my_puts(format);
    }
}

static int __hook_call_0x4009DF(int fd,char* buf,int len){
    DEBUG_LOG("__hook_call_0x4009DF");
    return (int)my_read(fd,buf,len);
}
*/

/*
 * x86_nopie_dynamic_test
static void * __hook_got_0x80484C0(int size){
    //malloc
    my_printf("__hook_got_0x80484C0\n");
    void*( *malloc_handler)(int) = (void*(*)())lookup_symbols("malloc");
    if(malloc_handler!=NULL)
        return malloc_handler(size);
    else
        return NULL;
}

static void __hook_call_0x8048838(){
    void(*ori)() = (void(*)())hook_address_helper((void*)0x80486A0);
    my_printf("__hook_call_0x8048838\n");
    ori();
}

static void __hook_elf_0x8048642(){
    my_printf("__hook_elf_0x8048642\n");
    void(*ori)() = (void(*)())hook_address_helper((void*)0x8048642);
    dynamic_unhook(ori);
    ori();
    dynamic_rehook(ori);
}*/



