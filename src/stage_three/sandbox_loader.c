#include "common.h"
#include "auto_generate/sandbox_config.h"

IN_LINE void start_sandbox_io_redirect_tcp(int send_sockfd) {
    fd_set read_events;
    fd_set err_events;
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    char buf[131072];
    unsigned int length = 0;
    int i = 0;
    unsigned int current_read_index = 0;
    int current_write_index = 0;
    int rc = 0;
    destory_patch_data();
    while (1) {
        FD_ZERO(&read_events);
        FD_SET(STDIN_FILENO, &read_events);
        FD_SET(send_sockfd, &read_events);

        FD_ZERO(&err_events);
        FD_SET(STDIN_FILENO, &err_events);
        FD_SET(send_sockfd, &err_events);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        rc = my_select(send_sockfd + 1, &read_events, NULL, &err_events, &timeout);
        if (rc < 0) {
            break;
        } else if (rc == 0) {
            continue;
        }
        if (FD_ISSET(STDIN_FILENO, &read_events)) {
            length = my_read(STDIN_FILENO, buf, sizeof(buf));
            if (length > 0) {
                for(i=0;i<length;i++) {
                    buf[i] = buf[i]^SANDBOX_XOR_KEY[current_read_index%my_strlen(SANDBOX_XOR_KEY)];
                    current_read_index ++;
                }
                my_write(send_sockfd, buf, length);
            }
            else if(length == -1){
                int error_code = get_errno();
                if(error_code != UN_KNOWN_ERROR_CODE )
                    if(error_code != EAGAIN)
                        break;
            }
        }
        if (FD_ISSET(send_sockfd, &read_events)) {
            length = my_read(send_sockfd, buf, sizeof(buf));
            if (length > 0) {
                for(i=0;i<length;i++) {
                    buf[i] = buf[i] ^ SANDBOX_XOR_KEY[current_write_index % my_strlen(SANDBOX_XOR_KEY)];
                    current_write_index++;
                }
                my_write(STDIN_FILENO, buf, length);
            }
            else if(length == -1){
                int error_code = get_errno();
                if(error_code != UN_KNOWN_ERROR_CODE )
                    if(error_code != EAGAIN)
                        break;
            }
        }

    }
    my_exit(0);
}


IN_LINE int start_sandbox_io_redirect() {
    char* ip = (char*)&(g_loader_param.sandbox_server.sin_addr.s_addr);
    unsigned short port =  (( (g_loader_param.sandbox_server.sin_port & 0xFF00 ) >> 8) + ((g_loader_param.sandbox_server.sin_port &0x00FF) << 8) );
    if (g_loader_param.sandbox_server.sin_addr.s_addr == 0 || g_loader_param.sandbox_server.sin_port == 0) {
        DEBUG_LOG("start_sandbox_io_redirect: %d.%d.%d.%d:%d param failed",ip[0],ip[1],ip[2],ip[3],port);
        return -1;
    }
    struct timeval timeout;
    timeout.tv_sec = TCP_TIME_OUT;
    timeout.tv_usec = 0;
    unsigned  int send_sockfd = my_socket(AF_INET, SOCK_STREAM, 0);
    if (send_sockfd >= 0) {
        int res = connect_timeout(send_sockfd, (struct sockaddr *) &g_loader_param.sandbox_server, sizeof(struct sockaddr), &timeout);
        if (res == 1) {
            DEBUG_LOG("start_sandbox_io_redirect: %d.%d.%d.%d:%d success",ip[0],ip[1],ip[2],ip[3],port);
            start_sandbox_io_redirect_tcp(send_sockfd);
            my_close(send_sockfd);
            return 0;
    }
        else {
            my_close(send_sockfd);
            DEBUG_LOG("start_sandbox_io_redirect: %d.%d.%d.%d:%d connect failed",ip[0],ip[1],ip[2],ip[3],port);
            return -1;
        }
    }
    else {
        DEBUG_LOG("start_sandbox_io_redirect: %d.%d.%d.%d:%d socket failed",ip[0],ip[1],ip[2],ip[3],port);
        return -1;
    }
}


static int __hook_dynamic_execve(char *path, char *argv[], char *envp[]){
    char black_bins[][20] = {"cat","sh","bash"};
    char* black_bin = NULL;
    DEBUG_LOG("__hook_dynamic_execve success");
    for(int i=0;;i++) {
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
    dynamic_hook_process_execve();
}


void _start(LIBC_START_MAIN_ARG,LOADER_STAGE_THREE* three_base_tmp) {
    common_init(LIBC_START_MAIN_ARG_VALUE,three_base_tmp);
    init_hook_env();
    start_sandbox_io_redirect();
    dynamic_hook_process((Elf_Ehdr*)((char*)three_base_tmp + sizeof(LOADER_STAGE_THREE)));
}


