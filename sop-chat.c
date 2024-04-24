#include "l4-common.h"

#define BACKLOG_SIZE 10
#define MAX_CLIENT_COUNT 4
#define MAX_EVENTS 10

#define NAME_OFFSET 0
#define NAME_SIZE 64
#define MESSAGE_OFFSET NAME_SIZE
#define MESSAGE_SIZE 448
#define BUFF_SIZE (NAME_SIZE + MESSAGE_SIZE)

volatile sig_atomic_t do_work = 1;

void sigint_handler(int sig) { do_work = 0; }

void server_work(int tcp_listen_socket, char* key) {
    int epoll_descriptor = epoll_create1(0);
    if (epoll_descriptor < 0)
        ERR("epoll_create:");
    struct epoll_event events[MAX_EVENTS], event = {.events = EPOLLIN, .data.fd = tcp_listen_socket};
    if (epoll_ctl(epoll_descriptor, EPOLL_CTL_ADD, tcp_listen_socket, &event) == -1)
    {
        perror("epoll_ctl: listen_sock");
        exit(EXIT_FAILURE);
    }

    int nfds;
    int client_status[MAX_CLIENT_COUNT] = {0};
    int client_socket[MAX_CLIENT_COUNT];
    char data[BUFF_SIZE], name[NAME_SIZE+1], message[MESSAGE_SIZE+1];
    name[NAME_SIZE] = '\0';
    message[MESSAGE_SIZE] = '\0';
    sigset_t mask, oldmask;
    ssize_t size;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_BLOCK, &mask, &oldmask);
    while (do_work)
    {
        if ((nfds = epoll_pwait(epoll_descriptor, events, MAX_EVENTS, -1, &oldmask)) > 0)
        {
            for (int n = 0; n < nfds; ++n)
            {
                int client_socket = add_new_client(events[n].data.fd);
                if (client_socket < 0)
                    continue;
                if ((size = bulk_read(client_socket, data, sizeof(data))) < 0)
                    ERR("read:");
                strncpy(name, data + NAME_OFFSET, NAME_SIZE);
                strncpy(message, data + MESSAGE_OFFSET, MESSAGE_SIZE);
                fprintf(stdout, "%s tried to authenticate with key: %s\n", name, message);
                if (strcmp(key, message) == 0)
                {
                    fprintf(stdout, "%s provided valid key\n", name);
                    if (bulk_write(client_socket, data, sizeof(data)) < 0) // Send back received message
                        ERR("write:");
                    for (int i = 0; i < 5; ++i)
                    {
                        if ((size = bulk_read(client_socket, data, sizeof(data))) < 0)
                            ERR("read:");
                        strncpy(name, data + NAME_OFFSET, NAME_SIZE);
                        strncpy(message, data + MESSAGE_OFFSET, MESSAGE_SIZE);
                        fprintf(stdout, "%s: %s\n", name, message);
                    }
                }
                else
                {
                    fprintf(stdout, "%s provided invalid key\n", name);
                    if (TEMP_FAILURE_RETRY(close(client_socket)) < 0)
                        ERR("close");
                }
            }
        }
        else
        {
            if (errno == EINTR)
                continue;
            ERR("epoll_pwait");
        }
        return;
    }
    for (int i = 0; i < MAX_CLIENT_COUNT; ++i)
    {
        if (client_status[i])
        {
            if (TEMP_FAILURE_RETRY(close(client_socket[i])) < 0)
                ERR("close");
        }
    }
    if (TEMP_FAILURE_RETRY(close(epoll_descriptor)) < 0)
        ERR("close");
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

void usage(char *program_name) {
    fprintf(stderr, "USAGE: %s port key\n", program_name);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    if (argc != 3) 
        usage(argv[0]);

    uint16_t port = atoi(argv[1]); // Incorrect, casting int to uint
    if (port == 0)
        usage(argv[0]);
    char *key = argv[2];

    if (sethandler(SIG_IGN, SIGPIPE))
        ERR("Seting SIGPIPE:");
    if (sethandler(sigint_handler, SIGINT))
        ERR("Seting SIGINT:");

    int tcp_listen_socket = bind_tcp_socket(port, BACKLOG_SIZE);
    int new_flags = fcntl(tcp_listen_socket, F_GETFL) | O_NONBLOCK;
    fcntl(tcp_listen_socket, F_SETFL, new_flags);

    server_work(tcp_listen_socket, key);

    if (TEMP_FAILURE_RETRY(close(tcp_listen_socket)) < 0)
        ERR("close");

    return EXIT_SUCCESS;
}