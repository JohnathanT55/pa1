#ifndef GLOBAL_H_
#define GLOBAL_H_

#define HOSTNAME_LEN 128
#define PATH_LEN 256
#define MAX_CLIENTS 4
#define MAX_BUFFERED_MSGS 100
#define IPV4_ADDR_LEN 16
#define MAX_MSG_LEN 256

struct buffered_message {
    char from_ip[IPV4_ADDR_LEN];
    char to_ip[IPV4_ADDR_LEN];
    char msg[MAX_MSG_LEN];
};

extern struct buffered_message message_buffer[MAX_BUFFERED_MSGS];

struct client_info {
    char hostname[HOSTNAME_LEN];
    char ip[IPV4_ADDR_LEN];
    int port;
    int socket_fd;
    int logged_in;
};

extern struct client_info client_list[MAX_CLIENTS];

extern int block_matrix[MAX_CLIENTS][MAX_CLIENTS];

#endif
