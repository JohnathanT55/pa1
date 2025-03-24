#ifndef GLOBAL_H_
#define GLOBAL_H_

#define HOSTNAME_LEN 128
#define PATH_LEN 256
#define MAX_CLIENTS 4
#define MAX_BUFFERED_MSGS 100
#define IPV4_ADDR_LEN 16

struct buffered_message {
    char from_ip[IPV4_ADDR_LEN];
    char to_ip[IPV4_ADDR_LEN];
    char msg[256];
};

extern struct buffered_message message_buffer[MAX_BUFFERED_MSGS];

#endif
