/**
 * @assignment1
 * @author  Team Members <ubitname@buffalo.edu>
 * @version 1.0
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * This contains the main function. Add further description here....
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/select.h>

#include "../include/global.h"
#include "../include/logger.h"

#define MAX_CLIENTS 4
#define BUFFER_SIZE 1024
#define YOUR_TEAM_NAME "junhuata-hanchaog"

struct buffered_message message_buffer[MAX_BUFFERED_MSGS];

int is_server = 0;
int server_socket = -1;
int client_socket = -1;
int port_number = 0;

/**
 * @section DESCRIPTION
 * 解析命令行参数
 */
void parse_args(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "Error: %s [s/c] <port>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	port_number = atoi(argv[2]);
	if (port_number <= 1024 || port_number > 65535) {
		fprintf(stderr, "Error: range 1025-65535.\n");
		exit(EXIT_FAILURE);
	}

	if (strcmp(argv[1], "s") == 0) {
		is_server = 1;
	} else if (strcmp(argv[1], "c") == 0) {
		is_server = 0;
	} else {
		fprintf(stderr, "Error: 's' for server or 'c' for client.\n");
		exit(EXIT_FAILURE);
	}
}

/**
 * @section DESCRIPTION
 * 初始化服务器socket
 */
void setup_server() {
	struct sockaddr_in server_addr;
	server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket < 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	int opt = 1;
	setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port_number);
	if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	if (listen(server_socket, MAX_CLIENTS) < 0) {
		perror("listen failed");
		exit(EXIT_FAILURE);
	}

	// 测试用，得删除
	cse4589_print_and_log("[%s:SUCCESS]\n", "SERVER_SETUP");
	cse4589_print_and_log("[%s:END]\n", "SERVER_SETUP");
}

/**
 * @section DESCRIPTION
 * 初始化客户端 socket
 */
void setup_client() {
	client_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (client_socket < 0) {
		perror("Client socket creation failed");
		exit(EXIT_FAILURE);
	}

	// 测试用，得删除
	cse4589_print_and_log("[%s:SUCCESS]\n", "CLIENT_SETUP");
	cse4589_print_and_log("[%s:END]\n", "CLIENT_SETUP");
}

/**
 * @section DESCRIPTION
 * 处理SHELL命令
 */
void handle_shell_command(char *cmd) {
	if (strcmp(cmd, "AUTHOR") == 0) {
		cse4589_print_and_log("[%s:SUCCESS]\n", "AUTHOR");
		cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", YOUR_TEAM_NAME);
		cse4589_print_and_log("[%s:END]\n", "AUTHOR");
	} else if (strcmp(cmd, "EXIT") == 0) {
		cse4589_print_and_log("[%s:SUCCESS]\n", "EXIT");
		cse4589_print_and_log("[%s:END]\n", "EXIT");
		exit(0);
	} else {
		cse4589_print_and_log("[%s:ERROR]\n", cmd);
		cse4589_print_and_log("[%s:END]\n", cmd);
	}
}

/**
 * @section DESCRIPTION
 * 服务器主循环
 */
void server_loop() {
    fd_set master, read_fds;
    FD_ZERO(&master);
    FD_SET(STDIN_FILENO, &master);
    FD_SET(server_socket, &master);
    int fd_max = server_socket;

    while (1) {
        read_fds = master;
        if (select(fd_max + 1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select error");
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            char input[BUFFER_SIZE];
            fgets(input, BUFFER_SIZE, stdin);
            input[strcspn(input, "\n")] = '\0';
            handle_shell_command(input);
        }

        if (FD_ISSET(server_socket, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int new_fd = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);
            if (new_fd == -1) {
                perror("accept failed");
            } else {
                FD_SET(new_fd, &master);
                if (new_fd > fd_max) fd_max = new_fd;
                printf("New connection accepted\n");
            }
        }
    }
}

/**
 * @section DESCRIPTION
 * 客户端主循环
 */
void client_loop() {
    fd_set master, read_fds;
    FD_ZERO(&master);
    FD_SET(STDIN_FILENO, &master);

    while (1) {
        read_fds = master;
        if (select(STDIN_FILENO + 1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select error");
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            char input[BUFFER_SIZE];
            fgets(input, BUFFER_SIZE, stdin);
            input[strcspn(input, "\n")] = '\0';
            handle_shell_command(input);
        }
    }
}

/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list
 * @return 0 EXIT_SUCCESS
 */
int main(int argc, char **argv)
{
	/*Init. Logger*/
	cse4589_init_log(argv[2]);

	/*Clear LOGFILE*/
	fclose(fopen(LOGFILE, "w"));

	/*Start Here*/
	parse_args(argc, argv);
	if (is_server) {
		setup_server();
		server_loop();
	} else {
		setup_client();
		client_loop();
	}

	return 0;
}
