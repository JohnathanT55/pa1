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
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200112L

int gethostname(char *name, size_t len);

struct buffered_message message_buffer[MAX_BUFFERED_MSGS];
struct client_info client_list[MAX_CLIENTS];
int block_matrix[MAX_CLIENTS][MAX_CLIENTS] = {0};


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
	// cse4589_print_and_log("[%s:SUCCESS]\n", "SERVER_SETUP");
	// cse4589_print_and_log("[%s:END]\n", "SERVER_SETUP");
}

/**
 * @section DESCRIPTION
 * 初始化客户端 socket
 */
void setup_client() {

	// 测试用，得删除
	//cse4589_print_and_log("[%s:SUCCESS]\n", "CLIENT_SETUP");
	//cse4589_print_and_log("[%s:END]\n", "CLIENT_SETUP");
}

/**
 * @section DESCRIPTION
 * 获取本机IP地址
 */
char* get_own_ip() {
    static char ip[INET_ADDRSTRLEN];
    struct sockaddr_in serv;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) return NULL;

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);

    connect(sock, (const struct sockaddr*)&serv, sizeof(serv));

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    getsockname(sock, (struct sockaddr*)&name, &namelen);

    const char* p = inet_ntop(AF_INET, &name.sin_addr, ip, sizeof(ip));
    close(sock);
    return (p != NULL) ? ip : NULL;
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
	} else if (strcmp(cmd, "IP") == 0) {
		char* ip_addr = get_own_ip();
		if (ip_addr) {
			cse4589_print_and_log("[%s:SUCCESS]\n", "IP");
			cse4589_print_and_log("IP:%s\n", ip_addr);
			cse4589_print_and_log("[%s:END]\n", "IP");
		} else {
			cse4589_print_and_log("[%s:ERROR]\n", "IP");
			cse4589_print_and_log("[%s:END]\n", "IP");
		}
	} else if (strcmp(cmd, "PORT") == 0) {
		cse4589_print_and_log("[%s:SUCCESS]\n", "PORT");
		cse4589_print_and_log("PORT:%d\n", port_number);
		cse4589_print_and_log("[%s:END]\n", "PORT");
	} else if (strcmp(cmd, "LIST") == 0) {
		if (is_server) {
			cse4589_print_and_log("[%s:SUCCESS]\n", "LIST");
			struct client_info sorted[MAX_CLIENTS];
			int count = 0;
			for (int i = 0; i < MAX_CLIENTS; ++i) {
				if (client_list[i].logged_in) {
					sorted[count++] = client_list[i];
				}
			}
			for (int i = 0; i < count - 1; ++i) {
				for (int j = i + 1; j < count; ++j) {
					if (sorted[i].port > sorted[j].port) {
						struct client_info tmp = sorted[i];
						sorted[i] = sorted[j];
						sorted[j] = tmp;
					}
				}
			}
			for (int i = 0; i < count; ++i) {
				cse4589_print_and_log("%-5d%-35s%-20s%-8d\n",
					i + 1,
					sorted[i].hostname,
					sorted[i].ip,
					sorted[i].port);
			}
			cse4589_print_and_log("[%s:END]\n", "LIST");
		} else {
			// 客户端将 LIST 命令发送给服务器
			send(client_socket, "LIST\n", strlen("LIST\n"), 0);
		}
	} else if (strncmp(cmd, "LOGIN", 5) == 0 && !is_server) {
    	// 避免重复登录（client_socket 已经存在说明已连接）
    	if (client_socket != -1) {
        	cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
			printf("Already logged in. Please LOGOUT first.\n");
        	cse4589_print_and_log("[%s:END]\n", "LOGIN");
        	return;
    	}

    	// 解析 LOGIN 参数
    	char server_ip[IPV4_ADDR_LEN];
    	int server_port;
    	if (sscanf(cmd, "LOGIN %15s %d", server_ip, &server_port) != 2) {
        	cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
			printf("Invalid command format. Usage: LOGIN <server_ip> <server_port>\n");
        	cse4589_print_and_log("[%s:END]\n", "LOGIN");
        	return;
    	}

    	// 创建 socket 并连接服务器
    	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    	if (sockfd < 0) {
        	perror("Socket");
        	cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
			printf("Socket creation failed\n");
        	cse4589_print_and_log("[%s:END]\n", "LOGIN");
        	return;
    	}

    	struct sockaddr_in serv_addr;
    	memset(&serv_addr, 0, sizeof(serv_addr));
    	serv_addr.sin_family = AF_INET;
    	serv_addr.sin_port = htons(server_port);
    	if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        	cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
			printf("Invalid server IP address\n");
        	cse4589_print_and_log("[%s:END]\n", "LOGIN");
        	close(sockfd);
        	return;
    	}

    	if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        	perror("Connect");
        	cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
			printf("Connection to server failed\n");
        	cse4589_print_and_log("[%s:END]\n", "LOGIN");
        	close(sockfd);
        	return;
   		}

    	// 获取本机主机名和 IP，用于发送登录信息
    	char* my_ip = get_own_ip();
    	char my_host[HOSTNAME_LEN];
    	gethostname(my_host, HOSTNAME_LEN);

    	// 构建登录报文并发送到服务器
    	char buffer[BUFFER_SIZE];
    	snprintf(buffer, sizeof(buffer), "LOGIN|%s|%s|%d", my_host, my_ip, port_number);
    	send(sockfd, buffer, strlen(buffer), 0);

    	client_socket = sockfd;

    	cse4589_print_and_log("[%s:SUCCESS]\n", "LOGIN");
    	cse4589_print_and_log("[%s:END]\n", "LOGIN");

    } else if (strncmp(cmd, "SEND", 4) == 0 && !is_server) {
		char target_ip[IPV4_ADDR_LEN], message[MAX_MSG_LEN];
    	if (sscanf(cmd, "SEND %15s %[^\n]", target_ip, message) != 2) {
        	cse4589_print_and_log("[%s:ERROR]\n", "SEND");
        	cse4589_print_and_log("[%s:END]\n", "SEND");
        	return;
    	}

    	char buffer[BUFFER_SIZE];
    	snprintf(buffer, sizeof(buffer), "SEND|%s|%s", target_ip, message);
    	send(client_socket, buffer, strlen(buffer), 0);

    	cse4589_print_and_log("[%s:SUCCESS]\n", "SEND");
    	cse4589_print_and_log("[%s:END]\n", "SEND");

    } else if (strncmp(cmd, "BROADCAST", 9) == 0 && !is_server) {
		char message[MAX_MSG_LEN];
    	if (sscanf(cmd, "BROADCAST %[^\n]", message) != 1) {
       		cse4589_print_and_log("[%s:ERROR]\n", "BROADCAST");
        	cse4589_print_and_log("[%s:END]\n", "BROADCAST");
        	return;
    	}

    	char buffer[BUFFER_SIZE];
    	snprintf(buffer, sizeof(buffer), "BROADCAST|%s", message);
    	send(client_socket, buffer, strlen(buffer), 0);

    	cse4589_print_and_log("[%s:SUCCESS]\n", "BROADCAST");
    	cse4589_print_and_log("[%s:END]\n", "BROADCAST");

	} else if (strncmp(cmd, "BLOCK", 6) == 0 && !is_server) {
    	char block_ip[IPV4_ADDR_LEN];
    	if (sscanf(cmd + 6, "%15s", block_ip) != 1) {
        	cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
        	cse4589_print_and_log("[%s:END]\n", "BLOCK");
        	return;
    	}
		// 验证是否存在该IP
		int found = 0;
    	for (int i = 0; i < MAX_CLIENTS; ++i) {
        	if (client_list[i].logged_in && strcmp(client_list[i].ip, block_ip) == 0) {
            	found = 1;
            	break;
        	}
    	}

    	if (!found) {
        	cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
        	printf("Client not found or IP invalid.\n");
        	cse4589_print_and_log("[%s:END]\n", "BLOCK");
        	return;
    	}

        // 发送 BLOCK 报文
    	char buffer[BUFFER_SIZE];
    	snprintf(buffer, sizeof(buffer), "BLOCK|%s", block_ip);
    	send(client_socket, buffer, strlen(buffer), 0);

    	cse4589_print_and_log("[%s:SUCCESS]\n", "BLOCK");
    	cse4589_print_and_log("[%s:END]\n", "BLOCK");

	} else if (strncmp(cmd, "UNBLOCK", 8) == 0 && !is_server) {
    	char unblock_ip[IPV4_ADDR_LEN];
    	if (sscanf(cmd + 8, "%15s", unblock_ip) != 1) {
        	cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
        	cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
        	return;
    	}

		// 验证本地列表中是否存在该 IP
   		int found = 0;
    	for (int i = 0; i < MAX_CLIENTS; ++i) {
        	if (client_list[i].logged_in && strcmp(client_list[i].ip, unblock_ip) == 0) {
            	found = 1;
            	break;
        	}
    	}

    	if (!found) {
        	cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
        	printf("Client not found or IP invalid.\n");
        	cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
        	return;
    	}

    	char buffer[BUFFER_SIZE];
    	snprintf(buffer, sizeof(buffer), "UNBLOCK|%s", unblock_ip);
    	send(client_socket, buffer, strlen(buffer), 0);

    	cse4589_print_and_log("[%s:SUCCESS]\n", "UNBLOCK");
    	cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
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
    fd_set master_fds, read_fds;
    FD_ZERO(&master_fds);
    FD_SET(STDIN_FILENO, &master_fds);
    FD_SET(server_socket, &master_fds);
    int fd_max = server_socket;

    while (1) {
        read_fds = master_fds;
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

		// 处理新客户端连接
        if (FD_ISSET(server_socket, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int new_fd = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);
            if (new_fd < 0) continue;

            // 接收客户端发来的 LOGIN 报文
            char buffer[BUFFER_SIZE] = {0};
			int bytes_received = recv(new_fd, buffer, sizeof(buffer), 0);
			if (bytes_received <= 0) {
        		close(new_fd);
        		continue;
    		}

    		// 解析 LOGIN 报文结构：LOGIN|hostname|ip|port
    		char type[16], hostname[HOSTNAME_LEN], ip[IPV4_ADDR_LEN];
    		int client_port;
    		if (sscanf(buffer, "%[^|]|%[^|]|%[^|]|%d", type, hostname, ip, &client_port) != 4) {
        		close(new_fd);
        		return;
    		}

    		// 注册该客户端到 client_list（如果尚未注册）
    		for (int i = 0; i < MAX_CLIENTS; ++i) {
        		if (!client_list[i].logged_in) {
            		strncpy(client_list[i].hostname, hostname, HOSTNAME_LEN);
            		strncpy(client_list[i].ip, ip, IPV4_ADDR_LEN);
            		client_list[i].port = client_port;
            		client_list[i].socket_fd = new_fd;
            		client_list[i].logged_in = 1;
            		break;
        		}
    		}

    		// 加入 select() 监听集合
    		FD_SET(new_fd, &master_fds);
    		if (new_fd > fd_max) fd_max = new_fd;
        }

        // 处理已连接客户端的消息
		for (int i = 0; i <= fd_max; ++i) {
    		if (FD_ISSET(i, &read_fds)) {
        		// 跳过已处理的 stdin 和 server_socket
        		if (i == STDIN_FILENO || i == server_socket) continue;

        		char recv_buf[BUFFER_SIZE] = {0};
        		int nbytes = recv(i, recv_buf, sizeof(recv_buf), 0);
        		if (nbytes <= 0) {
            		// 客户端断开
            		close(i);
            		FD_CLR(i, &master_fds);
            		// 同步更新 client_list
            		for (int j = 0; j < MAX_CLIENTS; ++j) {
                		if (client_list[j].socket_fd == i) {
                    		client_list[j].logged_in = 0;
                    		client_list[j].socket_fd = -1;
                    		break;
                		}
            		}
            		continue;
        		}

        		// 处理 SEND 报文
        		if (strncmp(recv_buf, "SEND|", 5) == 0) {
            		char target_ip[IPV4_ADDR_LEN], msg[MAX_MSG_LEN];
            		sscanf(recv_buf + 5, "%[^|]|%[^\n]", target_ip, msg);

            		// 查找发送者 IP
            		char sender_ip[IPV4_ADDR_LEN] = "";
					int sender_index = -1;
            		for (int k = 0; k < MAX_CLIENTS; ++k) {
                		if (client_list[k].socket_fd == i) {
                    		strcpy(sender_ip, client_list[k].ip);
							sender_index = k;
                    		break;
                		}
            		}

            		int delivered = 0;
            		for (int j = 0; j < MAX_CLIENTS; ++j) {
                		if (client_list[j].logged_in && strcmp(client_list[j].ip, target_ip) == 0) {

							// 插入 BLOCK 判断
							if (block_matrix[j][sender_index] == 1) {
                    			cse4589_print_and_log("[%s:ERROR]\n", "SEND");
                    			printf("Message blocked by recipient.\n");
                    			cse4589_print_and_log("[%s:END]\n", "SEND");
                    			delivered = 1;
                    			break;
                    		}

							char relay[BUFFER_SIZE];
                    		snprintf(relay, sizeof(relay), "RELAYED|%s|%s\n", sender_ip, msg);
                    		send(client_list[j].socket_fd, relay, strlen(relay), 0);
                    		delivered = 1;
                    		break;
                		}
            		}

            		// 缓存消息
            		if (!delivered) {
                		for (int b = 0; b < MAX_BUFFERED_MSGS; ++b) {
                	    	if (strlen(message_buffer[b].msg) == 0) {
                        		strcpy(message_buffer[b].from_ip, sender_ip);
                	        	strcpy(message_buffer[b].to_ip, target_ip);
                        		strcpy(message_buffer[b].msg, msg);
                        		break;
                    		}
                		}
            		}
        		}

        		// 处理 BROADCAST 报文
        		else if (strncmp(recv_buf, "BROADCAST|", 10) == 0) {
           			char msg[MAX_MSG_LEN];
            		sscanf(recv_buf + 10, "%[^\n]", msg);

            		char sender_ip[IPV4_ADDR_LEN] = "";
            		for (int k = 0; k < MAX_CLIENTS; ++k) {
                		if (client_list[k].socket_fd == i) {
                    		strcpy(sender_ip, client_list[k].ip);
                    		break;
                		}
            		}

            		for (int j = 0; j < MAX_CLIENTS; ++j) {
                		if (client_list[j].logged_in && client_list[j].socket_fd != i) {
                    		char relay[BUFFER_SIZE];
                    		snprintf(relay, sizeof(relay), "RELAYED|%s|%s\n", sender_ip, msg);
                    		send(client_list[j].socket_fd, relay, strlen(relay), 0);
                		}
            		}
        		}

				// 处理 LIST 请求
				else if (strncmp(recv_buf, "LIST", 4) == 0) {
					struct client_info sorted[MAX_CLIENTS];
					int count = 0;

					for (int j = 0; j < MAX_CLIENTS; ++j) {
						if (client_list[j].logged_in) {
							sorted[count++] = client_list[j];
						}
					}

					// 关键：按 port 升序排序
					for (int i = 0; i < count - 1; ++i) {
						for (int j = i + 1; j < count; ++j) {
							if (sorted[i].port > sorted[j].port) {
								struct client_info tmp = sorted[i];
								sorted[i] = sorted[j];
								sorted[j] = tmp;
							}
						}
					}

					// 拼接结果并发送给 client
					char result[BUFFER_SIZE * 4] = "";
					for (int i = 0; i < count; ++i) {
						char entry[128];
						snprintf(entry, sizeof(entry), "%-5d%-35s%-20s%-8d\n",
		         			i + 1,
		         			sorted[i].hostname,
		         			sorted[i].ip,
		         			sorted[i].port);
						strcat(result, entry);
					}

					send(i, result, strlen(result), 0);  // i 是当前 client 的 socket
				}

				// 处理 BLOCK 报文
                else if (strncmp(recv_buf, "BLOCK|", 6) == 0) {
                    char block_ip[IPV4_ADDR_LEN];
                    sscanf(recv_buf + 6, "%s", block_ip);

                    // 更新阻塞矩阵
                    int blocker_index = -1, blocked_index = -1;
					for (int j = 0; j < MAX_CLIENTS; ++j) {
						if (client_list[j].socket_fd == i) blocker_index = j;
						if (client_list[j].logged_in && strcmp(client_list[j].ip, block_ip) == 0) blocked_index = j;
					}

					if (blocker_index != -1 && blocked_index != -1) {
						block_matrix[blocker_index][blocked_index] = 1;
					}
				}

				// 处理 UNBLOCK 报文
                else if (strncmp(recv_buf, "UNBLOCK|", 8) == 0) {
                    char unblock_ip[IPV4_ADDR_LEN];
                    sscanf(recv_buf + 8, "%s", unblock_ip);

                    // 更新阻塞矩阵
                    int unblocker_index = -1, unblocked_index = -1;
                    for (int j = 0; j < MAX_CLIENTS; ++j) {
                        if (client_list[j].socket_fd == i) unblocker_index = j;
                        if (client_list[j].logged_in && strcmp(client_list[j].ip, unblock_ip) == 0) unblocked_index = j;
                    }

                    if (unblocker_index != -1 && unblocked_index != -1) {
                        block_matrix[unblocker_index][unblocked_index] = 0;
                    }
                }
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
	if (client_socket != -1) {
        FD_SET(client_socket, &master);
    }

    int fd_max = (client_socket > STDIN_FILENO) ? client_socket : STDIN_FILENO;

    while (1) {
        read_fds = master;
        if (select(fd_max + 1, &read_fds, NULL, NULL, NULL) == -1){
            perror("select error");
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            char input[BUFFER_SIZE];
            fgets(input, BUFFER_SIZE, stdin);
            input[strcspn(input, "\n")] = '\0';
            handle_shell_command(input);

			// 若登录成功后建立连接，更新监听集
			if (client_socket != -1) {
                FD_SET(client_socket, &master);
                if (client_socket > fd_max)
                    fd_max = client_socket;
            }
        }

        // 处理服务器发来的消息
		if (client_socket != -1 && FD_ISSET(client_socket, &read_fds)) {
            char buf[BUFFER_SIZE] = {0};
            int nbytes = recv(client_socket, buf, sizeof(buf), 0);
            if (nbytes <= 0) {
                // 服务器关闭连接或出错
                close(client_socket);
                FD_CLR(client_socket, &master);
                client_socket = -1;
                continue;
            }

            // 判断是 REPLAYED 消息 还是 LIST 输出
            if (strncmp(buf, "RELAYED|", 8) == 0) {
                char sender_ip[IPV4_ADDR_LEN], msg[MAX_MSG_LEN];
                sscanf(buf, "RELAYED|%[^|]|%[^\n]", sender_ip, msg);
                cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");
                cse4589_print_and_log("msg from:%s\n[msg]:%s\n", sender_ip, msg);
                cse4589_print_and_log("[%s:END]\n", "RECEIVED");
            } else {
                // 其他情况当作 LIST 响应处理
                cse4589_print_and_log("[%s:SUCCESS]\n", "LIST");
                printf("%s", buf);
                cse4589_print_and_log("[%s:END]\n", "LIST");
            }
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
