#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

void error_handling(char *msg)
{
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}

#define BUF_SIZE 	128

int main(int argc, char* argv[])
{
	int sock;
	struct sockaddr_in serv_addr;
	char message[BUF_SIZE+1];
	int str_len;
	
	if(argc != 3)
	{
		printf("Usage: %s <IP> <port> \n", argv[0]);
		exit(1);
	}
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if(sock == -1)
	{
		error_handling("socket() error");
	}
	
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));
	
	if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
	{
		error_handling("connect() error");
	}
	else{
		printf("Connented...........\n");
	}
	
	while(1)
	{
		printf("Input message(Q to quit): ");
		fgets(message, BUF_SIZE, stdin);
		if(!strcmp(message, "q\n") || !strcmp(message, "Q\n"))
		{
			break;
		}
		
		write(sock, message, strlen(message));
		str_len = read(sock, message, BUF_SIZE);
		message[str_len] = '\0';
		printf("Message from server: %s", message);
	}
	
	close(sock);
	
	return 0;
}
	
