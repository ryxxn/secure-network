/**
 * [목표]
 * accept() → read()/write() → close() 과정을 반복하여 다수의 클라이언트에게 Echo 서비스 제공
 * 서버는 클라이언트가 전송한 메시지를 전달받아, 그대로 다시 클라이언트에게로 전송
 * 클라이언트는 메시지를 입력받아 서버로 전송하고, 다시 서버가 전송한 메시지를 화면에 출력
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUF_SIZE 128
void error_handling(char *message);

int main(int argc, char* argv[])
{
  int sock;
  char message[BUF_SIZE + 1];
  int str_len, recv_len, recv_cnt;
  struct sockaddr_in serv_addr;

  if(argc != 3)
  {
    printf("Usage: %s <IP> <port>\n", argv[0]);
    exit(1);
  }

  sock = socket(PF_INET, SOCK_STREAM, 0);
  if(sock == -1)
    error_handling("socket() error");

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
  serv_addr.sin_port = htons(atoi(argv[2]));

  if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    error_handling("connect() error");
  else
    puts("Connected..........\n");

  recv_len = 0;
  while(recv_len < str_len)
  {
    recv_cnt = read(sock, &message[recv_len], BUF_SIZE );
    if(recv_cnt == -1)
      error_handling("read() error!");
    recv_len += recv_cnt;
  }

  message[recv_len] = '\0';
  printf("Message from server: %s\n", message);

  close(sock);
  return 0;
  
}

void error_handling(char *message)
{
  fputs(message, stderr);
  fputc('\n', stderr);
  exit(1);
}