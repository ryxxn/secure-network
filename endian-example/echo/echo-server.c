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
  int serv_sock, clnt_sock;
  char message[BUF_SIZE + 1];
  int str_len, cnt_i;

  struct sockaddr_in serv_addr;
  struct sockaddr_in clnt_addr;
  socklen_t clnt_addr_size;

  if(argc != 2)
  {
    printf("Usage: %s <port>\n", argv[0]);
    exit(1);
  }

  serv_sock = socket(PF_INET, SOCK_STREAM, 0);
  if(serv_sock == -1)
    error_handling("socket() error");

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(atoi(argv[1]));

  if(bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    error_handling("bind() error");

  if(listen(serv_sock, 5) == -1)
    error_handling("listen() error");

  clnt_addr_size = sizeof(clnt_addr);

  for(cnt_i = 0; cnt_i < 5; cnt_i++) {
    clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
    if(clnt_sock == -1)
      error_handling("accept() error");
    else
      printf("Connected client %d \n", cnt_i + 1);

    while((str_len = read(clnt_sock, message, BUF_SIZE)) != 0)
    {
      write(clnt_sock, message, str_len);
    }

    close(clnt_sock);
  }

  close(serv_sock);

  return 0;
}

void error_handling(char *message)
{
  fputs(message, stderr);
  fputc('\n', stderr);
  exit(1);
}