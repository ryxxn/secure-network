/*
 * [목표]
 * - client_cal.c은 사용자로부터 2개의 정수를 입력받아 서버로 전송
 * - server_cal.c는 사용자로부터 전달받은 2개의 정수를 더하여 다시 반환
 * - 클라이언트는 서버로부터의 덧셈 결과를 출력
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

void error_handling(char *message){
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

int main(int argc, char* argv[])
{
  int serv_sock;
  int clnt_sock;
  int num1, num2, result;

  struct sockaddr_in serv_addr;
  struct sockaddr_in clnt_addr;
  socklen_t clnt_addr_size;

  if(argc != 2){
    printf("Usage : %s <port>\n", argv[0]);
    exit(1);
  }
  
  serv_sock = socket(PF_INET, SOCK_STREAM, 0);
  if (serv_sock == -1)
    error_handling("socket() error");

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(atoi(argv[1]));

  if (bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    error_handling("bind() error");

  if (listen(serv_sock, 5) == -1)
    error_handling("listen() error");

  clnt_addr_size = sizeof(clnt_addr);
  clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);

  if (clnt_sock == -1)
    error_handling("accept() error");

  // read two numbers from the connected client
  read(clnt_sock, &num1, sizeof(num1));
  read(clnt_sock, &num2, sizeof(num2));

  num1 = ntohl(num1);
  num2 = ntohl(num2);

  printf("Received two numbers: %d, %d\n", num1, num2);
  result = num1 + num2;
  result = htonl(result);

  write(clnt_sock, &result, sizeof(result));

  close(clnt_sock);
  close(serv_sock);

  return 0;
}
