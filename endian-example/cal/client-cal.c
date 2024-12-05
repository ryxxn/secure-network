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
  int sock;
  struct sockaddr_in serv_addr;
  int num1, num2, result;

  if (argc != 3){
    printf("Usage: %s <IP> <port>\n", argv[0]);
    exit(1);
  }

  sock = socket(PF_INET, SOCK_STREAM, 0);

  if (sock == -1)
    error_handling("socket() error");

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
  serv_addr.sin_port = htons(atoi(argv[2]));

  if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    error_handling("connect() error");
  
  printf("Input two numbers to be added: \n");
  scanf("%d %d", &num1, &num2);
  printf("%d + %d = ", num1, num2);

  num1 = htonl(num1);
  num2 = htonl(num2);

  write(sock, &num1, sizeof(num1));
  write(sock, &num2, sizeof(num2));

  read(sock, &result, sizeof(result));

  result = ntohl(result);

  printf("%d\n", result);

  close(sock);

  return 0;
}