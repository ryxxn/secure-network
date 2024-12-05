#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "readnwrite.h"
#include "aesenc.h"
#include "msg.h"

void error_handling(char *message)
{
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

int main(int argc, char *argv[])
{
  int cnt_i;
  int serv_sock = -1;
  int clnt_sock = -1;

  struct sockaddr_in serv_addr;
  struct sockaddr_in clnt_addr;
  socklen_t clnt_addr_size;

  APP_MSG msg_in;
  APP_MSG msg_out;

  char plaintext[BUF_SIZE + AES_BLOCK_SIZE] = {0x00, };
  int n;
  int len;
  int plaintext_len;
  int ciphertext_len;

  unsigned char key[AES_KEY_128] = {0x00, };
  unsigned char iv[AES_KEY_128] = {0x00, };

  for (cnt_i = 0; cnt_i < AES_KEY_128; cnt_i++)
  {
    key[cnt_i] = (unsigned char)cnt_i;
    iv[cnt_i] = (unsigned char)cnt_i;
  }

  if (argc != 2)
  {
    printf("Usage: %s <port>\n", argv[0]);
    exit(1);
  }

  serv_sock = socket(PF_INET, SOCK_STREAM, 0);
  if (serv_sock == -1)
  {
    error_handling("socket() error");
  }

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(atoi(argv[1]));

  if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
  {
    error_handling("bind() error");
  }

  if (listen(serv_sock, 5) == -1)
  {
    error_handling("listen() error");
  }

  while(1)
  {
    clnt_addr_size = sizeof(clnt_addr);
    clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);

    if(clnt_sock == -1)
    {
      error_handling("accept() error");
    }

    printf("\n[TCP SERVER] client connected: IP=%s, port=%d\n", inet_ntoa(clnt_addr.sin_addr), ntohs(clnt_addr.sin_port));

    // data communication with the connected client
    while(1)
    {
      n = readn(clnt_sock, (char *)&msg_in, sizeof(APP_MSG));

      if (n == -1){
        error_handling("readn() error");
      }
      else if (n == 0){
        break;
      }

      msg_in.msg_len = ntohl(msg_in.msg_len);

      printf("\n encruptedMsg: \n");
      BIO_dump_fp(stdout, (const char *)msg_in.payload, msg_in.msg_len);

      plaintext_len = decrypt((unsigned char *)msg_in.payload, msg_in.msg_len, key, iv, (unsigned char *)plaintext);

      printf("\n decryptedMsg: \n");

      BIO_dump_fp(stdout, (const char *)plaintext, plaintext_len);

      // print the received message
      plaintext[plaintext_len] = '\0';
      printf("%s\n", plaintext);

      //
      printf("Input a message > \n");
      if(fgets(plaintext, BUF_SIZE+1, stdin) == NULL) break;

      // removing '\n' character
      len = strlen(plaintext);
      if (plaintext[len-1] == '\n') plaintext[len-1] = '\0';

      if(strlen(plaintext) == 0) break;

      ciphertext_len = encrypt((unsigned char*)plaintext, len, key, iv, msg_out.payload);
      msg_out.msg_len = htonl(ciphertext_len);

      n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
      if (n == -1){
        error_handling("writen() error");
        break;
      }
    }
    close(clnt_sock);
    printf("[TCP SERVER] client disconnected: IP=%s, port=%d\n", inet_ntoa(clnt_addr.sin_addr), ntohs(clnt_addr.sin_port));
  }

  close(serv_sock);
  return 0;
}