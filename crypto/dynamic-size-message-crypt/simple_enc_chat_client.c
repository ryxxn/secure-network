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
  int sock;
  struct sockaddr_in serv_addr;
  int len;

  char plaintext[BUFSIZE + AES_BLOCK_SIZE] = {0x00, };

  unsigned char key[AES_KEY_128] = {0x00, };
  unsigned char iv[AES_KEY_128] = {0x00, };

  APP_MSG msg_in, msg_out;

  int n;
  int plaintext_len;
  int ciphertext_len;

  for (cnt_i = 0; cnt_i < AES_KEY_128; cnt_i++)
  {
    key[cnt_i] = (unsigned char)cnt_i;
    iv[cnt_i] = (unsigned char)cnt_i;
  }

  if (argc != 3)
  {
    printf("Usage: %s <IP> <PORT>\n", argv[0]);
    exit(1);
  }

  sock = socket(PF_INET, SOCK_STREAM, 0);
  if (sock == -1)
  {
    error_handling("socket() error");
  }

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
  serv_addr.sin_port = htons(atoi(argv[2]));

  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
  {
    error_handling("connect() error");
  }

  while(1)
  {
    // input a message
    printf("Input a message > \n");
    if(fgets(plaintext, BUFSIZE, stdin) == NULL)
      break;

    // removing '\n' character
    len = strlen(plaintext);
    if(plaintext[len - 1] == '\n')
      plaintext[len - 1] = '\0';

    if(strlen(plaintext) == 0)
      break;

    memset(&msg_out, 0, sizeof(msg_out));

    ciphertext_len = encrypt((unsigned char *)plaintext, strlen(plaintext), key, iv, msg_out.payload);
    msg_out.msg_len = htonl(ciphertext_len);

    // sending the inputed message
    n = writen(sock, &msg_out, sizeof(APP_MSG));
    if (n == -1){
      error_handling("write() error");
      break;
    }

    // receiving a message from the server
    n = readn(sock, &msg_in, sizeof(APP_MSG));
    if (n == -1){
      error_handling("read() error");
      break;
    }
    else if (n == 0){
      break;
    }

    msg_in.msg_len = ntohl(msg_in.msg_len);

    printf("\n* encryptedMsg: \n");
    BIO_dump_fp(stdout, (const char*)msg_in.payload, msg_in.msg_len);

    plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);

    printf("\n* decryptedMsg: \n");
    BIO_dump_fp(stdout, (const char*)plaintext, plaintext_len);

    plaintext[plaintext_len] = '\0';
    printf("%s\n", plaintext);
  }

  close(sock);
  return 0;
}
