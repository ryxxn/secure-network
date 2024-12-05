#ifndef __MSG_H__
#define __MSG_H__

#include <openssl/aes.h>

#define AES_KEY_128 16
#define BUFSIZE 256

typedef struct _APP_MSG_
{
  int type;
  unsigned char payload[BUFSIZE + AES_BLOCK_SIZE];
  int msg_len;
}APP_MSG;

#endif
