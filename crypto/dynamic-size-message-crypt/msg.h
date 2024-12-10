#ifndef __MSG_H__
#define __MSG_H__

#include <openssl/aes.h>

#define AES_KEY_128 16
#define BUF_SIZE 256


typedef struct _APP_MSG_
{
  int type;
  // 가변 크기를 위해 포인터에 저장
  unsigned char payload[BUF_SIZE + AES_BLOCK_SIZE];
  int msg_len;
}APP_MSG;

#endif
