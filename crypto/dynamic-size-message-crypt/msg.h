#ifndef __MSG_H__
#define __MSG_H__

#define AES_KEY_128 16
#define BUFSIZE 256

typedef struct _APP_MSG_
{
  int type;
  // 가변 크기를 위해 포인터에 저장
  unsigned char payload[BUFSIZE + AES_KEY_128];
  int msg_len;
}APP_MSG;

#endif
