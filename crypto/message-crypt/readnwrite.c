#include "readnwrite.h"

ssize_t
readn(int fd, void* vptr, size_t n)
{
  ssize_t nleft;
  ssize_t nread;
  char* ptr;

  ptr = vptr;
  nleft = n;

  while (nleft > 0)
  {
    nread = read(fd, ptr, nleft);

    if (-1 == nread) return -1;
    else if (0 == nread) break;

    nleft -= nread;
    ptr += nread;
  }

  return (n - nleft);
}

ssize_t
writen(int fd, const void* vptr, size_t n)
{
  ssize_t nleft;
  ssize_t nwritten;
  const char* ptr;

  ptr = vptr;
  nleft = n;

  while (nleft > 0)
  {
    nwritten = write(fd, ptr, nleft);

    if (-1 == nwritten) return -1;

    nleft -= nwritten;
    ptr += nwritten;
  }

  return n;
}