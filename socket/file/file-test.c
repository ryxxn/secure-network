#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

void ErrorHandling(char* message);

void ErrorHandling(char* message) {
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

int main(void)
{
    int fd1, fd2, fd3;
    char buf[] = "Hello, Class!\n";

    fd1 = socket(PF_INET, SOCK_STREAM, 0);
    if(fd1 == -1){
        ErrorHandling("socket() error");
    }

    fd2 = open("test.txt", O_CREAT|O_WRONLY|O_TRUNC, S_IRWXU);
    if(fd2 == -1){
        ErrorHandling("open() error");
    }

    fd3 = socket(PF_INET, SOCK_DGRAM, 0);
    if(fd3 == -1){
        ErrorHandling("open() error");
    }

    printf("file descriptor 1: %d\n", fd1);
    printf("file descriptor 2: %d\n", fd2);
    printf("file descriptor 3: %d\n", fd3);

    if(write(fd2, buf, sizeof(buf)) == -1){
        ErrorHandling("write() error");
    }

    close(fd1);
    close(fd2);
    close(fd3);

    fd2 = open("test.txt", O_RDONLY);
    if(fd2 == -1){
        ErrorHandling("open() error");
    }

    printf("file descriptor 2: %d\n", fd2);

    if(read(fd2, buf, sizeof(buf)) == -1){
        ErrorHandling("read() error");
    }

    printf("file data: %s", buf);

    close(fd2);

    return 0;
}