// waitpid() 함수를 이용하여 좀비 프로세스 방지

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char* argv[]){

  pid_t pid = fork();
  int status;

  if (pid == 0)
  {
    sleep(15);
    return 24;
  }
  else
  {
    while(!waitpid(-1, &status, WNOHANG))
    {
      sleep(3);
      puts("I am working now");
    }

    if (WIFEXITED(status))
      printf("Child send %d\n", WEXITSTATUS(status));
  }

  return 0;
}