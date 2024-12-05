#include <stdio.h>
#include <unistd.h>
#include <signal.h>

void timeout(int sig)
{
  if (sig == SIGALRM)
    puts("Time out!");
  alarm(2);
}

void keycontrol(int sig)
{
  if (sig == SIGINT)
    puts("CTRL+C pressed");
}

int main(int argc, char* argv[]){

  int cnt_i;

  signal(SIGALRM, timeout);
  signal(SIGINT, keycontrol);
  alarm(2);

  for(cnt_i = 0; cnt_i < 3; cnt_i++)
  {
    puts("wait...");
    sleep(100);
  }

  return 0;
}