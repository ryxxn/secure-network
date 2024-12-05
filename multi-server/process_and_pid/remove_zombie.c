#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

void read_childproc(int sig)
{
	int status;
	pid_t id = waitpid(-1, &status, WNOHANG);
	if(WIFEXITED(status))
	{
		printf("Removed proc id : %d\n", id);
		printf("Child send %d\n", WEXITSTATUS(status));
	}
}

int main(int argc, char* argv[])
{
	int cnt_i;
	pid_t pid;
	struct sigaction act;
	act.sa_handler = read_childproc;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGCHLD, &act, 0);

	pid = fork();
	if(pid == 0)
	{
		printf("Hi, I am a child process\n");
		sleep(10);
		return 12;
	}
	else
	{
		printf("Child PID: %d\n", pid);
		pid = fork();
		if(pid == 0)
		{
			printf("Hi, I am a child process\n");
			sleep(15);
			exit(24);
		}
		else
		{
			printf("Child PID: %d\n", pid);
			for(cnt_i = 0; cnt_i < 8; cnt_i++)
			{
				puts("wait...");
				sleep(5);
			}
		}
	}
	return 0;
}