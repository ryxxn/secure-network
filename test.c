#include <stdio.h>
#include <math.h>

void helloWorld();

int main(int argc, char* argv[])
{
	double num;

	printf("I want to say\n");
	helloWorld();

	printf("Input a number\n");
	scanf("%lf", &num);

	printf("sin: %lf\n", sin(num));
	
	return 0;
}
