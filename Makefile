CC = gcc
CFLAGS = -W -Wall -O2
LDFLAGS = -lm

all : test
test : test.c hello.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	@rm -rf *.o test
