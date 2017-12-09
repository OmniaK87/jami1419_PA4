CC = gcc

all: proxy

proxy:
	$(CC) -pthread -g -o proxy -lm proxy.c

clean:
	rm -f proxy
