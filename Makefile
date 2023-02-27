CC = gcc
CFLAGS = -fPIC -Wall -g

.PHONY: build
build: aws

aws: http_parser_g.o
	$(CC) -g aws.c sock_util.c http_parser_g.o -o aws -laio

http_parser_g.o:
	$(CC) $(CFLAGS) -o http_parser_g.o -c http_parser.c

.PHONY: clean
clean:
	-rm -f http_parser_g.o aws