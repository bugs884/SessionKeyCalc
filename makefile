CC =gcc
CFLAGS =-g -Wall -lmbedcrypto -w

default: all

all: main.c
	$(CC) -o nwksintkeys main.c $(CFLAGS)	

