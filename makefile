CC = gcc
CFLAGS = -Wall -g

p1: p1.o list.o 
	$(CC) -o p1 p1.o list.o

clean: 
	rm -f list.o p1.o p1