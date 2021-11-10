CC = gcc
CFLAGS = -Wall -g

p2: p2.o list.o 
	$(CC) -o p2 p2.o list.o

clean: 
	rm -f list.o p2.o p2