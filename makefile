CC = gcc
CFLAGS = -Wall -g

p2: p2.o list.o memlist.o
	$(CC) -o p2 p2.o list.o memlist.o

clean: 
	rm -f list.o p2.o p2 memlist.o