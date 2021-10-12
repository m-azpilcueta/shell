CC = gcc
CFLAGS = -Wall -g

p0: p0.o list.o 
	$(CC) -o p0 p0.o list.o

clean: 
	rm -f list.o p0.o p0