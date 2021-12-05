CC = gcc
CFLAGS = -Wall -g

p3: p3.o list.o memlist.o proclist.o
	$(CC) -o p3 p3.o list.o memlist.o proclist.o

clean:
	rm -f list.o p3.o p3 memlist.o proclist.o