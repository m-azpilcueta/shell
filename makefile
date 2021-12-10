CC = gcc
CFLAGS = -Wall -g

shell: p3.o list.o memlist.o proclist.o
	$(CC) -o shell p3.o list.o memlist.o proclist.o

clean:
	rm -f list.o p3.o shell memlist.o proclist.o