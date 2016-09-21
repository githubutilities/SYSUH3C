CC=gcc
LIBS= -lpcap 
CFLAGS=-Wall

sysuh3c: main.o
	$(CC) $(CFLAGS) $+ $(LIBS) -o $@

main: main.c
	$(CC) $(CFLAGS) -c $<
