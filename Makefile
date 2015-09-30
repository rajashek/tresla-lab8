CC = gcc
CFLAGS = -O2 -Wall
LFLAGS =
PTHREADFLAGS=-pthread
PCAPFLAGS=-lpcap

router: main.o interface.o utils.o config.o route.o arp.o sniffer.o
	$(CC) $(CFLAGS) $(PTHREADFLAGS) $(PCAPFLAGS) -o router main.o interface.o utils.o config.o route.o arp.o sniffer.o

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

interface.o: interface.c interface.h
	$(CC) $(CFLAGS) -c interface.c

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c utils.c

config.o: config.c config.h
	$(CC) $(CFLAGS) -c config.c

route.o: route.c route.h
	$(CC) $(CFLAGS) -c route.c

arp.o: arp.c arp.h
	$(CC) $(CFLAGS) -c arp.c

sniffer.o: sniffer.c sniffer.h
	$(CC) $(CFLAGS) $(PTHREADFLAGS) $(PCAPFLAGS) -c sniffer.c

clean:
	rm -f *.o router