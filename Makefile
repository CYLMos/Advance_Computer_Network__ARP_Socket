ARP: main.o arp.o
	gcc main.o arp.c -o main
	gcc arp.o main.c -o arp

main.o arp.o: main.c arp.c
	gcc -c main.c
	gcc -c arp.c

clean:
	rm -f *.o
