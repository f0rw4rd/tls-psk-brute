CC=gcc
CFLAGS=-Wall -O2
LIBS=-lssl -lcrypto

all: full_psk_server full_psk_client tls_psk_bruteforce

full_psk_server: full_psk_server.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

full_psk_client: full_psk_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

tls_psk_bruteforce: tls_psk_bruteforce.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f full_psk_server full_psk_client tls_psk_bruteforce *.o

.PHONY: all clean