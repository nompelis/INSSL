CC = gcc
COPTS = -Wall -fPIC -O0
LIBS = -lm -lssl -lcrypto 
DEBUG = -D  _DEBUG_OSSL_

COPTS += $(DEBUG)

net:
	$(CC) $(COPTS) netssl.c $(LIBS)

web:
	$(CC) $(COPTS) webssl.c $(LIBS)

clean:
	rm -f *.o a.out 

