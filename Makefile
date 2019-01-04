CC = gcc
COPTS = -Wall -fPIC -O0
LIBS = -lm -lssl -lcrypto 
DEBUG = -D  _DEBUG_OSSL_

COPTS += $(DEBUG)

all: net

net:
	$(CC) $(COPTS) -D_INSSL_DRIVER_ netssl.c $(LIBS)

web:
	$(CC) $(COPTS) webssl.c $(LIBS)

clean:
	rm -f *.o a.out 

