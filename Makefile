CC = gcc
COPTS = -Wall -fPIC -O0 -D  _OUTPUT_OSSL_
LIBS = -lm -lssl -lcrypto 
DEBUG = -D  _DEBUG_OSSL_

################ use your own OpenSSL library ####################
### set the environment variable "OPENSSL_LIB_PATH" in the shell
MY_DIR = .
MY_DIR = ${OPENSSL_LIB_PATH}
COPTS += -I $(MY_DIR)/include
LOPTS = -L $(MY_DIR)/lib -Wl,-rpath=$(MY_DIR)/lib

COPTS += $(DEBUG)

all: net

net:
	$(CC) $(COPTS) -D_INSSL_DRIVER_ netssl.c $(LOPTS) $(LIBS)

web:
	$(CC) $(COPTS) -c netssl.c
	$(CC) $(COPTS) webssl.c netssl.o $(LIBS)


clean:
	rm -f *.o a.out 

