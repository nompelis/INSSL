/******************************************************************************
 Code to do SSL server/client stuff using OpenSSL

 Copyright 2018-2019 by Ioannis Nompelis

 Ioannis Nompelis <nompelis@nobelware.com> 2019/03/27
 ******************************************************************************/

#ifndef _INSSL_H_
#define _INSSL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <math.h>
#include <sys/time.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>


/*
 * The structure that holds all the information for a server/client using SSL
 */

struct inOSSL_data_s {
   SSL_CTX *sslctx;
   SSL_METHOD *method;
   struct sockaddr_in addr;
   int socket;
   int port;
   X509 *client_cert;
};


/*
 * function prototypes
 */

int inOSSL_InitializeSSL();

void inOSSL_DestroySSL();

void inOSSL_ShutdownSSLSession( SSL *p );

int inOSSL_LoadCertificates( SSL_CTX *ctx, char *certfile, char *keyfile );

int inOSSL_LoadCertificatesMem( SSL_CTX *ctx,
                                unsigned char *certdata, int clen,
                                unsigned char *keydata, int klen, int npk );

int inOSSL_CreateServer( struct inOSSL_data_s *p,
                         char *keyfile, char *certfile );

int inOSSL_CreateServerMemory( struct inOSSL_data_s *p,
                               unsigned char *keydata, int klen,
                               unsigned char *certdata, int clen );

int inOSSL_TerminateServer( struct inOSSL_data_s *p );

int inOSSL_StartServer( struct inOSSL_data_s *p, int iport );

X509* inOSSL_GetCertificate( SSL *ssl );

void inOSSL_ShowCertificate( X509 *cert );

int inOSSL_CreateClient( struct inOSSL_data_s *p,
                         char *keyfile, char *certfile );

int inOSSL_TerminateClient( struct inOSSL_data_s *p );

int inOSSL_ConnectToServer( const char *hostname, int iport );

void inOSSL_QueryVerifyResult( long result );


#endif

