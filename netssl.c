/******************************************************************************
 Code to do SSL server/client stuff using OpenSSL

 Copyright 2018-2021 by Ioannis Nompelis

 Ioannis Nompelis <nompelis@nobelware.com> 2019/03/27 - 2021/12/20
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <math.h>
#include <sys/time.h>
#include <time.h>

#include "inSSL.h"


/*
 * Function to initialize the OpenSSL library
 * (A lot of predefined constants seem to be created here...)
 */

int inOSSL_InitializeSSL()
{
   int ierr;
   char FUNC[] = "inOSSL_InitializeSSL";

#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Loading all algorithms \n", FUNC );
#endif
   OpenSSL_add_all_algorithms();
#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Loading various SSL library strings \n", FUNC );
#endif
   SSL_load_error_strings();
   ERR_load_BIO_strings();
   ERR_load_crypto_strings();

#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Initializing the SSL library \n", FUNC );
#endif
   ierr = SSL_library_init();
   if( ierr < 0 ) {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Could not initialize the SSL library \n", FUNC );
#endif
      return 1;
   }

   return 0;
}


/*
 * Function to terminate the OpenSSL library
 * (I have no idea what is being cleaned up here...)
 */

void inOSSL_DestroySSL()
{
   ERR_free_strings();
   EVP_cleanup();
}


/*
 * Function to shutdown an SSL session.
 * This routine should be called every time a particular session is to terminate
 * such that the SSL session pointer is cleaned up. It performs a two-step
 * shutdown procedure as per the manual page. (I have not encountered any
 * issues with sessions needing two steps to close, but the man page says that
 * the two-step procedure with checking the return code is preferred.)
 */

void inOSSL_ShutdownSSLSession( SSL *p )
{
   char FUNC[] = "inOSSL_ShutdownSSLSession";
   int ierr,n,nmax=10;

   if( p == NULL ) {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  The SSL session pointer is null!\n", FUNC );
#endif
      return;
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Shutting down the SSL session \n", FUNC );
#endif
   }

   n = 0;
   while( n < nmax ) {
      ierr = SSL_shutdown( p );
      if( ierr == 0 ) {
#ifdef _DEBUG_OSSL_
         fprintf( stdout, " [%s]  Shutdown return %d; will call again \n",
                  FUNC, ierr );
#endif
      } else if( ierr == 1 ) {
#ifdef _DEBUG_OSSL_
         fprintf( stdout, " [%s]  Shutdown return %d; completed \n",
                  FUNC, ierr );
#endif
         n = nmax;
      } else {
#ifdef _DEBUG_OSSL_
         fprintf( stdout, " [%s]  Shutdown return %d; failed\n",
                  FUNC, ierr );
#endif
         n = nmax;
      }
      ++n;
   }

#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Freeing structure \n", FUNC );
#endif
   SSL_free( p );

   return;
}


/*
 * Function to load the private key and the corresponding certificate into
 * the SSL context structure.
 *
 * This function seems to be needed by the "server" that will be serving to
 * clients, and they need to verify its certificate. (Lots of ambiguity here.)
 * Results are never internally fatal unless the certificate/key files are not
 * found. The context can continue to work with no certificates, apparently,
 * but I do not know what happens then.
 */

int inOSSL_LoadCertificates( SSL_CTX *ctx, char *certfile, char *keyfile )
{
   char FUNC[] = "inOSSL_LoadCertificates";
   int iret;
#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Loading certificates \n", FUNC );
#endif

#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Loading certificate: \"%s\" \n", FUNC, keyfile );
#endif
   iret = SSL_CTX_use_certificate_file( ctx, certfile, SSL_FILETYPE_PEM );
   if( iret <= 0 ) {
      fprintf( stdout, " [%s]  Could not load certificate file: \'%s\" \n",
               FUNC, certfile );
      ERR_print_errors_fp( stdout );
      return(-1);
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Loaded certificate file: \"%s\" \n",
               FUNC, certfile );
#endif
   }

#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Loading key: \"%s\" \n", FUNC, keyfile );
#endif
   iret = SSL_CTX_use_PrivateKey_file( ctx, keyfile, SSL_FILETYPE_PEM );
   if( iret <= 0 ) {
      fprintf( stdout, " [%s]  Could not load private key file: \'%s\" \n",
               FUNC, keyfile );
      ERR_print_errors_fp( stdout );
      // unload certfile here?
      return(-2);
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Loaded private key from file: \"%s\" \n",
               FUNC, keyfile );
#endif
   }

   if( !SSL_CTX_check_private_key( ctx ) ) {
      fprintf( stdout, " [%s]  Private key does not match the public certificate\n", FUNC );
      // unload certfile/privkey here?
      return(1);
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Private key matches certificate \n", FUNC );
#endif
   }

   return 0;
}


/*
 * Function to load the private key and the corresponding certificate from
 * embedded binary representations to the SSL context structure.
 * This function works the same way as the file-based one, but uses memory
 * segments such that certificates can be embedded to executable/library code.
 * One argument specifies the type of the key.
 */

int inOSSL_LoadCertificatesMem( SSL_CTX *ctx,
                                unsigned char *certdata, int clen,
                                unsigned char *keydata, int klen )
{
   char FUNC[] = "inOSSL_LoadCertificatesMem";
   int iret;
#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Loading certificates from memory segments\n",FUNC);
#endif

   if( certdata == NULL || keydata == NULL ) {
      fprintf( stdout, " [%s]  Certificate data is null \n", FUNC );
      return(2);
   }

   iret = SSL_CTX_use_certificate_ASN1( ctx, clen, certdata );
   if( iret <= 0 ) {
      fprintf( stdout, " [%s]  Could not load certificate chunk (size= %d)\n",
               FUNC, clen );
      ERR_print_errors_fp( stdout );
      return(-1);
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Loaded certificate chunk (size= %d)\n",
               FUNC, clen );
#endif
   }

   iret = SSL_CTX_use_RSAPrivateKey_ASN1( ctx, keydata, klen );
   if( iret <= 0 ) {
      fprintf( stdout, " [%s]  Could not load private key chunk (size=%d)\n",
               FUNC, klen );
      ERR_print_errors_fp( stdout );
      // unload certfile here?
      return(-2);
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Loaded private key chunk (size=%d)\n",
               FUNC, klen );
#endif
   }

   if( !SSL_CTX_check_private_key( ctx ) ) {
      fprintf( stdout, " [%s]  Private key does not match the public certificate\n", FUNC );
      // unload certfile/privkey here?
      return(1);
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Private key matches certificate \n", FUNC );
#endif
   }

   return 0;
}


/*
 * Function to create an SSL "server"
 *
 * This function creates an SSL context by using select methods and loads the
 * certificates that it needs to allow for the clients to perform verification
 * of the server's identity. It loads the certificate and its key from files.
 */

int inOSSL_CreateServerFromFiles( struct inOSSL_data_s *p,
                                  char *keyfile, char *certfile )
{
   char FUNC[] = "inOSSL_CreateServerFromFiles";
   int iret;

#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Creating SSL server \n", FUNC );
#endif

// p->method = SSLv2_server_method();
// p->method = SSLv3_server_method();
// p->method = TLSv1_server_method();
// p->method = TLSv1_1_server_method();
// p->method = TLSv1_2_server_method();
   p->method = DTLS_server_method();
   p->sslctx = SSL_CTX_new( p->method );

   if( p->sslctx == NULL ) {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  Could not create SSL server context \n", FUNC );
      ERR_print_errors_fp( stdout );
#endif
      return(-1);
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Created SSL server context \n", FUNC );
#endif
   }

   if( SSL_CTX_load_verify_locations( p->sslctx, p->ca_cert, p->ca_path ) ) {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  Could not open CA file \n", FUNC );
#endif
      return(-2);
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Loaded trusted CA certificates \n", FUNC );
#endif
   }

   SSL_CTX_set_options( p->sslctx, SSL_OP_NO_SSLv2 );

   iret = inOSSL_LoadCertificates( p->sslctx, certfile, keyfile );
   if( iret != 0 ) {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  There was a problem with the SSL certificates\n", FUNC );
#endif
      // clean context before returning
      SSL_CTX_free( p->sslctx );
      return(1);
   }

   return 0;
}


/*
 * Function to create an SSL "server"
 *
 * This function creates an SSL context by using select methods and loads the
 * certificates that it needs to allow for the clients to perform verification
 * of the server's identity. It loads the certificate and its key from memory.
 */

int inOSSL_CreateServerFromMemory( struct inOSSL_data_s *p,
                                   unsigned char *keydata, int klen,
                                   unsigned char *certdata, int clen )
{
   char FUNC[] = "inOSSL_CreateServerFromMemory";
   int iret;

#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Creating SSL server \n", FUNC );
#endif

// p->method = SSLv2_server_method();
// p->method = SSLv3_server_method();
// p->method = SSLv23_server_method();
// p->method = TLSv1_server_method();
// p->method = TLSv1_1_server_method();
// p->method = TLSv1_2_server_method();
   p->method = DTLS_server_method();
   p->sslctx = SSL_CTX_new( p->method );

   if( p->sslctx == NULL ) {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  Could not create SSL server context \n", FUNC );
      ERR_print_errors_fp( stdout );
#endif
      return(-1);
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Created SSL server context \n", FUNC );
#endif
   }

   if( SSL_CTX_load_verify_locations( p->sslctx, p->ca_cert, p->ca_path ) ) {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  Could not open CA file \n", FUNC );
#endif
      return(-2);
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Loaded trusted CA certificates \n", FUNC );
#endif
   }

   SSL_CTX_set_options( p->sslctx, SSL_OP_NO_SSLv2 );

   iret = inOSSL_LoadCertificatesMem( p->sslctx, certdata, clen, keydata, klen);
   if( iret != 0 ) {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  There was a problem with the SSL certificates\n", FUNC );
#endif
      // clean context before returning
      SSL_CTX_free( p->sslctx );
      return(1);
   }

   return 0;
}


/*
 * Function to terminate and clean-up an SSL server context
 * This is a clean-up function with little functionality...
 */

int inOSSL_TerminateServer( struct inOSSL_data_s *p )
{
   // check for validity of SSL context and return error...
   if( p == NULL ) return(1);

   // terminate SSL context (possibly clean-up certificates?)
   SSL_CTX_free( p->sslctx );

   return(0);
}


/*
 * Function to create a listening INET socket
 *
 * This function is NOT needed for OpenSSL, but because I may need a server
 * socket over which to run a secure transport layer, I have this simple INET
 * socket binding/llstening function here.
 */

int inOSSL_StartServer( struct inOSSL_data_s *p, int iport, int num_backlog )
{
   char FUNC[] = "inOSSL_StartServer";
   int sd;
   int iret;

#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Starting INET server \n", FUNC );
#endif

   // create a listening a socket
   sd = socket(PF_INET, SOCK_STREAM, 0);
   bzero(&(p->addr), sizeof(p->addr));
   p->addr.sin_family = AF_INET;
   p->addr.sin_port = htons( iport );
   p->addr.sin_addr.s_addr = INADDR_ANY;
   iret = bind( sd, (struct sockaddr *) &(p->addr), sizeof(p->addr) );
   if(iret != 0 ) {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  Could not bind() the socket to port: %d \n",
               FUNC, iport );
      perror("bind to port");
#endif
      return(-1);
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Successfully bind() socket to port: %d \n",
               FUNC, iport );
#endif
   }

   iret = listen( sd, num_backlog );
   if( iret != 0 ) {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  Could not listen() on socket \n", FUNC );
      perror("Cannot configure listening port");
#endif
      // close socket
      close( sd );
      return(-2);
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Successfully listen()ing on socket \n", FUNC );
#endif
   }

   // assign the socket file descriptor to the server structure
   p->socket = sd;
   // also return the socket descriptor number
   return( sd );
}


/*
 * Function to retrieve the _peer's_ certificate(s)
 *
 * I do not know exactly what this function does, but it wants to look at only
 * the peer's certificates and reports "NO certificate" if called by an SSL
 * "server" setup; this is not a bad thing. (This is to be explored...)
 */

X509* inOSSL_GetCertificate( SSL *ssl )
{
#ifdef _OUTPUT_OSSL_
   char FUNC[] = "inOSSL_GetCertificate";
#endif
   X509 *cert;

   // get the certificate if it is available
   cert = SSL_get_peer_certificate( ssl );
   if( cert != NULL ) {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  Retrieved server certificate\n", FUNC );
#endif
   } else {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  No certificates\n",  FUNC );
#endif
      return( NULL );
   }

   return( cert );
}


/*
 * Function to show a certificate
 *
 * This function shows the name, issuer and serial number of the certificate.
 * It also checks if the certificate is a CA certificate and prints that info.
 * (This function helps the user in knowing what is going on.)
 */

void inOSSL_ShowCertificate( X509 *cert )
{
   char FUNC[] = "inOSSL_ShowCertificate";
   char *line;
   int raw;
   ASN1_INTEGER *serial;
   BIGNUM *bn;
   char *serial_ascii;

   if( cert == NULL ) {
      fprintf( stdout, " [%s]  Certificate pointer is null \n", FUNC );
      return;
   }

   fprintf( stdout, " [%s]  Server certificate:\n", FUNC );
   line = X509_NAME_oneline( X509_get_subject_name( cert ), NULL, 0 );
   fprintf( stdout, " [%s]  Subject: %s\n", FUNC, line );
   free( line );
   line = X509_NAME_oneline( X509_get_issuer_name( cert ), NULL, 0 );
   fprintf( stdout, " [%s]  Issuer: %s\n", FUNC, line );
   free( line );

   // get the certificate's serial number and display it 
   serial = X509_get_serialNumber(cert);  // get internal pointer; don't free
   bn = ASN1_INTEGER_to_BN(serial, NULL); // makes new BN object
   serial_ascii = BN_bn2dec(bn);          // get pointer to new char object
   BN_free( bn );                         // drop the big-number object
   fprintf( stdout, " [%s]  Certificate's serial num. \"%s\"\n",
            FUNC, serial_ascii );
   free( serial_ascii );                  // drop the string

   // provide some info about the certificate
   fprintf( stdout, " [%s]  ", FUNC );
   raw = X509_check_ca( cert );
/// Here is the manual page on what to expect:
///    Function return 0, if it is not CA certificate, 1 if it is proper
///    X509v3 CA certificate with basicConstraints extension CA:TRUE, 3, if it
///    is self-signed X509 v1 certificate, 4, if it is certificate with
///    keyUsage extension with bit keyCertSign set, but without
///    basicConstraints, and 5 if it has outdated Netscape Certificate Type
///    extension telling that it is CA certificate.
///    Actually, any non-zero value means that this certificate could have
///    been used to sign other certificates.
   if( raw == 0 ) {
      fprintf( stdout, "   This is not a CA certificate \n");
   } else if( raw == 1 ) {
      fprintf( stdout, "   This is an X.509 v3 CA certificate with basicConstraints extension CA:TRUE \n");
   } else if( raw == 3 ) {
      fprintf( stdout, "   This is a self-signed X.509 v1 certificate \n");
   } else if( raw == 4 ) {
      fprintf( stdout, "   This is a certificate with keyUsage extension with bit keyCertSign set, but without basicConstraints \n");
   } else if( raw == 5 ) {
      fprintf( stdout, "   This is a certificate with an outdated Netscape Certificate Type extension telling that it is a CA certificate \n");
   } else {
      fprintf( stdout, "   (Negative value) This is just unknown \n");
   }
}


/*
 * Function to create an SSL "client"
 *
 * This function creates an SSL context by using select methods and loads the
 * certificates that it needs to securely connect to a trusted SSL server and
 * verify the server's identity.
 *
 * NOTE: this is how I will get a certificate from memory
 * "const unsigned char *data = ... ;"
 * "size_t len = ... ;"
 * "X509 *cert = d2i_X509(NULL, &data, len);"
 */

int inOSSL_CreateClient( struct inOSSL_data_s *p, char *keyfile, char *certfile)
{
   char FUNC[] = "inOSSL_CreateClient";
#ifdef _DEBUG_OSSL_
   fprintf( stdout, " [%s]  Creating SSL client \n", FUNC );
#endif

// p->method = SSLv2_client_method();
// p->method = SSLv3_client_method();
// p->method = SSLv23_client_method();
// p->method = TLSv1_client_method();
// p->method = TLSv1_1_client_method();
// p->method = TLSv1_2_client_method();
// p->method = TLSv1_3_client_method();
   p->method = DTLS_client_method();
   p->sslctx = SSL_CTX_new( p->method );

   if( p->sslctx == NULL ) {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  Could not create SSL client context \n", FUNC );
      ERR_print_errors_fp( stdout );
#endif
      return(-1);
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Created SSL client context \n", FUNC );
#endif
   }

   if( p->ca_cert != NULL ) {
      if( SSL_CTX_load_verify_locations( p->sslctx, p->ca_cert, p->ca_path ) ) {
#ifdef _OUTPUT_OSSL_
         fprintf( stdout, " [%s]  Could not open CA file \n", FUNC );
#endif
         return(-2);
      } else {
#ifdef _DEBUG_OSSL_
         fprintf( stdout, " [%s]  Loaded trusted CA certificates \n", FUNC );
#endif
      }
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Not loading trusted CA certificates \n", FUNC );
#endif
   }

   SSL_CTX_set_options( p->sslctx, SSL_OP_NO_SSLv2 );

   p->client_cert = NULL;
   return 0;    // skip loading the known certificate

   // TEMPORARY load a certificate from a file with no error-trapping
   // this is temporary
   FILE *fp = fopen( certfile, "r" );
   p->client_cert = PEM_read_X509( fp, NULL, NULL, NULL);
   fclose( fp );

   return 0;
}


/*
 * Function to terminate and clean-up an SSL client context
 * This is a clean-up functions with little functionality...
 */

int inOSSL_TerminateClient( struct inOSSL_data_s *p )
{
   // check for validity of SSL context and return error...
   if( p == NULL ) return(1);

   // drop client certificate if we have loaded one
   if( p->client_cert != NULL ) {
     X509_free( p->client_cert );
   }

   // terminate SSL context (possibly clean-up certificates?)
   SSL_CTX_free( p->sslctx );

   return(0);
}


/*
 * Function that connects to a listening (server) socket
 * (This function is what a client executes to connect to a server)
 */

int inOSSL_ConnectToServer( const char *hostname, int iport, int flag )
{
   char FUNC[] = "inOSSL_ConnectToServer";
   int sd;
   struct hostent *host;
   struct sockaddr_in addr;
   int iret;


   host = gethostbyname( hostname );
   if( host == NULL ) {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  Could not get host structure \n", FUNC );
      perror(hostname);
#endif
      return(-1);
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Prepared hostname structure \n", FUNC );
#endif
   }

   if( flag ) { 
      sd = socket( PF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0 );
   } else {
      sd = socket( PF_INET, SOCK_STREAM, 0 );    // blocking socket
   }
   if( sd == -1 ) {
#ifdef _OUTPUT_OSSL_
      fprintf( stdout, " [%s]  Could not create INET socket \n", FUNC );
      perror("socket creation failed");
#endif
   } else {
#ifdef _DEBUG_OSSL_
      fprintf( stdout, " [%s]  Created INET socket \n", FUNC );
#endif
   }

   bzero(&addr, sizeof(addr));
   addr.sin_family = AF_INET;
   addr.sin_port = htons( iport );
   addr.sin_addr.s_addr = *(long*)(host->h_addr);

   iret = connect( sd, (struct sockaddr *) &addr, sizeof(addr) );
   if( flag ) {    // for non-blocking sockets
      // Need to check whether the connected socket is _writeable_, as we are
      // assuming that we intend to write to the socket; checking whether the
      // socket is readable makes no sense, because we cannot expect that the
      // other side is necessarily going to write data to us upon connecting.

      fd_set fds;
      struct timeval tv;

      FD_ZERO( &fds );
      FD_SET( sd, &fds );
      tv.tv_sec = 10;     // wait up to 10 seconds for connection
      tv.tv_usec = 0;

      if( iret != 0 ) {
         if( errno == EINPROGRESS ) {
#ifdef _OUTPUT_OSSL_
            fprintf( stdout, " [%s]  Socket \"in progress\" \n", FUNC );
            perror(hostname);
#endif
            // check for writeability
            iret = select( sd+1, NULL, &fds, NULL, &tv );
            if( iret < 0 ) {
#ifdef _OUTPUT_OSSL_
               fprintf( stdout, " [%s]  Could not connect to server \n", FUNC );
               perror(hostname);
#endif
               return -2;
            } else if( iret == 0 ) {
#ifdef _OUTPUT_OSSL_
               fprintf( stdout, " [%s]  Timetout connect to server \n", FUNC );
               perror(hostname);
#endif
               return -2;
            } else {
#ifdef _DEBUG_OSSL_
               fprintf( stdout, " [%s]  Connected (NonBlk) to server \n", FUNC);
#endif
            }
         } else {
#ifdef _OUTPUT_OSSL_
            fprintf( stdout, " [%s]  Unknown socket error \n", FUNC );
            perror(hostname);
#endif
         }
      } else {
         // this should NEVER happen
#ifdef _OUTPUT_OSSL_
         fprintf( stdout, " [%s]  Connection established (no drama?)\n", FUNC );
         fprintf( stdout, "  **** Something is rong here... **** \n" );
         fprintf( stdout, "  Call to connect() should return error first, \n" );
         fprintf( stdout, "  and we should check descriptor for progress. \n" );
#endif
      }
   } else {   // for blocking sockets
      if( iret != 0 ) {
#ifdef _OUTPUT_OSSL_
         fprintf( stdout, " [%s]  Could not connect to server \n", FUNC );
         perror(hostname);
#endif
         close( sd );
         return -2;
      } else {
#ifdef _DEBUG_OSSL_
         fprintf( stdout, " [%s]  Connected to server \n", FUNC );
#endif
      }
   }

   return( sd );
}


//
// Function that connects to a server via SSL
// (This function tries to create a context and ssl connection that works
// by trying a number of different negotiation methods.)
//

int inOSSL_ConnectToServerSSL(
            int *socket,
            const SSL_METHOD **method_,
            SSL_CTX **sslctx_,
            SSL **ssl_,
            const char *hostname, int iport, int flag )
{
   char FUNC[] = "inOSSL_ConnectToServerSSL";
   const SSL_METHOD *method;
   SSL_CTX *sslctx=NULL;
   SSL *ssl=NULL;
   int sd;
   struct hostent *host;
   struct sockaddr_in addr;
   int n=0, nt=2, iret, iverb=0, idbg=0;

#ifdef _OUTPUT_OSSL_
   iverb=1;
#endif
#ifdef _DEBUG_OSSL_
   idbg=1;
#endif

n=1; /// SKIP THE BULLSHIT
   while( n < nt ) {    // sweep over SSL methods to try
      if( iverb )
        fprintf( stdout, " [%s]  SSL method trial: %d \n", FUNC, n );

      if( flag ) {
         sd = inOSSL_ConnectToServer( hostname, iport, 1 ); // non-block. socket
      } else {
         sd = inOSSL_ConnectToServer( hostname, iport, 0 );
      }
      if( sd < 0 ) {
         if( iverb )
            fprintf( stdout, " [%s]  Could not connect to server (TCP)\n",FUNC);
         return 1;
      } else {
         if( iverb )
            fprintf( stdout, " [%s]  Socket to server: %d \n", FUNC, sd );
      }

      // the following will be replaced with a swwp over an array of pointers
      if( n == 0 ) method = DTLS_client_method();
      if( n == 1 ) method = SSLv23_client_method();
  //  if( n == 2 ) method = TLSv1_client_method();
  //  if( n == 3 ) method = TLSv1_1_client_method();
  //  if( n == 4 ) method = TLSv1_2_client_method();
  //  if( n == 5 ) method = TLSv1_3_client_method();
  //  if( n == 6 ) method = SSLv2_client_method();
  //  if( n == 7 ) method = SSLv3_client_method();

      sslctx = SSL_CTX_new( method );
      if( sslctx == NULL ) {
         if( iverb ) {
            fprintf( stdout, " [%s]  Could create SSL Context \n",FUNC);
            ERR_print_errors_fp( stdout );
         }
         if( idbg ) fprintf( stdout, "       Shutding down socket \n" );
         shutdown( sd, SHUT_RDWR );
         if( idbg ) fprintf( stdout, "       Closing socket \n" );
         close( sd );
         return 2;
      } else {
         if( iverb )
            fprintf( stdout, "       Pointer to CTX %p \n", sslctx );
      }

      ssl = SSL_new( sslctx );
      if( ssl == NULL ) {
         if( iverb )
            fprintf( stdout, " [%s]  Could create SSL session object \n",FUNC);
         if( idbg ) fprintf( stdout, "   Freeing SSL CTX \n" );
         SSL_CTX_free( sslctx );
         if( idbg ) fprintf( stdout, "   Shutding down socket \n" );
         shutdown( sd, SHUT_RDWR );
         if( idbg ) fprintf( stdout, "   Closing socket \n" );
         close( sd );
         return 3;
      } else {
         if( iverb )
            fprintf( stdout, "       Pointer to session obj. %p \n", ssl );
      }

      SSL_set_fd( ssl, sd );

      // act differently based on blocking or non-blocking socket
      if( flag ) {
         int iend=1;
         while( iend ) {
            iret = SSL_connect( ssl );
            if ( iret < 0 ) {
               if( iverb )
                  fprintf( stdout, " [%s]  Stage in conection: %d\n",FUNC,iret);
               if( iverb ) usleep( 100000 );

               int ssl_error = SSL_get_error( ssl, iret );
               if( ssl_error == SSL_ERROR_WANT_WRITE ) {
                  if( iverb )
                     fprintf( stdout, "  Got ssl_error: \"want write\" \n" );
               } else
               if( ssl_error == SSL_ERROR_WANT_READ ) {
                  if( iverb )
                     fprintf( stdout, "  Got ssl_error: \"want read\" \n" );
               } else {
                  if( iverb )
                     fprintf( stdout, "  Got ssl_error NEITHER!!! (Fatal) \n" );
                  iend = 0;
                  if( idbg ) fprintf( stdout, "   Freeing SSL sess. object \n");
                  SSL_free( ssl );
                  if( idbg ) fprintf( stdout, "   Freeing SSL CTX \n" );
                  SSL_CTX_free( sslctx );
                  if( idbg ) fprintf( stdout, "   Shutding down socket \n" );
                  shutdown( sd, SHUT_RDWR );
                  if( idbg ) fprintf( stdout, "   Closing socket \n" );
                  close( sd );
               }

            } else if ( iret == 2 ) {
               if( iverb )
                  fprintf( stdout, " [%s]  Could not enable SSL/TLS, but shutdown was good \n",FUNC);
               if( idbg ) fprintf( stdout, "   Freeing SSL session object \n" );
               SSL_free( ssl );
               if( idbg ) fprintf( stdout, "   Freeing SSL CTX \n" );
               SSL_CTX_free( sslctx );
            } else {  // iret == 1
               if( iverb )
                  fprintf( stdout, " [%s]  Successfully enabled SSL \n", FUNC );
               n = 999;    // for exiting the loop
               iend = 0;   // exit the ssl_connect calls
            }
         }
      } else {
         iret = SSL_connect( ssl );
         if ( iret < 0 ) {
            if( iverb )
               fprintf( stdout, " [%s]  Could not start session \n",FUNC );
            if( idbg ) fprintf( stdout, "   Freeing SSL session object \n" );
            SSL_free( ssl );
            if( idbg ) fprintf( stdout, "   Freeing SSL CTX \n" );
            SSL_CTX_free( sslctx );
            if( idbg ) fprintf( stdout, "   Shutding down socket \n" );
            shutdown( sd, SHUT_RDWR );
            if( idbg ) fprintf( stdout, "   Closing socket \n" );
            close( sd );
         } else if ( iret == 2 ) {
            if( iverb )
               fprintf( stdout, " [%s]  Could not enable SSL/TLS, but shutdown was good \n",FUNC);
            if( idbg ) fprintf( stdout, "   Freeing SSL session object \n" );
            SSL_free( ssl );
            if( idbg ) fprintf( stdout, "   Freeing SSL CTX \n" );
            SSL_CTX_free( sslctx );
         } else {  // iret == 1
            if( iverb )
               fprintf( stdout, " [%s]  Successfully enabled SSL/TLS\n", FUNC );
            n = 999;    // for exiting the loop
         }
      }

      ++n;
   }


// if( CONNECTED_SSL _OR_ CREATED_CONTEXT ??? ) {
//    if( SSL_CTX_load_verify_locations( p->sslctx, p->ca_cert, p->ca_path ) ) {
//       if( iverb )
//          fprintf( stdout, " [%s]  Could not open CA file \n", FUNC );
//    }
// }

   if( n == 999+1 ) {
      // return data on success
      if( iverb )
         fprintf( stdout, " [%s]  Returning SSL objects \n", FUNC );
      *socket = sd;
      *method_ = method;
      *sslctx_ = sslctx;
      *ssl_ = ssl;
      return 0;
   }

   return 4;
}


/*
 * Function to show the result of certificate verification
 */
void inOSSL_QueryVerifyResult( long result )
{
   fprintf( stdout, " Verification result is: " );

   if(        result == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT ) {
      fprintf( stdout, "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT \n" );
   } else if( result == X509_V_ERR_UNABLE_TO_GET_CRL ) {
      fprintf( stdout, "X509_V_ERR_UNABLE_TO_GET_CRL \n" );
   } else if( result == X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE ) {
      fprintf( stdout, "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE \n" );
   } else if( result == X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE) {
      fprintf( stdout, "X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE \n" );
   } else if( result == X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY ) {
      fprintf( stdout, "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY \n" );
   } else if( result == X509_V_ERR_CERT_SIGNATURE_FAILURE) {
      fprintf( stdout, "X509_V_ERR_CERT_SIGNATURE_FAILURE \n" );
   } else if( result == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ) {
      fprintf( stdout, "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY \n" );
   } else {
      fprintf( stdout, "UNKNOWN: %ld  \n", result );
   }

   fprintf( stdout, "\n" );
}



//
// Driver (becomes a server or a client)
//
#ifdef _INSSL_DRIVER_
int main( int argc, char *argv[] )
{
   int ierr;
   int iround=0;


if( argc == 1 ) {    // make it a server when no arguments are provided
//----- start of server code
   struct inOSSL_data_s server_data;
   int iport = 60001;

#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  IN's SSL server (built: %s %s)\n",__DATE__,__TIME__);
#endif

   // should get paths from either env variables or passed in
   server_data.ca_cert = NULL;
   server_data.ca_path = NULL;

   ierr = inOSSL_InitializeSSL();
   ierr = inOSSL_CreateServerFromFiles( &server_data, "key.pem", "cert.pem" );
   server_data.socket = inOSSL_StartServer( &server_data, iport, 10 );
   if( server_data.socket < 0 ) {
      printf(" [MAIN}  Failed to start server \n");
      (void) inOSSL_TerminateServer( &server_data );
      inOSSL_DestroySSL();
      exit(1);
   }

   while( iround < 3 ) {
      struct sockaddr_in peer_addr;
      socklen_t len = sizeof(peer_addr);
      SSL *ssl = NULL;
      X509 *cert = NULL;
      int client;
      char buffer[1024];
      int bytes;

#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Waiting at accept() ... \n");
#endif
      client = accept(server_data.socket, (struct sockaddr *) &peer_addr, &len);
      printf("Connection: %s:%d\n",inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port));
      ssl = SSL_new(server_data.sslctx);
      cert = inOSSL_GetCertificate( ssl );   // should show no certificates
      inOSSL_ShowCertificate( cert );        // should show no certificates
      if( cert != NULL ) X509_free( cert );  // paranoia... or noiveness

      SSL_set_fd(ssl, client);   // set FD of client to be the SSL's FD
      SSL_accept(ssl);
#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Accepted..\n");
#endif

      // work happens here...
      bytes = SSL_read( ssl, buffer, sizeof(buffer) );
      if ( bytes > 0 ) {
         buffer[bytes] = '\0';
         printf(" [MAIN]  Got message: \"%s\" \n",buffer);
      }

      inOSSL_ShutdownSSLSession( ssl );
#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Shut down the SSL session \n");
#endif
      ierr = close(client);
      if( ierr == 0 ) {
#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Closed socket with no drama %d\n",ierr);
#endif
      } else {
#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Closed socket, but there was some drama %d\n",ierr);
#endif
      }

#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  End of cycle \n");
#endif
       ++iround;
    }

#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Terminating server SSL context \n");
#endif
   (void) inOSSL_TerminateServer( &server_data );

#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Destroying internal structures\n");
#endif
   inOSSL_DestroySSL();

//----- end of server code
} else {   // make it a client
//----- start of client code
   struct inOSSL_data_s client_data;

#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  IN's SSL client (built: %s %s)\n",__DATE__,__TIME__);
#endif

   // should get paths from either env variables or passed in
   client_data.ca_cert = NULL;
   client_data.ca_path = NULL;

   ierr = inOSSL_InitializeSSL();
   ierr = inOSSL_CreateClient( &client_data, "key.pem", "cert.pem" );
   if( ierr != 0 ) {
      printf(" [MAIN}  Failed to start client \n");
      inOSSL_DestroySSL();
      exit(1);
   }

   while( iround < 1 ) {
      SSL *ssl = NULL;
      X509 *cert = NULL;
      int server;

#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Waiting until connect() ... \n");
#endif
      sleep(2);

#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Attempting connection \n");
#endif
      server = inOSSL_ConnectToServer( argv[1] , atoi( argv[2] ), 0 );
      if( server < 0 ) {
#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Connection failed! \n");
#endif
      } else {
#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Connection established \n");
#endif
      client_data.socket = server;
      ssl = SSL_new( client_data.sslctx );
      SSL_set_fd( ssl, server );
      ierr = SSL_connect( ssl );
      if( ierr == -1 ) {
#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Could not connect with SSL! \n");
#endif
      } else {
         char mesg[] = "This is a message sent from the client.";
         long verify;
#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Connected the SSL layer \n");
#endif
         cert = inOSSL_GetCertificate( ssl );  // get the server's cert.
         inOSSL_ShowCertificate( cert );       // should show the server's cert.
         X509_free( cert );
         verify = SSL_get_verify_result( ssl );
         if( verify == X509_V_OK ) {
            printf(" [MAIN]  Verification result is X509_V_OK \n");
         } else {
            printf(" [MAIN]  Verification result not OK; this is expected \n");
            // do some more extensive verification tests...
            inOSSL_QueryVerifyResult( verify );
         }
         // wait for some time
         sleep(1);
         // send some crap
#ifdef _DEBUG_OSSL_
         printf(" [MAIN]  Writing data to server...\n");
#endif
         SSL_write(ssl, mesg, strlen(mesg));
      }

#ifdef _DEBUG_OSSL_
      printf(" [MAIN]  Shutting down SSL \n");
#endif
      inOSSL_ShutdownSSLSession( ssl );
      close( server );
   }

#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  End of cycle \n");
#endif
       ++iround;
    }

#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Terminating client SSL context \n");
#endif
   (void) inOSSL_TerminateClient( &client_data );

#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Destroying internal structures\n");
#endif
   inOSSL_DestroySSL();

//----- end of client code
}

   return(ierr);
}

#endif

