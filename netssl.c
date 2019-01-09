/******************************************************************************
 Code to do SSL server/client stuff using OpenSSL

 Copyright 2018 by Ioannis Nompelis

 Ioannis Nompelis <nompelis@nobelware.com> 2018/12/26
 ******************************************************************************/
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
 * Function to initialize the OpenSSL library
 * (A lot of predefined constants seem to be created here...)
 */

int inOSSL_InitializeSSL()
{
   int ierr;
   char FUNC[] = "inOSSL_InitializeSSL";


#ifdef _DEBUG_OSSL_
   printf(" [%s]  Loading all algorithms \n",FUNC);
#endif
   OpenSSL_add_all_algorithms();
#ifdef _DEBUG_OSSL_
   printf(" [%s]  Loading various SSL library strings \n",FUNC);
#endif
   SSL_load_error_strings();
   ERR_load_BIO_strings();
   ERR_load_crypto_strings();

#ifdef _DEBUG_OSSL_
   printf(" [%s]  Initializing the SSL library \n",FUNC);
#endif
   ierr = SSL_library_init();
   if( ierr < 0 ) {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Could not initialize the SSL library \n",FUNC);
#endif
      return(1);
   }

   return(0);
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
      printf(" [%s]  The SSL session pointer is null!\n",FUNC);
#endif
      return;
   } else {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Shutting down the SSL session \n",FUNC);
#endif
   }

   n = 0;
   while( n < nmax ) {
      ierr = SSL_shutdown( p );
      if( ierr == 0 ) {
#ifdef _DEBUG_OSSL_
         printf(" [%s]  Shutdown return %d; will call again \n",FUNC,ierr);
#endif
      } else if( ierr == 1 ) {
#ifdef _DEBUG_OSSL_
         printf(" [%s]  Shutdown return %d; completed \n",FUNC,ierr);
#endif
         n = nmax;
      } else {
#ifdef _DEBUG_OSSL_
         printf(" [%s]  Shutdown return %d; failed\n",FUNC,ierr);
#endif
         n = nmax;
      }
      ++n;
   }

#ifdef _DEBUG_OSSL_
   printf(" [%s]  Freeing structure \n",FUNC);
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
   printf(" [%s]  Loading certificates \n",FUNC);
#endif

   iret = SSL_CTX_use_certificate_file( ctx, certfile, SSL_FILETYPE_PEM );
   if( iret <= 0 ) {
      printf(" [%s]  Could not load certificate file: \'%s\" \n",FUNC,certfile);
      ERR_print_errors_fp( stdout );
      return(-1);
   } else {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Loaded certificate file: \"%s\" \n",FUNC,certfile);
#endif
   }

   iret = SSL_CTX_use_PrivateKey_file( ctx, keyfile, SSL_FILETYPE_PEM );
   if( iret <= 0 ) {
      printf(" [%s]  Could not load private key file: \'%s\" \n",FUNC,keyfile);
      ERR_print_errors_fp( stdout );
      // unload certfile here?
      return(-2);
   } else {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Loaded private key from file: \"%s\" \n",FUNC,keyfile);
#endif
   }

   if( !SSL_CTX_check_private_key( ctx ) ) {
      printf(" [%s]  Private key does not match the public certificate\n",FUNC);
      // unload certfile/privkey here?
      return(1);
   } else {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Private key matches certificate \n",FUNC);
#endif
   }

   return 0;
}



/*
 * Function to load the private key and the corresponding certificate from
 * embedded binary representations to the SSL context structure.
 * This function works the same way as the file-based one, but uses memory
 * segments such that certificates can be embedded to executable/library code.
 * One argument specifies the type of hte key.
 */

int inOSSL_LoadCertificatesMem( SSL_CTX *ctx,
                                unsigned char *certdata, int clen,
                                unsigned char *keydata, int klen, int ipk )
{
   char FUNC[] = "inOSSL_LoadCertificatesMem";
   int iret;
#ifdef _DEBUG_OSSL_
   printf(" [%s]  Loading certificates from memory segments\n",FUNC);
#endif

   if( certdata == NULL || keydata == NULL ) {
      printf(" [%s]  Certificate data is null \n",FUNC);
      return(2);
   }

   iret = SSL_CTX_use_certificate_ASN1( ctx, clen, certdata );
   if( iret <= 0 ) {
      printf(" [%s]  Could not load certificate chunk (size= %d)\n",FUNC,clen);
      ERR_print_errors_fp( stdout );
      return(-1);
   } else {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Loaded certificate chunk (size= %d)\n",FUNC,clen);
#endif
   }

   iret = SSL_CTX_use_PrivateKey_ASN1( ipk, ctx, keydata, klen );
   if( iret <= 0 ) {
      printf(" [%s]  Could not load private key chunk (size=%d)\n",FUNC,klen);
      ERR_print_errors_fp( stdout );
      // unload certfile here?
      return(-2);
   } else {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Loaded private key chunk (size=%d)\n",FUNC,klen);
#endif
   }

   if( !SSL_CTX_check_private_key( ctx ) ) {
      printf(" [%s]  Private key does not match the public certificate\n",FUNC);
      // unload certfile/privkey here?
      return(1);
   } else {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Private key matches certificate \n",FUNC);
#endif
   }

   return 0;
}


/*
 * Function to create an SSL "server"
 *
 * This function creates an SSL context by using select methods and loads the
 * certificates that it needs to allow for the clients to perform verification
 * of the server's identity.
 */

int inOSSL_CreateServer( struct inOSSL_data_s *p, char *keyfile, char *certfile)
{
   char FUNC[] = "inOSSL_CreateServer";
   int iret;

#ifdef _DEBUG_OSSL_
   printf(" [%s]  Creating SSL server \n",FUNC);
#endif

   p->method = SSLv2_server_method();
   p->sslctx = SSL_CTX_new( p->method );

   if( p->sslctx == NULL ) {
      printf(" [%s]  Could not create SSL server context \n",FUNC);
      ERR_print_errors_fp( stdout );
      return(-1);
   } else {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Created SSL server context \n",FUNC);
#endif
   }

   SSL_CTX_set_options( p->sslctx, SSL_OP_NO_SSLv2 );

   iret = inOSSL_LoadCertificates( p->sslctx, certfile, keyfile );
   if( iret != 0 ) {
      printf(" [%s]  There was a problem with the SSL certificates\n",FUNC);
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

int inOSSL_StartServer( struct inOSSL_data_s *p, int iport )
{
   char FUNC[] = "inOSSL_StartServer";
   int sd;
   int iret;

#ifdef _DEBUG_OSSL_
   printf(" [%s]  Starting INET server \n",FUNC);
#endif

   // create a listening a socket
   sd = socket(PF_INET, SOCK_STREAM, 0);
   bzero(&(p->addr), sizeof(p->addr));
   p->addr.sin_family = AF_INET;
   p->addr.sin_port = htons( iport );
   p->addr.sin_addr.s_addr = INADDR_ANY;
   iret = bind( sd, (struct sockaddr *) &(p->addr), sizeof(p->addr) );
   if(iret != 0 ) {
      printf(" [%s]  Could not bind() the socket to port: %d \n",FUNC,iport);
      perror("bind to port");
      return(-1);
   } else {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Successfully bind() socket to port: %d \n",FUNC,iport);
#endif
   }

   iret = listen( sd, 10 );    // set backlog to ten
   if( iret != 0 ) {
      printf(" [%s]  Could not listen() on socket \n",FUNC);
      perror("Cannot configure listening port");
      // close socket
      close( sd );
      return(-2);
   } else {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Successfully listen()ing on socket \n",FUNC);
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
   char FUNC[] = "inOSSL_GetCertificate";
   X509 *cert;

   // get the certificate if it is available
   cert = SSL_get_peer_certificate( ssl );
   if( cert != NULL ) {
      printf(" [%s]  Retrieved server certificate\n",FUNC);
   } else {
      printf(" [%s]  No certificates\n", FUNC);
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
      printf(" [%s]  Certificate pointer is null \n",FUNC);
      return;
   }

   printf(" [%s]  Server certificate:\n",FUNC);
   line = X509_NAME_oneline( X509_get_subject_name( cert ), 0, 0 );
   printf(" [%s]  Subject: %s\n", FUNC, line);
   free(line);
   line = X509_NAME_oneline( X509_get_issuer_name( cert ), 0, 0 );
   printf(" [%s]  Issuer: %s\n", FUNC, line);
   free(line);

   // get the certificate's serial number and display it 
   serial = X509_get_serialNumber(cert);  // get internal pointer; don't free
   bn = ASN1_INTEGER_to_BN(serial, NULL); // makes new BN object
   serial_ascii = BN_bn2dec(bn);          // get pointer to new char object
   BN_free( bn );                         // drop the big-number object
   printf(" [%s]  Certificate's serial num. \"%s\"\n",FUNC,serial_ascii);
   free( serial_ascii );                  // drop the string

   // provide some info about the certificate
   printf(" [%s]  ",FUNC);
   raw = X509_check_ca( cert );
   if( raw <= 0 ) {
      printf("Is an unknown certificate \n");
   } else if( raw == 1 ) {
      printf("Is an X.509 v3 CA certificate with basicConstraints extension CA:TRUE \n");
   } else if( raw == 3 ) {
      printf("Is a self-signed X.509 v1 certificate \n");
   } else if( raw == 4 ) {
      printf("Is a certificate with keyUsage extension with bit keyCertSign set, but without basicConstraints \n");
   } else if( raw == 5 ) {
      printf("Is a certificate with an outdated Netscape Certificate Type extension telling that it is a CA certificate \n");
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
   printf(" [%s]  Creating SSL client \n",FUNC);
#endif

   p->method = SSLv2_client_method();
   p->sslctx = SSL_CTX_new( p->method );

   if( p->sslctx == NULL ) {
      printf(" [%s]  Could not create SSL client context \n",FUNC);
      ERR_print_errors_fp( stdout );
      return(-1);
   } else {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Created SSL client context \n",FUNC);
#endif
   }

   SSL_CTX_set_options( p->sslctx, SSL_OP_NO_SSLv2 );

   // TEMPORARY load a certificate from a file with no error-trapping
   p->client_cert = NULL;
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

int inOSSL_ConnectToServer( const char *hostname, int iport )
{
   char FUNC[] = "inOSSL_ConnectToServer";
   int sd;
   struct hostent *host;
   struct sockaddr_in addr;
   int iret;


   host = gethostbyname( hostname );
   if( host == NULL ) {
      printf(" [%s]  Could not get host structure \n",FUNC);
      perror(hostname);
      return(-1);
   } else {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Prepared hostname structure \n",FUNC);
#endif
   }

   sd = socket(PF_INET, SOCK_STREAM, 0);
   if( sd == -1 ) {
      printf(" [%s]  Could not create INET socket \n",FUNC);
      perror("socket creation failed");
   } else {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Created INET socket \n",FUNC);
#endif
   }

   bzero(&addr, sizeof(addr));
   addr.sin_family = AF_INET;
   addr.sin_port = htons( iport );
   addr.sin_addr.s_addr = *(long*)(host->h_addr);

   iret = connect( sd, (struct sockaddr *) &addr, sizeof(addr) );
   if( iret != 0 ) {
      printf(" [%s]  Could not connect to server \n",FUNC);
      perror(hostname);
      close( sd );
      return(-2);
   } else {
#ifdef _DEBUG_OSSL_
      printf(" [%s]  Connected to server \n",FUNC);
#endif
   }

   return( sd );
}


/*
 * Function to show the result of certificate verification
 */
void inOSSL_QueryVerifyResult( long result )
{
   printf(" Verification result is: ");

   if(        result == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT ) {
                printf("X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT \n");
   } else if( result == X509_V_ERR_UNABLE_TO_GET_CRL ) {
                printf("X509_V_ERR_UNABLE_TO_GET_CRL \n");
   } else if( result == X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE ) {
                printf("X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE \n");
   } else if( result == X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE) {
                printf("X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE \n");
   } else if( result == X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY ) {
                printf("X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY \n");
   } else if( result == X509_V_ERR_CERT_SIGNATURE_FAILURE) {
                printf("X509_V_ERR_CERT_SIGNATURE_FAILURE \n");
   } else if( result == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ) {
                printf("X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY \n");
   } else {
      printf("UNKNOWN: %ld  \n",result);
   }

   printf("\n");
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

   ierr = inOSSL_InitializeSSL();
   ierr = inOSSL_CreateServer( &server_data, "key.pem", "cert.pem" );
   server_data.socket = inOSSL_StartServer( &server_data, iport );
   if( server_data.socket < 0 ) {
      printf(" [MAIN}  Failed to start server \n");
      (void) inOSSL_TerminateServer( &server_data );
      inOSSL_DestroySSL();
      exit(1);
   }

   while( iround < 3 ) {
      struct sockaddr_in addr, peer_addr;
      socklen_t len = sizeof(addr);
      SSL *ssl = NULL;
      X509 *cert = NULL;
      int client;
      char buffer[1024];
      int bytes;

#ifdef _DEBUG_OSSL_
   printf(" [MAIN]  Waiting at accept() ... \n");
#endif
      client = accept(server_data.socket, (struct sockaddr *) &peer_addr, &len);
      printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
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

   ierr = inOSSL_InitializeSSL();
   ierr = inOSSL_CreateClient( &client_data, "key.pem", "cert.pem" );
   if( ierr != 0 ) {
      printf(" [MAIN}  Failed to start client \n");
      inOSSL_DestroySSL();
      exit(1);
   }

   while( iround < 3 ) {
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
      server = inOSSL_ConnectToServer( argv[1] , atoi( argv[2] ) );
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
         SSL_write(ssl, mesg, strlen(mesg));
      }

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

