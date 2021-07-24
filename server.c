#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>

/////////////////////////////////////////////////////////////////////
// (SSL)[https://www.openssl.org/docs/manmaster/man7/ssl.html]
// (Man)[https://www.openssl.org/docs/manmaster/]
// /usr/include/openssl/ssl.h
/////////////////////////////////////////////////////////////////////

#define CERTIFICATE "certificate.pem"
#define PRIVATEKEY "private.pem"

/////////////////////////////////////////////////////////////////////
// This program uses openssl SSL API to accept secure connections on 
// hostname:port and exchange encrypted messages between client and
// server.
// To run the program a certificate.pem and private.pem must be 
// created.
// - Parameter *argv[]: Accepts host:port string (eg: 127.0.1.1:4390)
/////////////////////////////////////////////////////////////////////
void main(int argc, char *argv[]) {
  char *hostport = NULL;
  if (argv[1] != NULL) {
    hostport = argv[1];
  } else {
    printf("hostport variable is NULL.\n");
    exit(EXIT_FAILURE);
  }

  ///////////////////////////////////////////////////////////////////
  // SSL_CTX_new() creates a new SSL_CTX object as framework to 
  // establish TLS/SSL or DTLS enabled connections. An SSL_CTX object 
  // is reference counted. 
  ///////////////////////////////////////////////////////////////////
  SSL_CTX *ctx;

  ///////////////////////////////////////////////////////////////////
  // TLS_method(), TLS_server_method(), TLS_client_method()
  // These are the general-purpose version-flexible SSL/TLS methods. 
  // The actual protocol version used will be negotiated to the 
  // highest version mutually supported by the client and the server. 
  // The supported protocols are SSLv3, TLSv1, TLSv1.1 and TLSv1.2. 
  ///////////////////////////////////////////////////////////////////
  const SSL_METHOD *method = TLS_server_method();
  ctx = SSL_CTX_new(method);
  if (ctx == NULL) {
    perror("Context");
    exit(EXIT_FAILURE);
  }
 
  ////////////////////////////////////////////////////////////////////
  // SSL_CTX_use_certificate_file() loads the first certificate stored 
  // in file into ctx. The formatting type of the certificate must be 
  // specified from the known types SSL_FILETYPE_PEM, SSL_FILETYPE_ASN1. 
  // See the NOTES section on why SSL_CTX_use_certificate_chain_file() 
  // should be preferred.
  //
  // SSL_CTX_use_PrivateKey_file() adds the first private key found in 
  // file to ctx.
  //
  // SSL_CTX_check_private_key() checks the consistency of a 
  // private key with the corresponding certificate loaded into ctx.
  ////////////////////////////////////////////////////////////////////
  if (!SSL_CTX_use_certificate_file(ctx, CERTIFICATE, SSL_FILETYPE_PEM)
      || !SSL_CTX_use_PrivateKey_file(ctx, PRIVATEKEY, SSL_FILETYPE_PEM)
      || !SSL_CTX_check_private_key(ctx)) {

    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
    
  ///////////////////////////////////////////////////////////////////
  // The OpenSSL ssl library implements several versions of the 
  // Secure Sockets Layer, Transport Layer Security, and Datagram 
  // Transport Layer Security protocols. 
  ///////////////////////////////////////////////////////////////////
  SSL *ssl;

  ///////////////////////////////////////////////////////////////////
  // SSL_new() creates a new SSL structure which is needed to hold 
  // the data for a TLS/SSL connection. The new structure inherits 
  // the settings of the underlying context ctx: connection method, 
  // options, verification settings, timeout settings. An SSL 
  // structure is reference counted. 
  ///////////////////////////////////////////////////////////////////
  ssl = SSL_new(ctx);

  ///////////////////////////////////////////////////////////////////
  // BIO_new_accept() combines BIO_new() and BIO_set_accept_name() 
  // into a single call: that is it creates a new accept BIO with 
  // port host_port.
  ///////////////////////////////////////////////////////////////////
  BIO *abio;
  abio = BIO_new_accept(hostport);

  ///////////////////////////////////////////////////////////////////
  // BIO_set_nbio_accept() sets the accept socket to blocking mode 
  // (the default) if n is 0 or non blocking mode if n is 1.
  ///////////////////////////////////////////////////////////////////
  int isblocking = 0;
  BIO_set_nbio_accept(abio, isblocking);

  ///////////////////////////////////////////////////////////////////
  // If BIO_BIND_REUSEADDR is set the other sockets can bind to the
  // same port.
  ///////////////////////////////////////////////////////////////////
  BIO_set_bind_mode(abio, BIO_BIND_REUSEADDR);
 
  ///////////////////////////////////////////////////////////////////
  // Data written to a buffering BIO is buffered and periodically 
  // written to the next BIO in the chain. Data read from a buffering 
  // BIO comes from an internal buffer which is filled from the next 
  // BIO in the chain. Both BIO_gets() and BIO_puts() are supported.
  ///////////////////////////////////////////////////////////////////
  BIO *sbio = BIO_new(BIO_f_buffer());

  ///////////////////////////////////////////////////////////////////
  // The BIO_push() function appends the BIO b to a, it returns a.
  ///////////////////////////////////////////////////////////////////
  BIO_push(sbio, abio);

  ///////////////////////////////////////////////////////////////////
  // SSL_set_bio() connects the BIOs rbio and wbio for the read and 
  // write operations of the TLS/SSL (encrypted) side of ssl.
  ///////////////////////////////////////////////////////////////////
  SSL_set_bio(ssl, sbio, sbio);
 
  ///////////////////////////////////////////////////////////////////
  // SSL_accept() waits for a TLS/SSL client to initiate the TLS/SSL 
  // handshake. The communication channel must already have been 
  // set and assigned to the ssl by setting an underlying BIO.
  ///////////////////////////////////////////////////////////////////
  int arv = SSL_accept(ssl);
  if (arv <= 0) {
    int err = SSL_get_error(ssl, arv);
    printf("Handshake failure: err = %d \n", err);
    exit(EXIT_FAILURE);
  }
  
  ///////////////////////////////////////////////////////////////////
  // BIO_set_fd() sets the file descriptor of BIO b to fd and the 
  // close flag to c.
  ///////////////////////////////////////////////////////////////////
  BIO *out = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);
  
  while(1) {
    int length = 1024;
    char buffer[1024];
    /////////////////////////////////////////////////////////////////
    // SSL_read_ex() and SSL_read() try to read num bytes from the 
    // specified ssl into the buffer buf. On success SSL_read_ex() 
    // will store the number of bytes actually read in *readbytes.
    /////////////////////////////////////////////////////////////////
    int bytes = SSL_read(ssl, buffer, length);
    buffer[bytes] = 0x00;
    if(bytes <= 0) break;

    /////////////////////////////////////////////////////////////////
    // If necessary, SSL_write() will negotiate a TLS/SSL session, 
    // if not already explicitly performed by SSL_connect(3) or 
    // SSL_accept(3). If the peer requests a re-negotiation, it will 
    // be performed transparently during the SSL_write() operation. 
    // The behaviour of SSL_write() depends on the underlying BIO.
    /////////////////////////////////////////////////////////////////
    BIO_write(out, buffer, bytes);
  }

  ///////////////////////////////////////////////////////////////////
  // BIO_free() frees up a single BIO. BIO_free_all() frees up an 
  // entire BIO chain, it does not halt if an error occurs freeing 
  // up an individual BIO in the chain.
  ///////////////////////////////////////////////////////////////////
  BIO_free(out);

  ///////////////////////////////////////////////////////////////////
  // SSL_CTX_free() decrements the reference count of ctx, and 
  // removes the SSL_CTX object pointed to by ctx and frees up the 
  // allocated memory if the the reference count has reached 0.
  // It also calls the free()ing procedures for indirectly affected 
  // items, if applicable: the session cache, the list of ciphers, 
  // the list of Client CAs, the certificates and keys.
  ///////////////////////////////////////////////////////////////////
  SSL_CTX_free(ctx);

  ///////////////////////////////////////////////////////////////////
  // SSL_free() also calls the free()ing procedures for indirectly 
  // affected items, if applicable: the buffering BIO, the read and 
  // write BIOs, cipher lists specially created for this ssl, the 
  // SSL_SESSION. Do not explicitly free these indirectly freed up 
  // items before or after calling SSL_free(), as trying to free 
  // things twice may lead to program failure.
  ///////////////////////////////////////////////////////////////////
  SSL_free(ssl);
}
