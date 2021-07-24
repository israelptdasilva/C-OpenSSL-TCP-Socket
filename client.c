#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>

/////////////////////////////////////////////////////////////////////
// (SSL)[https://www.openssl.org/docs/manmaster/man7/ssl.html]
// (Man)[https://www.openssl.org/docs/manmaster/]
// /usr/include/openssl/ssl.h
/////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////
// This program uses openssl SSL API to make a secure connection and 
// exchange encrypted messages with a server on hostname:port.
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
  const SSL_METHOD *method = TLS_client_method();
  ctx = SSL_CTX_new(method);
  if (ctx == NULL) {
    perror("Context");
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
  BIO *cbio;
  cbio = BIO_new_connect("israel:4390");

  ///////////////////////////////////////////////////////////////////
  // SSL_set0_rbio() connects the BIO rbio for the read operations of 
  // the ssl object. The SSL engine inherits the behaviour of rbio. 
  // If the BIO is nonblocking then the ssl object will also have 
  // nonblocking behaviour. This function transfers ownership of rbio 
  // to ssl. It will be automatically freed using BIO_free_all(3) 
  // when the ssl is freed. 
  ///////////////////////////////////////////////////////////////////
  SSL_set0_rbio(ssl, cbio);   
  SSL_set0_wbio(ssl, cbio);   

  ///////////////////////////////////////////////////////////////////
  // SSL_connect() initiates the TLS/SSL handshake with a server. 
  // The communication channel must already have been set and 
  // assigned to the ssl by setting an underlying BIO.
  ///////////////////////////////////////////////////////////////////
  int arv = SSL_connect(ssl);
  if (arv <= 0) {
    int err = SSL_get_error(ssl, arv);
    printf("arv = %d, err = %d \n", arv, err);
    exit(EXIT_FAILURE);
  } 
 
  ///////////////////////////////////////////////////////////////////
  // BIO_set_fd() sets the file descriptor of BIO b to fd and the 
  // close flag to c.
  ///////////////////////////////////////////////////////////////////
  BIO *ibio = BIO_new_fd(fileno(stdin), BIO_NOCLOSE);

  while (1) {
    char buffer[1024];
    int length = 1024;

    /////////////////////////////////////////////////////////////////
    // SSL_read_ex() and SSL_read() try to read num bytes from the 
    // specified ssl into the buffer buf. 
    /////////////////////////////////////////////////////////////////
    int bytes = BIO_read(ibio, &buffer, length);
    if (bytes <= 0) break;
    buffer[bytes] = '\0';

    /////////////////////////////////////////////////////////////////
    // If necessary, SSL_write() will negotiate a TLS/SSL session, 
    // if not already explicitly performed by SSL_connect(3) or 
    // SSL_accept(3). If the peer requests a re-negotiation, it will 
    // be performed transparently during the SSL_write() operation. 
    // The behaviour of SSL_write() depends on the underlying BIO.
    /////////////////////////////////////////////////////////////////
    int wr = SSL_write(ssl, buffer, bytes);
    if (wr <= 0) break;
  }

  ///////////////////////////////////////////////////////////////////
  // BIO_free() frees up a single BIO. BIO_free_all() frees up an 
  // entire BIO chain, it does not halt if an error occurs freeing 
  // up an individual BIO in the chain.
  ///////////////////////////////////////////////////////////////////
  BIO_free(ibio);

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
