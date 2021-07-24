# C OpenSSL TCP Socket

*© Israel Pereira Tavares da Silva*

> OpenSSL is a robust, commercial-grade, and full-featured toolkit for the Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols. It is also a general-purpose cryptography library. 


* [Turing: Pioneer of the Information Age ](https://www.goodreads.com/book/show/16193364-turing)
* [OpenSSL](https://www.openssl.org/)
* [OpenSSL CookBook](https://www.feistyduck.com/books/openssl-cookbook/)

When reading [Turing: Pioneer of the Information Age ](https://www.goodreads.com/book/show/16193364-turing) it was interesting to notice the parallel between the use of cryptology during second world war and in today's internet. For this reason, I decided to explore the open source framework OpenSSL and create a project where a secure communication can be made between client and server programs.

### OpenSSL
`server.c` and `client.c` use [OpenSSL](https://www.openssl.org/) to create a secure connection between each other. Check if you have it installed with:
```bash
$ openssl version
OpenSSL 1.1.1f  31 Mar 2020
```


### Public and Private Keys
To run the `server.c` program a public and a private key are needed. The public key is in the form of a certificate. To generate these it is best to read [OpenSSL CookBook](https://www.feistyduck.com/books/openssl-cookbook/). The `server.c` program expects the certificate to be named `certificate.pem` and the private key to be named `private.pem`.

### Server
To run the `server.c` program compile and run with:
```bash
cc -o server server.c -lssl -lcrypto && ./server hostname:port
```
`hostname` can be `127.0.1.1` and `port` can be `4390` as an example. `-lssl` and `lcrypto` are needed in the compilation step to include `openssl` libraries.


### Client
To connect to the `server.c` program there are two alternative. The first one is to compile and run `client.c` with:
```bash
cc -o client client.c -lssl -lcrypto && ./client hostname:port
```
The second alternative is to use openssl in the command line:
```bash
openssl s_client -connect hostname:port
```
Both options in the client side are able to send messages to the server via the stardard user input.


>  Like most student travellers, Turing had purchased the cheapest possible ticket, and spent the voyage in ‘steerage’, the most uncomfortable class of accommodation. (Turing Pioneer of the Information Age by Jack Copeland)
