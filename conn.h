/*
 * Copyright (c) 2019 Julius Barzdziukas <julius.barzdziukas@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef CONN_H
#define CONN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include <sys/socket.h>

int epoll_mod_init(int,int,uint8_t,int *);
int epoll_mod_wait(int,int,uint8_t,int *);
int epoll_mod_del(int,int,int *);

int socket_block(int,int *);
int socket_nonblock(int,int *);
int socket_error_check(int,int *);

int tcp_socket_init(int *,int *,int *);

int tcp_connect(int,int,struct sockaddr *,int,size_t,int *);

int tcp_socket_send(int,int,int,size_t,uint8_t *,size_t,int *);
int tcp_socket_recv(int,int,int,size_t,uint8_t *,size_t,int *);

int tls_init(SSL_CTX **);
int tcp_socket_tls_connect(int *,int *,SSL_CTX *,SSL **,SSL_SESSION **,int,size_t,int *);
int tcp_socket_tls_disconnect(int *,int *,SSL **,SSL_SESSION **,int *);
int tcp_socket_tls_end(int *,int *,SSL_CTX **,SSL **,SSL_SESSION **,int *);

int tcp_tls_send(SSL *,int,int,size_t,uint8_t *,size_t,int *);
int tcp_tls_recv(SSL *,int,int,size_t,uint8_t *,size_t,int *);

#ifdef __cplusplus
}
#endif 

#endif
