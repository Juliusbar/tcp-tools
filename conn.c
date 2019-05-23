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

#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <endian.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

//#include <openssl/opensslconf.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "conn.h"

#define ALLOC(p,n) ((p)=malloc(sizeof(*(p))*(n)))
#define STRCAT(p,s) ((p)=mystrcat((p),(s)))
#define STRNULL(p,s) { (p)=(s); *(p)=0; }

static pthread_mutex_t *locks;

char *mystrcat(char* A,char* B){
	while (*A) A++;
	while ( (*A++ = *B++) );
	return --A;
}

//---------------------------------------- Openssl Locks ------------------------------------
#if defined(__GNUC__)
__attribute__((unused))
#endif
static void lock_callback(int mode,int type,char *F,int L){
	(void)F;
	(void)L;
	if(mode & CRYPTO_LOCK) pthread_mutex_lock(&(locks[type]));
	else pthread_mutex_unlock(&(locks[type]));
}

#if defined(__GNUC__)
__attribute__((unused))
#endif
static unsigned long thread_id(void){
	unsigned long ret;
	ret=(unsigned long)pthread_self();
	return ret;
}

static void init_locks(void){
	locks=(pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks()*sizeof(pthread_mutex_t));
	for(int i=0;i<CRYPTO_num_locks();i++) pthread_mutex_init(&(locks[i]),NULL);
	CRYPTO_set_id_callback((unsigned long (*)())thread_id);
	CRYPTO_set_locking_callback((void (*)(int, int, const char*, int))lock_callback);
}

static void kill_locks(void){
	CRYPTO_set_locking_callback(NULL);
	for(int i=0; i<CRYPTO_num_locks(); i++) pthread_mutex_destroy(&(locks[i]));
	CRYPTO_set_id_callback(NULL);
	OPENSSL_free(locks);
}

//---------------------------------------- Epoll --------------------------------------------
int epoll_mod_init(int sd,int epollfd,uint8_t send,int *ret_err){
	int ret;
	struct epoll_event ev;

	ev.data.fd=sd;
	if(send) ev.events=EPOLLOUT|EPOLLERR|EPOLLHUP;
	else ev.events=EPOLLIN|EPOLLERR|EPOLLHUP;
	ret=epoll_ctl(epollfd,EPOLL_CTL_ADD,sd,&ev);
	if(ret<0){
		*ret_err=errno;
		return 1;
	}
	return 0;
}

int epoll_mod_wait(int sd,int epollfd,uint8_t send,int *ret_err){
	int ret;
	struct epoll_event ev;

	ev.data.fd=sd;
	if(send) ev.events=EPOLLOUT|EPOLLERR|EPOLLHUP;
	else ev.events=EPOLLIN|EPOLLERR|EPOLLHUP;

	ret=epoll_ctl(epollfd,EPOLL_CTL_MOD,sd,&ev);
	if(ret<0){
		*ret_err=errno;
		return 1;
	}
	return 0;
}

int epoll_mod_del(int sd,int epollfd,int *ret_err){
	int ret;

	ret=epoll_ctl(epollfd,EPOLL_CTL_DEL,sd,NULL);
	if(ret<0){
		*ret_err=errno;
		return 1;
	}
	return 0;
}

//---------------------------------------- Socket -------------------------------------------
int socket_block(int sd,int *ret_err){
	int ret;
	ret=fcntl(sd,F_SETFL,fcntl(sd,F_GETFL,0)&(~O_NONBLOCK));
	if(ret<0){
		*ret_err=errno;
		return 1;
	}
	return 0;
}

int socket_nonblock(int sd,int *ret_err){
	int ret;
	ret=fcntl(sd,F_SETFL,fcntl(sd,F_GETFL,0)|O_NONBLOCK);
	if(ret<0){
		*ret_err=errno;
		return 1;
	}
	return 0;
}

int socket_error_check(int sd,int *ret_err){
	int ret=-1;
	socklen_t retLen=sizeof ret;

	if(getsockopt(sd,SOL_SOCKET,SO_ERROR,&ret,&retLen)<0){ //socket error check
		*ret_err=errno;
		return 1; // get socket error failed
	}
	if(ret!=0){
		*ret_err=ret;
		return 2; // error
	}
	*ret_err=0;
	return 0;
}

//---------------------------------------- Socket init --------------------------------------
int tcp_socket_init(int *sd,int *epollfd,int *ret_err){
	int ret;
	struct epoll_event ev;

	*sd=socket(AF_INET,SOCK_STREAM,0);
	if(*sd<0){
		*ret_err=errno;
		return 1;
	}

	*epollfd=epoll_create1(0);
	if(*epollfd<0){
		*ret_err=errno;
		return 2;
	}

//	keepalive enabled
	ret=1;
	if(setsockopt(*sd,SOL_SOCKET,SO_KEEPALIVE,(char*)&ret,sizeof ret)<0){
		*ret_err=errno;
		return 3;
	}
// keepalive time
	ret=60;
	if(setsockopt(*sd,IPPROTO_TCP,TCP_KEEPIDLE,(char*)&ret,sizeof ret)<0){
		*ret_err=errno;
		return 4;
	}
// keepalive count
	ret=3;
	if(setsockopt(*sd,IPPROTO_TCP,TCP_KEEPCNT,(char*)&ret,sizeof ret)<0){
		*ret_err=errno;
		return 5;
	}
// keepalive interval
	ret=10;
	if(setsockopt(*sd,IPPROTO_TCP,TCP_KEEPINTVL,(char*)&ret,sizeof ret)<0){
		*ret_err=errno;
		return 6;
	}

	ret=socket_nonblock(*sd,ret_err);
	if(ret) return 10;

	memset(&ev,0,sizeof(ev));

	ret=epoll_mod_init(*sd,*epollfd,1,ret_err);
	if(ret) return 11;

	*ret_err=0;
	return 0;
}

//---------------------------------------- Socket Connection --------------------------------
int tcp_connect(int sd,int epollfd,struct sockaddr *addr,int timeout,size_t ev_events_n,int *ret_err){
	uint8_t cycle_continue;
	struct epoll_event ev_events[ev_events_n];
	struct timespec t0,t1;
	uint64_t dt,timeout_ns;
	int ret;
	size_t j;
		//Connect to remote server
	clock_gettime(CLOCK_MONOTONIC,&t0);
	ret=connect(sd,addr,sizeof(*addr));
	if(ret<0){
		*ret_err=errno;
		if((*ret_err)!=EINPROGRESS){
			return 1; // failure to start connect
		}
		cycle_continue=1;
		timeout_ns=UINT64_C(1000000)*timeout;
		while(cycle_continue){
			clock_gettime(CLOCK_MONOTONIC,&t1);
			dt=UINT64_C(1000000000)*(t1.tv_sec-t0.tv_sec)+t1.tv_nsec-t0.tv_nsec;
			if(dt<timeout_ns){
				ret=epoll_wait(epollfd,ev_events,ev_events_n,timeout-dt/UINT64_C(1000000));
				if(ret<0){
					*ret_err=0;
					return 2;  // error
				}else if(ret==0){
					*ret_err=0;
					return 3; // timeout
				}else{
					for(j=0;j<ret;j++){
						if(ev_events[j].events & EPOLLOUT){
							cycle_continue=0;
						}else if(ev_events[j].events & EPOLLERR){
							*ret_err=0;
							return 4; // error during waiting
						}else if(ev_events[j].events & EPOLLHUP){
							*ret_err=0;
							return 5; // disconnect
						}
					}
					ret=socket_error_check(sd,ret_err);
					if(ret) return 6+ret; // 7 socket error, 8 other error
				}
			}else{
				return 6; // timeout
			}
		}
	}
	*ret_err=0;
	return 0;
}

int tcp_disconnect(int *sd,int *epollfd){
	if(sd&&((*sd)!=-1)){
		close(*sd);
		*sd=-1;
	}
	if(epollfd&&((*epollfd)!=-1){
		close(*epollfd);
		*epollfd=-1;
	}

	return 0;
}

int tcp_socket_send(int sd,int epollfd,int timeout,size_t ev_events_n,uint8_t *d,size_t n,int *ret_err){
	uint8_t cycle_continue;
	int ret,bytes;
	struct epoll_event ev_events[ev_events_n];
	struct timespec t0,t1;
	uint64_t dt,timeout_ns;
	size_t j;

	clock_gettime(CLOCK_MONOTONIC,&t0);
	timeout_ns=UINT64_C(1000000)*timeout;
	cycle_continue=1;
	while(cycle_continue){
		bytes=send(sd,d,n,0);
		if(bytes<=0){
			*ret_err=errno;
			if(((*ret_err)==EAGAIN)||((*ret_err)==EWOULDBLOCK)){
				cycle_continue=1;
				while(cycle_continue){
					clock_gettime(CLOCK_MONOTONIC,&t1);
					dt=UINT64_C(1000000000)*(t1.tv_sec-t0.tv_sec)+t1.tv_nsec-t0.tv_nsec;
					if(dt<timeout_ns){
						ret=epoll_wait(epollfd,ev_events,ev_events_n,timeout-dt/UINT64_C(1000000));
						if(ret<0){ //error
							*ret_err=errno;
							return 1;
						}else if(ret==0){ //timeout
							return 2;
						}else{
								for(j=0;j<ret;j++){
								if(ev_events[j].events & EPOLLOUT){
									cycle_continue=0;
								}else if(ev_events[j].events & EPOLLERR){
									return 3;
								}else if(ev_events[j].events & EPOLLHUP){
									return 4;
								}
							}
						}
					}else{ //timeout
						return 5;
					}
				}
				cycle_continue=1;
			}else if((*ret_err)==EINTR){
			}else{
				return 6;
			}
		}else cycle_continue=0;
	}
	*ret_err=errno;
	return 0;
}

int tcp_socket_recv(int sd,int epollfd,int timeout,size_t ev_events_n,uint8_t *d,size_t n,int *ret_err){
	uint8_t cycle_continue;
	int ret,bytes;
	struct epoll_event ev_events[ev_events_n];
	struct timespec t0,t1;
	uint64_t dt,timeout_ns;
	size_t j;

	clock_gettime(CLOCK_MONOTONIC,&t0);
	timeout_ns=UINT64_C(1000000)*timeout;
	cycle_continue=1;
	while(cycle_continue){
		bytes=recv(sd,d,n-1,0);
		if(bytes<=0){
			*ret_err=errno;
			if(((*ret_err)==EAGAIN)||((*ret_err)==EWOULDBLOCK)){
				cycle_continue=1;
				while(cycle_continue){
					clock_gettime(CLOCK_MONOTONIC,&t1);
					dt=UINT64_C(1000000000)*(t1.tv_sec-t0.tv_sec)+t1.tv_nsec-t0.tv_nsec;
					if(dt<timeout_ns){
						ret=epoll_wait(epollfd,ev_events,ev_events_n,timeout-dt/UINT64_C(1000000));
						if(ret<0){ //error
							*ret_err=errno;
							return 1;
						}else if(ret==0){ //timeout
							return 2;
						}else{
								for(j=0;j<ret;j++){
								if(ev_events[j].events & EPOLLIN){
									cycle_continue=0;
								}else if(ev_events[j].events & EPOLLERR){
									return 3;
								}else if(ev_events[j].events & EPOLLHUP){
									return 4;
								}
							}
						}
					}else{ //timeout
						return 5;
					}
				}
				cycle_continue=1;
			}else if((*ret_err)==EINTR){
			}else{
				return 6;
			}
		}else cycle_continue=0;
	}
	*ret_err=errno;
	return 0;
}

//---------------------------------------- TLS ----------------------------------------------
int tls_init(SSL_CTX **ctx){
#if log_debug_ssl
	CRYPTO_malloc_debug_init();
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if(SSL_library_init()<0){
#else
	if(OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS|OPENSSL_INIT_ADD_ALL_CIPHERS|OPENSSL_INIT_ADD_ALL_DIGESTS,NULL)==0){
#endif
		fprintf(stderr,"Could not initialize the OpenSSL library !\n");
		return 1;
	}
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	OPENSSL_config(NULL);
#endif
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
//	FIPS_mode_set(1);

//	*ctx=SSL_CTX_new(SSLv23_client_method());
//	*ctx=SSL_CTX_new(TLSv1_2_client_method());
	*ctx=SSL_CTX_new(TLS_client_method());
	if(!*ctx){
		fprintf(stderr,"Error: Could not create SSL object\n");
		return 2;
	}
	SSL_CTX_set_options(*ctx, SSL_OP_NO_SSLv2|
						SSL_OP_NO_SSLv3|
						SSL_OP_NO_TLSv1|
						SSL_OP_NO_TLSv1_1
//							SSL_OP_NO_TLSv1_2
						);
	init_locks();
	return 0;
}

int tcp_socket_tls_connect(int *sd,int *epollfd,SSL_CTX *ctx,SSL **ssl,SSL_SESSION **sess,int timeout,size_t ev_events_n,int *ret_err){
	uint8_t cycle_continue;
	int ret,ret1;
	size_t j;
	struct epoll_event ev_events[ev_events_n];
	struct timespec t0,t1;
	uint64_t dt,timeout_ns;

	*ssl=SSL_new(ctx);
	if(!*ssl){
		return 1;
	}
	if(!SSL_set_fd(*ssl,*sd)){
		return 2;
	}
	SSL_set_connect_state(*ssl);

	if(sess&&(*sess)){
		if(!SSL_set_session(*ssl,*sess)){
			return 3;
		}
	}
	clock_gettime(CLOCK_MONOTONIC,&t0);
	timeout_ns=UINT64_C(1000000)*timeout;
	cycle_continue=1;
	while(cycle_continue){
		ret=SSL_connect(*ssl);
		if(ret<0){
			ret1=SSL_get_error(*ssl,ret);
			if((ret1==SSL_ERROR_WANT_WRITE)||(ret1==SSL_ERROR_WANT_READ)||(ret1==SSL_ERROR_WANT_X509_LOOKUP)){
				while(cycle_continue){
					clock_gettime(CLOCK_MONOTONIC,&t1);
					dt=UINT64_C(1000000000)*(t1.tv_sec-t0.tv_sec)+t1.tv_nsec-t0.tv_nsec;
					if(dt<timeout_ns){
						ret=epoll_wait(*epollfd,ev_events,ev_events_n,timeout-dt/UINT64_C(1000000));
						if(ret<0){ //error
							*ret_err=errno;
							return 4;
						}else if(ret==0){ //timeout
							*ret_err=ret1;
							return 5;
						}else{
								for(j=0;j<ret;j++){
								if(ev_events[j].events & EPOLLOUT){
									cycle_continue=0;
								}else if(ev_events[j].events & EPOLLERR){
									*ret_err=ret1;
									return 6;
								}else if(ev_events[j].events & EPOLLHUP){
									*ret_err=ret1;
									return 7;
								}
							}
						}
					}else{ //timeout
						return 8;
					}
				}
				cycle_continue=1;
			}else if(ret1==SSL_ERROR_ZERO_RETURN){ //Close notify by server
				*ret_err=ret1;
				return 9;
			}else{
				*ret_err=ret1;
				return 10;
			}
		}else if(ret==0){ //SSL shutdown
			*ret_err=SSL_get_error(*ssl,ret);
			return 11;
		}else cycle_continue=0;
	}
	if(sess){
		*sess=SSL_get1_session(*ssl);
	}
	return 0;
}

int tcp_socket_tls_disconnect(int *sd,int *epollfd,SSL **ssl,SSL_SESSION **sess,int *ret_err){
	int ret;
	ret=epoll_mod_del(*sd,*epollfd,ret_err);
	if(ret) return 1;

	if(!SSL_shutdown(*ssl)) SSL_shutdown(*ssl);
	SSL_free(*ssl);
	*ssl=0;
	close(*sd);
	*sd=-1;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	ERR_remove_thread_state(NULL);
#endif
	return 0;
}

int tcp_socket_tls_end(int *sd,int *epollfd,SSL_CTX **ctx,SSL **ssl,SSL_SESSION **sess,int *ret_err){
	int ret;
	if(ssl&&(*ssl)){
		ret=tcp_socket_tls_disconnect(sd,epollfd,ssl,sess,ret_err);
		if(ret){
			return 1;
		}
	}
	if(sd&&((*sd)!=-1)){
		close(*sd);
		*sd=-1;
	}
	if((*epollfd)!=-1){
		close(*epollfd);
		*epollfd=-1;
	}
	if(sess&&(*sess)){
		SSL_SESSION_free(*sess);
		*sess=0;
	}

	kill_locks();
	if(ctx&&(*ctx)){
		SSL_CTX_free(*ctx);
		*ctx=0;
	}
	SSL_COMP_free_compression_methods();
	ENGINE_cleanup();
	CONF_modules_unload(1);

//	COMP_zlib_cleanup();

	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
#if log_debug_ssl
	CRYPTO_mem_leaks_fp(stderr);
#endif
	return 0;
}

int tcp_tls_send(SSL *ssl,int epollfd,int timeout,size_t ev_events_n,uint8_t *d,size_t n,int *ret_err){
	uint8_t cycle_continue;
	int ret,bytes;
	struct epoll_event ev_events[ev_events_n];
	struct timespec t0,t1;
	uint64_t dt,timeout_ns;
	size_t j;

	clock_gettime(CLOCK_MONOTONIC,&t0);
	timeout_ns=UINT64_C(1000000)*timeout;
	cycle_continue=1;
	while(cycle_continue){
		bytes=SSL_write(ssl,d,n);
		if(bytes<=0){
			*ret_err=SSL_get_error(ssl,bytes);
			if(((*ret_err)==SSL_ERROR_WANT_WRITE)||((*ret_err)==SSL_ERROR_WANT_READ)||((*ret_err)==SSL_ERROR_WANT_X509_LOOKUP)){
				cycle_continue=1;
				while(cycle_continue){
					clock_gettime(CLOCK_MONOTONIC,&t1);
					dt=UINT64_C(1000000000)*(t1.tv_sec-t0.tv_sec)+t1.tv_nsec-t0.tv_nsec;
					if(dt<timeout_ns){
						ret=epoll_wait(epollfd,ev_events,ev_events_n,timeout-dt/UINT64_C(1000000));
						if(ret<0){ //error
							*ret_err=errno;
							return 1;
						}else if(ret==0){ //timeout
							return 2;
						}else{
								for(j=0;j<ret;j++){
								if(ev_events[j].events & EPOLLOUT){
									cycle_continue=0;
								}else if(ev_events[j].events & EPOLLERR){
									return 3;
								}else if(ev_events[j].events & EPOLLHUP){
									return 4;
								}
							}
						}
					}else{ //timeout
						return 5;
					}
				}
				cycle_continue=1;
			}else if((*ret_err)==SSL_ERROR_ZERO_RETURN){ //Close notify by server
				return 6;
			}else{
				return 7;
			}
		}else cycle_continue=0;
	}
	*ret_err=0;
	return 0;
}

int tcp_tls_recv(SSL *ssl,int epollfd,int timeout,size_t ev_events_n,uint8_t *d,size_t n,int *ret_err){
	uint8_t cycle_continue;
	int ret,bytes;
	struct epoll_event ev_events[ev_events_n];
	struct timespec t0,t1;
	uint64_t dt,timeout_ns;
	size_t j;

	clock_gettime(CLOCK_MONOTONIC,&t0);
	timeout_ns=UINT64_C(1000000)*timeout;
	cycle_continue=1;
	while(cycle_continue){
		while(cycle_continue){
			clock_gettime(CLOCK_MONOTONIC,&t1);
			dt=UINT64_C(1000000000)*(t1.tv_sec-t0.tv_sec)+t1.tv_nsec-t0.tv_nsec;
			if(dt<timeout_ns){
				ret=epoll_wait(epollfd,ev_events,ev_events_n,timeout-dt/UINT64_C(1000000));
				if(ret<0){ //error
					*ret_err=errno;
					return 1;
				}else if(ret==0){ //timeout
					return 2;
				}else{
						for(j=0;j<ret;j++){
						if(ev_events[j].events & EPOLLIN){
							cycle_continue=0;
						}else if(ev_events[j].events & EPOLLERR){
							return 3;
						}else if(ev_events[j].events & EPOLLHUP){
							return 4;
						}
					}
				}
			}else{ //timeout
				return 5;
			}
		}
		bytes=SSL_read(ssl,d,n-1);
		if(bytes<=0){
			*ret_err=SSL_get_error(ssl,bytes);
			if(((*ret_err)==SSL_ERROR_WANT_WRITE)||((*ret_err)==SSL_ERROR_WANT_READ)||((*ret_err)==SSL_ERROR_WANT_X509_LOOKUP)){
				cycle_continue=1;
			}else if((*ret_err)==SSL_ERROR_ZERO_RETURN){ //Close notify by server
				return 6;
			}else{
				return 7;
			}
		}else cycle_continue=0;
	}
	*ret_err=0;
	return 0;
}

//---------------------------------------- HTTP ---------------------------------------------
int http_request(char *d,char *domain,char *path,char *ua,size_t *n){
	STRNULL(p,d);
	STRCAT(p,"GET ");
	STRCAT(p,path);
	STRCAT(p," HTTP/1.1\r\nHost: ");
	STRCAT(p,domain);
	STRCAT(p,"\r\nUser-Agent: ");
	STRCAT(p,ua);
	STRCAT(p,"\r\nContent-Length: 0\r\nAccept: */*\r\nConnection: Keep-Alive\r\n\r\n");
	return 0;
}

int http_reply(char *d,size_t n){
	size_t j;
	char *p,*p1;
	uint64_t dat;
	dat=be64toh(*((uint64_t *)d));
	if((dat&(~UINT64_C(0xFF)))==UINT64_C(0x485454502f322000)){ // HTTP/2
		j=6;
	}else if((dat==UINT64_C(0x485454502f312e31))|| // HTTP/1.1
		(dat==UINT64_C(0x485454502f312e30))|| // HTTP/1.0
		(dat==UINT64_C(0x485454502f302e39))){ // HTTP/0.9
		j=8;
	}else{
		j=0;
	}
	if(j&&(be32toh(*((uint32_t *)(d+j)))>=UINT32_C(0x20323030))&&(be32toh(*((uint32_t *)(d+j)))<=UINT32_C(0x20323038))){ // 200-208 Success
		p=d+j+4;
	}else{
		p=d;
	}
	p1=strstr(p,http_body_del);
	if(p1) *p1=0;
	lowcase(p);

	return 0;
}
