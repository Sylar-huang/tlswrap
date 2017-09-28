/*
 * Copyright (c) 2002-2006 Tomas Svensson <ts@codepix.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "conf.h"

#define _POSIX_PII_SOCKET /* for Tru64 UNIX 5.1 */

#include <sys/types.h>
#ifdef WIN32
#include <Winsock2.h>
#include <process.h>
#define snprintf _snprintf
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
typedef   __int32 ssize_t;
typedef int socklen_t;
#define ECONNREFUSED WSAECONNREFUSED
#define EINPROGRESS WSAEWOULDBLOCK
#else
#include <sys/socket.h>
#include <netdb.h>
#include <sys/uio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif
#include <fcntl.h>
#include <sys/types.h>


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

extern int debug;

#include "tlswrap.h"
#include "network.h"
#include "misc.h"

#ifdef WIN32

int write(SOCKET s, void *buf, int len) {
	return send(s, (char*)buf, len, 0);
}

int read(SOCKET s, void *buf, int len) {
	return recv(s, (char*)buf, len, 0);
}

#endif

void setup_connect_1(struct user_data *ud, int index, char *serv,
		     char *port, int write_pipe) {
	struct dns_msg dns;

  	dns.ud = index;
  	strlcpy(dns.port, port, sizeof(dns.port));
  	strlcpy(dns.hostname, serv, sizeof(dns.hostname));
  	if (write(write_pipe, &dns, sizeof(dns)) != sizeof(dns)) {
    		fprintf(stderr, "Error: Too many hostname lookups\n");
    		return;
  	}
  	ud->connected = CONN_DNS;
  	if (debug)
		printf("Resolving %s on %d...\n",serv, index);
}

void
setup_connect_2(struct user_data *ud, struct dns_msg *dns, int data)
{
	char 	*ep;
	int 	result, tos = 0;

	if (strlen(dns->hostname) == 0) {
  	if (debug)
			printf("Error: Could not resolve hostname\n");
		if (!(data)) {
			ud->connected = CONN_NO;
			print_to_ud(ud, "530 Could not resolve hostname.\r\n");
		}
		return;
	}
	ud->ssl_data = NULL; /* Could be data left from other session, which would crash dataclose */
	ud->rport = strtol(dns->port, &ep, 10);
		if (debug)
			printf("Connecting to %s on port %s, please wait...\n", dns->hostname, dns->port);

		if (data) {
			ud->serv_data_fd = setup_connect(dns->hostname, dns->port, &ud->lport, &result);
#ifndef WIN32
			tos = IPTOS_THROUGHPUT;
			if ((setsockopt(ud->serv_data_fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1) && debug)
				printf("Unable to set TOS=Throughput for data channel.\n");
#endif
		} else {
			ud->serv_fd = setup_connect(dns->hostname, dns->port,
		    &ud->lport, &result);
#ifndef WIN32
			tos = IPTOS_THROUGHPUT;
			if ((setsockopt(ud->serv_fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1) && debug)
				printf("Unable to set TOS=Lowdelay for control channel.\n");
#endif
		}

  	if (result == 0) {
    		if (data) {
			if (debug)
				printf("data connected\n");
			ud->data_connected = CONN_YES;
    		} else {
    			ud->connected = CONN_YES;
    			ud->serv_status = SERV_CONN;
    		}
  	} else if (result == 2) {
    		print_to_ud(ud, "Can't find hostname, should not happen!");
    		ud->connected = CONN_CMD;
  	} else if (result == 3) {
		print_to_ud(ud,"421 Connection refused by server.\r\n");
		user_close(ud);
  	} else if (result == 4) {
		print_to_ud(ud,"421 Software caused connection abort.\r\n");
		user_close(ud);
	} else {
		if (debug)
			printf("connection in progress\n");
		if (!data)
			ud->connected = CONN_IN_PROG;  
		else
			ud->data_connected = CONN_IN_PROG;
  	} 
}

#ifdef WIN32
SOCKET
#else
int
#endif
setup_connect(const char *host, const char *port,
	unsigned int *lport, int *result)
{

	int  flags,  sockopt;
	char *ep;

	struct sockaddr_in sin, *sin2;
	unsigned short	nport;
  	struct sockaddr sa;
  	socklen_t sa_len;
#ifdef WIN32
  SOCKET conn_fd;
	unsigned long nonblockopt = 1;
#else
  int conn_fd;
#endif
 
	conn_fd = socket(PF_INET, SOCK_STREAM, 0);

#ifdef WIN32
	if (conn_fd == INVALID_SOCKET)
#else
	if (conn_fd < 0)
#endif
		sys_err("setup_connect_socket");

#ifdef WIN32
	ioctlsocket(conn_fd, FIONBIO, &nonblockopt);
#else
	flags = fcntl(conn_fd,F_GETFL);
  	fcntl(conn_fd, F_SETFL, flags | O_NONBLOCK);
#endif

  	sockopt = 1;
#ifdef WIN32
	if (setsockopt(conn_fd, SOL_SOCKET, SO_KEEPALIVE, (char*)&sockopt, sizeof(sockopt)))
    		sys_err("setsockopt-keepalive");
#else
  	if (setsockopt(conn_fd, SOL_SOCKET, SO_KEEPALIVE, &sockopt, sizeof(sockopt)))
    		sys_err("setsockopt-keepalive");
#endif

   	memset(&sa,0,sizeof(sa));
	sa.sa_family = PF_INET;
   	if (bind(conn_fd, &sa, sizeof(sa)) < 0)
   		perror("bind");

  	sa_len = sizeof(sa);
  	if (getsockname(conn_fd, &sa, &sa_len))
		sys_err("getsockname");


	memset(&sin, 0, sizeof(sin));
	sin2 = (struct sockaddr_in *)&sa;
	if (debug)
		printf("host = %s, port = %s\n", host, port);
#if defined(HAVE_INET_ATON) || defined(HAVE_LIBRESOLV)
	if (inet_aton(host, &sin.sin_addr) != 1)
		sys_err(host);
#else
	if ( (sin.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE)
		sys_err("inet_addr");
#endif
	*lport = ntohs(sin2->sin_port);
	nport = (unsigned short)strtol(port, &ep, 10);
	sin.sin_port = htons(nport);
	sin.sin_family = PF_INET;
	if (connect(conn_fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
#ifdef WIN32
		errno = WSAGetLastError();
#endif
    		if (errno == ECONNREFUSED) {
				*result = 3;
#ifdef WIN32
			} else if (errno == WSAECONNABORTED) { // i.e. blocked by firewall or such
				*result = 4; 
#endif
    		} else {
				if (errno != EINPROGRESS) {
					if (debug) printf("socket error is %d", errno);
					sys_err("connect");
				}
    			*result = 1; /* Nonblocking operation */
    		}
  	} else
		*result = 0; /* Connected */

  	return conn_fd;
}

#ifdef WIN32

extern int in_service;

void dns_helper(void *arg) { // __cdecl 
	SOCKET *sarg = (SOCKET*)arg;
	SOCKET read_fd = sarg[0];
	SOCKET write_fd = sarg[1];	
#else
void dns_helper(int read_fd, int write_fd) {
#endif
	struct dns_msg dns;
  	ssize_t bytes;

	struct sockaddr_in saddr;
	struct hostent *hptr;

#ifdef HAVE_SETPROCTITLE
  	char sp[40];
  	unsigned int serv = 0;
#endif
  	for(;;) {
#ifdef HAVE_SETPROCTITLE
    		snprintf(sp, sizeof(sp), "tlswrap-dns (serviced %u reqs)",
		    serv++);
    		setproctitle(sp);
#endif
    		bytes = read(read_fd, &dns, sizeof(dns));
    		if (bytes == 0) {
      			if (debug)
					printf("Parent died, exiting...\n");
#ifdef WIN32
//				if  (in_service)
//					closesocket(pipe1[1]);
//x			closesocket(pipe1[0]);
//x			closesocket(pipe2[0]);
//x			closesocket(pipe2[1]);
				closesocket(write_fd);
				_endthread();
//				else
#endif
					exit(0);
			}

		memset(&saddr, 0, sizeof(saddr));
		if ((hptr = gethostbyname(dns.hostname)) == NULL)
			dns.hostname[0] = '\0';
		else    {
			memcpy(&saddr.sin_addr, hptr->h_addr,
			    sizeof(saddr.sin_addr));
			strlcpy(dns.hostname, inet_ntoa(saddr.sin_addr),
			    sizeof(dns.hostname));
		}
    		bytes = write(write_fd, &dns, sizeof(dns));
  	}
  
}

#ifdef WIN32
SOCKET
#else
int
#endif
setup_listen(int max_users, const char *host, char *port, int portlen, int data_flag)
{
	/* IP V4 only version */

	/* Returns a non-blocking listening socket on the specified port.
	 Listen backlog is set to max_users. if portlen != 0 then blah */
	   
	int flags, sockopt;
	unsigned short rport;
	socklen_t slen;
	//*port = "\056314";

	struct sockaddr_in sin;
	char *ep;
	struct hostent *hptr;
#ifdef WIN32
	unsigned long nonblockopt = 1;
	SOCKET listen_socket;
#else
  int listen_socket;
#endif

			
	rport = (unsigned short)strtol(port, &ep, 10);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_port = htons(rport);
	//add data_connection_port, if data_flag = 1, then use 56234 port to transfer data
	if(data_flag == 1)
	{
		sin.sin_port = htons(56234);
	}
	
	if (host == NULL)
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
	else {
		if ((hptr = gethostbyname(host)) == NULL) {
			printf("hostname = %s\n", host);
			sys_err("can't resolve specified local hostname");
		} else
				memcpy(&sin.sin_addr, hptr->h_addr, sizeof(sin.sin_addr));
	}
	listen_socket = socket(PF_INET, SOCK_STREAM, 0);

#ifdef WIN32
	if (listen_socket == INVALID_SOCKET)
#else
  if (listen_socket < 0) 
#endif
		sys_err("socket_listen_ipv4");

	sockopt = 1;
#ifdef WIN32
	if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&sockopt,
	    sizeof(sockopt)))
		sys_err("setsockopt-reuseaddr");
#else
	if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &sockopt,
	    sizeof(sockopt)))
		sys_err("setsockopt-reuseaddr");
#endif

	if (bind(listen_socket, (struct sockaddr *)&sin, sizeof(sin)))
		sys_err("bind");

	slen = sizeof(struct sockaddr_in);
        if (getsockname(listen_socket, (struct sockaddr*)&sin, &slen) < 0)
		sys_err("getsockname");

	if (listen(listen_socket, max_users))
		sys_err("listen");


#ifdef WIN32
	ioctlsocket(listen_socket, FIONBIO, &nonblockopt);
#else
    flags = fcntl(listen_socket, F_GETFL);
	fcntl(listen_socket, F_SETFL, flags | O_NONBLOCK);
#endif
	if (portlen > 0)
		snprintf(port, portlen, "%u", ntohs(sin.sin_port));
	//printf("--------------port init with %s----------------", sin.sin_port);
	return listen_socket;
}


int get_local_ip(int fd, char *ip, int iplen)
{
	socklen_t slen;
	struct sockaddr_in sin;

    slen = sizeof(struct sockaddr_in); 
	if (getsockname(fd, (struct sockaddr*)&sin, &slen) < 0)
		sys_err("getsockname");

	strlcpy(ip, inet_ntoa(sin.sin_addr), iplen);
	//strlcpy(ip, "10.204.51.27", iplen);


	return 0;
}

int get_remote_ip(int fd, char *ip, int iplen)
{
	socklen_t slen;
	struct sockaddr_in sin;

    slen = sizeof(struct sockaddr_in); 
	if (getpeername(fd, (struct sockaddr*)&sin, &slen) < 0)
		sys_err("getsockname");

	strlcpy(ip, inet_ntoa(sin.sin_addr), iplen);
	return 0;
}
