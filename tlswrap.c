
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

#define _POSIX_PII_SOCKET /* for Tru64 UNIX 5.1 */

#define TLSWRAP_VERSION_TEXT "v1.04"

#ifdef WIN32
#include "stdafx.h"
#endif

#include "conf.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#include <Winsock2.h>
#include <windows.h>
#include <process.h>    /* _beginthread, _endthread */
#include <direct.h>
#define snprintf _snprintf
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define chdir _chdir
#define mkdir _mkdir
#define getcwd _getcwd
typedef int socklen_t;
#ifdef WIN64
typedef   __int64 ssize_t;
#else
typedef   __int32 ssize_t;
#endif
#define ECONNREFUSED WSAECONNREFUSED
#define EINPROGRESS WSAEINPROGRESS
#define EWOULDBLOCK WSAEWOULDBLOCK
#define ECONNRESET WSAECONNRESET
int write(SOCKET s, void *buf, int len);
int read(SOCKET s, void *buf, int len);
#define close closesocket
char *srv_name = "TLSWrap";
char *srv_name2 = "TLSWrap Service";
char *srv_desc = "TLSWrap is a TLS/SSL FTP wrapper";
#else
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include "tlswrap.h"
#include "network.h"
#include "misc.h"
#include "parse.h"
#include "tls.h"
#include "config.h"

char	*cfg_tlsrsafile;
char	*cfg_tlsciphers;

int		debug;
int		sec_mode;
int		dns_write_pipe, dns_read_pipe, pipe1[2], pipe2[2];

#ifdef WIN32
int		in_service;
struct	parm serv_param;
#endif


#ifdef HAVE_LIBWRAP
#include <tcpd.h>

int allow_severity;
int deny_severity;
#endif

int main2(int argc, char *argv[]);

int main(int argc, char *argv[])
{
#if defined(WIN32) && !defined(WIN98)
	SERVICE_TABLE_ENTRY servicetable[]=
	{
		{srv_name,(LPSERVICE_MAIN_FUNCTION)service_main},
		{NULL,NULL}
	};
	serv_param.argc = argc;
	serv_param.argv = argv;
	in_service = 0;
	if ((argc >= 2) && !strcmp(argv[1], "-S")) {
		in_service = 1;
		StartServiceCtrlDispatcher(servicetable);
	}
	else
#endif
	return main2(argc, argv);
}

#if defined(WIN32) && !defined(WIN98)
DWORD service_execution_thread(LPDWORD param) {
	return main2(serv_param.argc, serv_param.argv);
}
#endif

int main2(int argc, char *argv[]) {
#ifndef WIN32
	struct	sigaction sact;
	pid_t 	childpid;
	struct	rlimit rlimit;
	int		flags;
#ifndef __CYGWIN__
	char	fakebuf[1];
	int		sock_err;
	socklen_t sock_errlen;
#endif
#else
	WORD	wVersionRequested;
	WSADATA wsaData;
	char 	port[6] ;//, tport[6];
	SOCKET	temp_sock;
	int		conn_res;
	unsigned int lport;
	SOCKET  arg[2];
	unsigned long sockarg;
#endif
#if defined(WIN32) || defined(__CYGWIN__)
	fd_set	eset;
#endif
	char	buffer[NI_MAXHOST];
	int 	listen_fd;
	int		idx;
	int		i, sel, newsock;
	int		remove_this,  serv_write;
	char 	cfg_listenport[6];
	char	cfg_egdsock[NI_MAXHOST];
	char	cfg_listenhost[NI_MAXHOST];
	char	cfg_instopt[NI_MAXHOST];
	unsigned int cfg_max_users;
	fd_set  rset, wset;
	struct	sockaddr sockaddr;
	socklen_t	socklen;
	struct	user_data *ud;
	struct	dns_msg dns;
	unsigned int	tcpbufsize, tcpsndlowat;
	ssize_t bytes, bytesW;
	char	token[6];
	char	certspath[1024];
	char	ucertspath[1024];
	char	cfg_cafile[1024];
	char	crlfile[1024];
	int		conn_err, serv_remove, serv_install, key_wait;
	char remoteip[NI_MAXHOST];
	if ( (cfg_tlsciphers = (char*)malloc(1024)) == NULL)
		exit(1);

#ifndef WIN32
	rlimit.rlim_cur = RLIM_INFINITY;
	rlimit.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_CORE, &rlimit);
#else
	wVersionRequested = MAKEWORD(2,0);
 
	if (WSAStartup(wVersionRequested, &wsaData)) {
		MessageBox(NULL, "Can't initialize WinSock 2.0", "TLSWrap", MB_OK |
			MB_ICONERROR);
		exit(0);
	}
	if(!SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE)) {
		printf("Can't set control handler\n");
	}		

#endif

	read_config(argc, argv, &cfg_max_users, cfg_listenport, 
	    sizeof(cfg_listenport), &debug,
	    cfg_egdsock, sizeof(cfg_egdsock), cfg_tlsciphers,
	    1024, &tcpbufsize, &tcpsndlowat, cfg_listenhost,
	    sizeof(cfg_listenhost), token, sizeof(token), &sec_mode,
	    certspath, sizeof(certspath), &serv_install, &serv_remove, &key_wait,
		cfg_instopt, sizeof(cfg_instopt), ucertspath, sizeof(ucertspath),
		cfg_cafile, sizeof(cfg_cafile), crlfile, sizeof(crlfile));

	if ( (ud = (struct user_data*)malloc(cfg_max_users *
		    sizeof(struct user_data))) == NULL) {
		fprintf(stderr,"can't malloc user_data");
		exit(1);
	}

#if defined(WIN32) && !defined(WIN98)
	if (serv_install) {
		if(_getcwd(buffer, NI_MAXHOST) == NULL )
			perror("_getcwd error" );
		install_service(buffer, cfg_instopt, key_wait);
	} else if (serv_remove)
		remove_service(key_wait);
#endif

	if (1) { //if (sec_mode > 0) {
#ifndef WIN32
		umask(077);
#endif
		if (certspath[0] != '\0') {
			if (chdir(certspath))
				sys_err("unable to access certs dir");
		} else {
			if (chdir("certs")) {
#ifndef WIN32
				if (mkdir("certs", 0700))
#else
				if (mkdir("certs"))
#endif
					sys_err("unable to create certs dir");
				if (chdir("certs"))
					sys_err("unable to access certs dir");
			}
			if (getcwd(certspath, sizeof(certspath)) == NULL)
				sys_err("certspath getcwd");
		}
	}
	
	if (debug) {
		printf("certspath = %s\nucertspath = %s\n", certspath, ucertspath);	
	}
	tls_init(cfg_egdsock);

#ifndef WIN32
	sact.sa_handler = SIG_IGN;
	sigemptyset(&sact.sa_mask);
	sact.sa_flags = 0;
	sigaction(SIGPIPE, &sact, NULL);
#endif

#ifdef HAVE_SETPROCTITLE
  	setproctitle("tlswrap");
#endif

#ifndef WIN32

	if (pipe(pipe1)) sys_err("pipe1");
	if (pipe(pipe2)) sys_err("pipe2");

	if ( (childpid = fork()) == 0) {
		close(pipe1[1]);
		close(pipe2[0]);
		dns_helper(pipe1[0], pipe2[1]);
	} else {
		close(pipe1[0]);
		close(pipe2[1]);
	}

	dns_write_pipe = pipe1[1];
	dns_read_pipe  = pipe2[0];

	flags = fcntl(dns_write_pipe, F_GETFL);
	fcntl(dns_write_pipe, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(dns_read_pipe, F_GETFL);
	fcntl(dns_read_pipe, F_SETFL, flags | O_NONBLOCK);

#else
	port[0] = '\0';
	temp_sock = setup_listen(5, "127.0.0.1", port, sizeof(port),0);
	if (debug)
		printf("listening to port %s for pipe setup\n", port);
	pipe1[0] = setup_connect("127.0.0.1", port, &lport, &conn_res);
	if (conn_res == 0) { /* connected OK */
		if ((pipe1[1] = accept(temp_sock, NULL, NULL)) == INVALID_SOCKET)
			sys_err("setup error for fake pipe");
	} else if (conn_res != 1) sys_err("local pipe connect1");
	FD_ZERO(&rset);
	FD_SET(temp_sock, &rset);
	select(1, &rset, NULL, NULL, NULL);
	//if (FD_ISSET(pipe1[0], &wset)) {
	if (FD_ISSET(temp_sock, &rset)) {
		if ((pipe1[1] = accept(temp_sock, NULL, NULL)) == INVALID_SOCKET){
			printf("setup error for fake pipe1: %d\n", WSAGetLastError());
			exit(0);
		}
	} else sys_err("could not connect to local pipe 1");


	pipe2[1] = setup_connect("127.0.0.1", port, &lport, &conn_res);
	if (conn_res == 0) { /* connected OK */
		if ((pipe2[0] = accept(temp_sock, NULL, NULL)) == INVALID_SOCKET)
			sys_err("setup error for fake pipe");
	} else if (conn_res != 1) sys_err("local pipe connect2");
	FD_ZERO(&rset);
	FD_SET(temp_sock, &rset);
	select(1, &rset, NULL, NULL, NULL);
	if (FD_ISSET(temp_sock, &rset)) {
		if ((pipe2[0] = accept(temp_sock, NULL, NULL)) == INVALID_SOCKET) {
			printf("setup error for fake pipe2: %d\n", WSAGetLastError());
			exit(0);
		}
	} else sys_err("could not connect to local pipe 2");

	if (closesocket(temp_sock) == SOCKET_ERROR)
		printf("error closing listening socket because %d\n", WSAGetLastError());

	dns_write_pipe = pipe1[1];
	dns_read_pipe  = pipe2[0];

	/* Turn off non-blocking for sockets to be used in the DNS helper */

	sockarg = 0;

	if (ioctlsocket(pipe1[0], FIONBIO, &sockarg) ==  SOCKET_ERROR) {
		printf("ioctlsocket 1 failed because %d\n", WSAGetLastError());
		exit(-1);
	}

	if (ioctlsocket(pipe2[1], FIONBIO, &sockarg) ==  SOCKET_ERROR) {
		printf("ioctlsocket 2 failed because %d\n", WSAGetLastError());
		exit(-1);
	}
	arg[0] = pipe1[0];
	arg[1] = pipe2[1];

	_beginthread((dns_helper), 0, &arg);

#endif /* WIN32 */

	/* Do blocking DNS requests before this (if any) */

	init_ud(ud, cfg_max_users);

	listen_fd = setup_listen(5, cfg_listenhost, cfg_listenport, 0,0);

	fprintf(stderr,
	    "TLSWrap %s (c) 2002-2006 Tomas Svensson <ts@codepix.com> Modified by SylarHuang\n", TLSWRAP_VERSION_TEXT);
	fprintf(stderr, "Servicing up to %u clients on %s:%s\n", cfg_max_users, cfg_listenhost, cfg_listenport);
#if !defined __CYGWIN__ && !defined WIN32
#ifdef __HAVE_DAEMON
	if (!debug)
		daemon(0 ,0);
#else
	if (!debug) {
		if ( (childpid = fork()) < 0)
			sys_err("fork()");
		else if (childpid != 0) {
			fprintf(stderr, "Running as process %u\n", (unsigned int)childpid);
			exit(0); /* parent */
		}
		(void)setsid();
		if (certspath[0] == '\0')
			chdir("/"); 
	}
#endif /* !HAVE_DAEMON */
#endif /* !__CYGWIN__ */

 	for(;;) {
		FD_ZERO(&rset);
		FD_ZERO(&wset);
#if defined(WIN32) || defined(__CYGWIN__)
		FD_ZERO(&eset);
#endif
		FD_SET(listen_fd, &rset);
		FD_SET(dns_read_pipe, &rset);

		for(i = 0; i < cfg_max_users ; i++) {
			if (ud[i].user_fd != -1) {
				/* If there is room in the buffer, read from the user control connection */
				if (ud[i].u2s_i < &ud[i].u2s_buf[U2S_SIZE]) {
					FD_SET(ud[i].user_fd, &rset);
				}
				/* If there is room in the buffer and we are connected,
					read from the server control connection */
				if ((ud[i].connected == CONN_YES) &&
					(ud[i].s2u_i < &ud[i].s2u_buf[S2U_SIZE])) {
					FD_SET(ud[i].serv_fd, &rset);
					//printf("----------------------%d---------------create",ud[i].lport);
				}
				else if (ud[i].connected == CONN_IN_PROG) {
#if defined(WIN32) || defined(__CYGWIN__)
					FD_SET(ud[i].serv_fd, &eset);
#else
					FD_SET(ud[i].serv_fd, &rset);
#endif
					FD_SET(ud[i].serv_fd, &wset);
				}
				if (ud[i].data_connected == CONN_IN_PROG) {
#if defined(WIN32) || defined(__CYGWIN__)
					FD_SET(ud[i].serv_data_fd, &eset);
#else
					FD_SET(ud[i].serv_data_fd, &rset);
#endif
					FD_SET(ud[i].serv_data_fd, &wset);
				} else if (ud[i].data_connected == CONN_DATA_OK) {
					if (ud[i].dc2s_i < 
					    &ud[i].dc2s_buf[DBUF_SIZE])
					 	if (ud[i].user_data_close != CLOSE_READ)
							FD_SET(ud[i].user_data_fd, &rset);
					if (ud[i].ds2c_i <
					    &ud[i].ds2c_buf[DBUF_SIZE])
						if  (ud[i].serv_data_close != CLOSE_READ)
							FD_SET(ud[i].serv_data_fd, &rset);
					if (ud[i].dc2s_i != ud[i].dc2s_o)
						if (ud[i].serv_data_close != CLOSE_WRITE)
							FD_SET(ud[i].serv_data_fd, &wset);
					if (ud[i].ds2c_i != ud[i].ds2c_o)
						if (ud[i].user_data_close != CLOSE_WRITE)
							FD_SET(ud[i].user_data_fd, &wset);
				} else if (ud[i].data_connected == CONN_DATA_LISTEN) {
					FD_SET(ud[i].user_data_fd, &rset);
					if (debug)
						printf("setting fd %d for conn_data_listen\n",ud[i].user_data_fd);
				}
				
				if ((ud[i].connected == CONN_YES) && (ud[i].u2s_i != ud[i].u2s_o)) {
					FD_SET(ud[i].serv_fd, &wset);
				}
				if ((ud[i].u2s_i - ud[i].u2s_o) < 0)
					sys_err("bug");
				if (ud[i].s2u_i != ud[i].s2u_o) {
					if ((memchr(ud[i].s2u_o, '\n', ud[i].s2u_i-ud[i].s2u_o) != NULL) ||
						(ud[i].s2u_i == &ud[i].s2u_buf[S2U_SIZE]))
						//(memchr(ud[i].s2u_o, '\n', ud[i].s2u_i-ud[i].s2u_o) != NULL)  /* should be? */
						FD_SET(ud[i].user_fd, &wset); // memchr crap again
				}


				if (ud[i].retry)
					FD_SET(ud[i].user_fd, &wset);
				if (ud[i].retry_data)
					FD_SET(ud[i].user_data_fd, &wset);

				/* TLS connection negotiation */

				if (ud[i].ssl_ctrl_fd_mode == TLS_READ) {
					if (debug)
						printf("TLS_READ: fd = %d\n", ud[i].serv_fd);
					FD_SET(ud[i].serv_fd, &rset);
					FD_CLR(ud[i].serv_fd, &wset);
				} else if (ud[i].ssl_ctrl_fd_mode == TLS_WRITE) {
					FD_SET(ud[i].serv_fd, &wset);
					FD_CLR(ud[i].serv_fd, &rset);
				}

				if (ud[i].ssl_data_fd_mode == TLS_READ) {
					if (debug)
						printf("setting serv_data_fd (%d) in rset for TLS_READ\n", ud[i].serv_data_fd);
					FD_SET(ud[i].serv_data_fd, &rset); 
					FD_CLR(ud[i].serv_data_fd, &wset);
				} else if (ud[i].ssl_data_fd_mode == TLS_WRITE) {
					if (debug)
						printf("setting serv_data_fd (%d) in wset for TLS_WRITE\n", ud[i].serv_data_fd);
					FD_SET(ud[i].serv_data_fd, &wset);
					FD_CLR(ud[i].serv_data_fd, &rset);
				}
			} /* if fd */

		} /* for */

		/*
		max_fd = find_max_fd((dns_read_pipe > listen_fd) ?
		    dns_read_pipe : listen_fd, ud, cfg_max_users);
		 max_fd = find_max_fd(&rset, &wset);

		if (debug)
			printf("max_fd = %d\n",max_fd);
		*/
#if 0
		
		if (debug) {
			printf("listening for:\n");
			i = 0;
			if (FD_ISSET(ud[i].user_fd, &rset))
				printf("user_fd readable\n");
			if (FD_ISSET(ud[i].user_fd, &wset))
				printf("user_fd writable\n");
			if (FD_ISSET(ud[i].serv_fd, &rset))
				printf("serv_fd readable\n");
			if (FD_ISSET(ud[i].serv_fd, &wset))
				printf("serv_fd writable\n");
			if (FD_ISSET(ud[i].user_data_fd, &rset))
				printf("user_data_fd (%d) readable\n", ud[i].user_data_fd);
			if (FD_ISSET(ud[i].user_data_fd, &wset))
				printf("user_data_fd (%d) writable\n", ud[i].user_data_fd);
			if (FD_ISSET(ud[i].serv_data_fd, &rset))
				printf("serv_data_fd (%d) readable\n", ud[i].serv_data_fd);
			if (FD_ISSET(ud[i].serv_data_fd, &wset))
				printf("serv_data_fd (%d) writable\n", ud[i].serv_data_fd);
#ifdef WIN32
			if (FD_ISSET(ud[i].serv_data_fd, &eset))
				printf("serv_data_fd (%d) exception\n", ud[i].serv_data_fd);
			if (FD_ISSET(ud[i].serv_fd, &eset))
				printf("serv_fd (%d) exception\n", ud[i].serv_fd);
#endif
		}
#endif

#if defined(WIN32) || defined(__CYGWIN__)
		sel = select(FD_SETSIZE, &rset, &wset, &eset, NULL);
#else
		sel = select(FD_SETSIZE, &rset, &wset, NULL, NULL);
#endif
#if 0
		if (debug) {
			printf("result is :\n");
			i = 0;
			if (FD_ISSET(ud[i].user_fd, &rset))
				printf("user_fd readable\n");
			if (FD_ISSET(ud[i].user_fd, &wset))
				printf("user_fd writable\n");
			if (FD_ISSET(ud[i].serv_fd, &rset))
				printf("serv_fd readable\n");
			if (FD_ISSET(ud[i].serv_fd, &wset))
				printf("serv_fd writable\n");
			if (FD_ISSET(ud[i].user_data_fd, &rset))
				printf("user_fd readable\n");
			if (FD_ISSET(ud[i].user_data_fd, &wset))
				printf("user_fd writable\n");
			if (FD_ISSET(ud[i].serv_data_fd, &rset))
				printf("serv_fd readable\n");
			if (FD_ISSET(ud[i].serv_data_fd, &wset))
				printf("serv_fd writable\n");
#ifdef WIN32
			if (FD_ISSET(ud[i].serv_data_fd, &eset))
				printf("serv_data_fd (%d) exception\n", ud[i].serv_data_fd);
			if (FD_ISSET(ud[i].serv_fd, &eset))
				printf("serv_fd (%d) exception\n", ud[i].serv_fd);
#endif
			if (FD_ISSET(dns_read_pipe, &rset))
				printf("dns read pipe\n");
			if (FD_ISSET(listen_fd, &rset))
				printf("listen_fd\n");
			printf("---------------------\n");
		} 
		if (sel == -1) {
#ifdef WIN32
			printf("select failed because %d\n", WSAGetLastError());
#endif
			sys_err("select");
		}	
#endif
		if (debug)
			printf("selected\n");
		if (FD_ISSET(dns_read_pipe, &rset)) {
			if ( (bytes = read(dns_read_pipe, &dns, sizeof(dns)))
			    == sizeof(dns) ) {
				if ((ud[dns.ud].user_fd != -1) && (ud[dns.ud].connected == CONN_DNS)) {
					ud[dns.ud].serv_dns = dns; /* use for EPSV later */
					setup_connect_2(&ud[dns.ud], &dns, 0);
				}
			} else {
#ifdef WIN32
					printf("Exiting...\n");
					WSACleanup();
					if (in_service)
						_endthread();
					else
						exit(0);
#endif
				sys_err("child died");
			}
		}
		if (FD_ISSET(listen_fd, &rset)) {
			memset(&sockaddr, 0, sizeof(sockaddr));
			socklen = sizeof(sockaddr);
			if ( (newsock = accept(listen_fd, &sockaddr, &socklen)) != -1) {
				idx = find_free_slot(ud, cfg_max_users);
				if (idx==-1) {
					write(newsock, "No more users allowed.\r\n", 24);
					close(newsock);
				} else {
					memset(&ud[idx], 0, sizeof(struct user_data));
					ud[idx].u2s_i = ud[idx].u2s_o = ud[idx].u2s_buf;
					ud[idx].s2u_i = ud[idx].s2u_o = ud[idx].s2u_buf;
					ud[idx].user_ptr = ud[idx].user_input;
					ud[idx].serv_ptr = ud[idx].serv_input;
					ud[idx].connected = CONN_NO;
					ud[idx].data_connected = CONN_NO;
					ud[idx].serv_status = SERV_NONE;
					ud[idx].serv_data_fd = -1;
					ud[idx].user_fd = newsock;
					ud[idx].ssl_data_fd_mode = TLS_NONE;
					ud[idx].ssl_ctrl_fd_mode = TLS_NONE;
					ud[idx].sec_level = sec_mode;
					if (debug)
						printf("connected to user\n");
					snprintf(buffer, sizeof(buffer), "220 TLSWrap FTP Proxy Server (%s) - Modifed by SylarHuang  ready.\r\n", TLSWRAP_VERSION_TEXT);
					print_to_ud(&ud[idx], buffer);
				}
			} /*else {
				printf("accept failed\n");
			}*/
		}
		for(i = 0; i < cfg_max_users; i++) {
			remove_this = 0;
			serv_write = 0;
			if (ud[i].user_fd != -1) {

				/* TLS section */

				if (ud[i].serv_status == SERV_TLS) {
					if (debug)
						printf("checking TLS status\n");
					if ( ((ud[i].ssl_ctrl_fd_mode == TLS_READ) && FD_ISSET(ud[i].serv_fd, &rset)) || 
						((ud[i].ssl_ctrl_fd_mode == TLS_WRITE) && FD_ISSET(ud[i].serv_fd, &wset)) ) {
						tls_auth_cont(&ud[i], 0);
						continue;
					}
				}
				if (ud[i].data_connected == CONN_DATA_TLS) {
					if (debug)
						printf("checking conn_data_tls\n");
					if ( ((ud[i].ssl_data_fd_mode == TLS_READ) && FD_ISSET(ud[i].serv_data_fd, &rset)) ||
						((ud[i].ssl_data_fd_mode == TLS_WRITE) && FD_ISSET(ud[i].serv_data_fd, &wset)) ) {
						tls_auth_cont(&ud[i], 1);
						continue;
					}
				}

				/* TLS fd swapping */

				if (ud[i].tls_status & TLS_CTRL) {
					if (ud[i].ssl_ctrl_fd_mode == TLS_READ && FD_ISSET(ud[i].serv_fd, &rset) &&
				      ud[i].ssl_ctrl_func == TLS_WRITE) {
						FD_SET(ud[i].serv_fd, &wset);
						FD_CLR(ud[i].serv_fd, &rset);
					} else if (ud[i].ssl_ctrl_fd_mode == TLS_WRITE && FD_ISSET(ud[i].serv_fd, &wset) &&
				     ud[i].ssl_ctrl_func == TLS_READ) {
						FD_SET(ud[i].serv_fd, &rset);
						FD_CLR(ud[i].serv_fd, &wset);
					}
				}

				if (ud[i].tls_status & TLS_DATA) {
					if (ud[i].ssl_data_fd_mode == TLS_READ && FD_ISSET(ud[i].serv_data_fd, &rset) &&
					  ud[i].ssl_data_func == TLS_WRITE) {
						FD_SET(ud[i].serv_data_fd, &wset);
						FD_CLR(ud[i].serv_data_fd, &rset);
					} else if ( ud[i].ssl_data_fd_mode == TLS_WRITE && FD_ISSET(ud[i].serv_data_fd, &wset) &&
						ud[i].ssl_data_func == TLS_READ) { 
						FD_SET(ud[i].serv_data_fd, &rset);
						FD_CLR(ud[i].serv_data_fd, &wset);
					}       
				}       

				/* Read Section */


				if (ud[i].connected == CONN_YES) {
					if ((ud[i].retry && FD_ISSET(ud[i].user_fd,  &wset)) ||
					  FD_ISSET(ud[i].serv_fd, &rset)) {
						if ((debug) && (ud[i].retry))
							printf("retry set\n");
						if (ud[i].tls_status & TLS_CTRL)
							bytes = tls_read(&ud[i], ud[i].s2u_i, &ud[i].s2u_buf[S2U_SIZE] - ud[i].s2u_i,0);
						else
							bytes = read(ud[i].serv_fd, ud[i].s2u_i, &ud[i].s2u_buf[S2U_SIZE] - ud[i].s2u_i);

						ud[i].retry = 0;
						if (bytes < 0) {
#ifdef WIN32
							errno = WSAGetLastError();
#endif 
							if (errno != EWOULDBLOCK) {
								perror("server_read");
								user_close(&ud[i]); /* inte data_close! */
							}
							continue;
						} else if ((bytes == 0) && ((&ud[i].s2u_buf[S2U_SIZE] - ud[i].s2u_i) > 0)){
							FD_CLR(ud[i].serv_fd,&wset);
							FD_CLR(ud[i].user_fd,&rset);
							user_close(&ud[i]);
							remove_this = 1;
						} else {
							if (bytes == (&ud[i].s2u_buf[S2U_SIZE] - ud[i].s2u_i)) {
								if (debug)
									printf("filled buffer - retrying\n");
								ud[i].retry = 1;
							}
							ud[i].s2u_i += bytes;
							FD_SET(ud[i].user_fd, &wset); /* Try to write this data below */
							if (debug) {
								printf("read %lu bytes from server control, trying to write later\n", (unsigned long)bytes);
								//printf("%s\n", (char*)(ud[i].s2u_i-bytes));
							}
						}
					}
				}
				
				if (ud[i].data_connected == CONN_DATA_OK)  {
					if ((ud[i].retry_data && FD_ISSET(ud[i].user_data_fd,  &wset)) ||
					FD_ISSET(ud[i].serv_data_fd, &rset)) {
						if (ud[i].tls_status & TLS_DATA)
							bytes = tls_read(&ud[i], ud[i].ds2c_i, 
							    &ud[i].ds2c_buf[DBUF_SIZE] - ud[i].ds2c_i, 1);
						else
							bytes = read(ud[i].serv_data_fd, ud[i].ds2c_i,
							    &ud[i].ds2c_buf[DBUF_SIZE] - ud[i].ds2c_i);
						ud[i].retry_data = 0;
						if (bytes < 0) {
#ifdef WIN32
							errno = WSAGetLastError();
#endif
							if (errno != EWOULDBLOCK) {
#ifdef WIN32
								printf("bytes = %u, err = %d\n", bytes, WSAGetLastError());
#endif
								perror("server_data_read1");
								data_close(&ud[i]);
							}
							continue;
						} else if ((bytes == 0) && ((&ud[i].ds2c_buf[DBUF_SIZE] - ud[i].ds2c_i) > 0) ){
								ud[i].serv_data_close = CLOSE_READ;
								if (debug)
									printf("setting CLOSE_READ in serv_data_close\n");
								if (ud[i].serv_read_cnt > 0) /* va? */
									ud[i].user_data_close = CLOSE_READ;
						} else {
							if (bytes == (&ud[i].ds2c_buf[DBUF_SIZE] - ud[i].ds2c_i)) {
								if (debug)
									printf("filled data buffer - retrying\n");
								ud[i].retry_data = 1;
							}
							if (debug)
								printf("read %ld bytes from serv_data_fd\n", (long)bytes);
							ud[i].ds2c_i += bytes;
							ud[i].serv_read_cnt += bytes;
							FD_SET(ud[i].user_data_fd, &wset); /* Try to write this data below */ 
						}
					}

					if (FD_ISSET(ud[i].user_data_fd, &rset)) {
						bytes = read(ud[i].user_data_fd, ud[i].dc2s_i,
						    &ud[i].dc2s_buf[DBUF_SIZE] - ud[i].dc2s_i);
						if (bytes < 0) {
#ifdef WIN32
							errno = WSAGetLastError();
#endif
							if (errno != EWOULDBLOCK) {
#ifdef WIN32
								printf("bytes = %u, err = %d\n", bytes, WSAGetLastError());
#endif
								perror("server_data_read");
								data_close(&ud[i]);
							}
							continue;
						} else if (bytes == 0) {
								ud[i].user_data_close = CLOSE_READ;
								if (ud[i].user_read_cnt > 0)
									ud[i].serv_data_close = CLOSE_READ;
								if (debug)
									printf("setting CLOSE_READ in user_data_close\n");
						} else {
							if (debug)
								printf("read %ld bytes from user_data_fd\n", (long)bytes);
							ud[i].dc2s_i += bytes;
							ud[i].user_read_cnt += bytes;
							FD_SET(ud[i].serv_data_fd, &wset); /* Try to write this data below */
						}
					}

				}
				if (ud[i].connected == CONN_YES && ud[i].data_connected == CONN_DATA_LISTEN) {
					if (debug)
						printf("conn_data_listen\n");
					if (FD_ISSET(ud[i].user_data_fd, &rset)) {
							if (debug)
								printf("trying to accept user data connection\n");
							if ( (newsock = accept(ud[i].user_data_fd, &sockaddr, &socklen)) != -1) {
								close(ud[i].user_data_fd);
								if (ud[i].active) {
									ud[i].user_data_fd = ud[i].serv_data_fd;
									ud[i].serv_data_fd = newsock;
									get_remote_ip(newsock, remoteip, sizeof(remoteip));
									strlcpy(ud[i].serv_data_host, remoteip, sizeof(ud[i].serv_data_host));
								} else
									ud[i].user_data_fd = newsock;
								ud[i].data_connected = CONN_DATA_OK;
								ud[i].ssl_data_fd_mode = TLS_NONE;
								ud[i].dc2s_i = ud[i].dc2s_o = ud[i].dc2s_buf;
								ud[i].ds2c_i = ud[i].ds2c_o = ud[i].ds2c_buf;
								ud[i].serv_data_close = CLOSE_NONE;
								ud[i].user_data_close = CLOSE_NONE;
								ud[i].user_read_cnt = 0;
								ud[i].serv_read_cnt = 0;
/*	
								(void)setsockopt(ud[i].user_data_fd, SOL_SOCKET, SO_SNDLOWAT, 
								    &tcpsndlowat, sizeof(tcpsndlowat));
								(void)setsockopt(ud[i].serv_data_fd, SOL_SOCKET, SO_SNDLOWAT,
								    &tcpsndlowat, sizeof(tcpsndlowat));
								(void)setsockopt(ud[i].user_data_fd, SOL_SOCKET, SO_SNDBUF,
								    &tcpbufsize, sizeof(tcpbufsize));
								(void)setsockopt(ud[i].serv_data_fd, SOL_SOCKET, SO_SNDBUF,
								    &tcpbufsize, sizeof(tcpbufsize));
								(void)setsockopt(ud[i].user_data_fd, SOL_SOCKET, SO_RCVBUF,
								    &tcpbufsize, sizeof(tcpbufsize));
								(void)setsockopt(ud[i].serv_data_fd, SOL_SOCKET, SO_RCVBUF,
								    &tcpbufsize, sizeof(tcpbufsize));
*/

								ud[i].data_connected = CONN_DATA_TLS;
								if (debug)
									printf("accept'ed client data connection\n");
								tls_auth(&ud[i], 1, ucertspath, cfg_cafile);
							} else
								printf("accept failed\n");
					}
				}

				if (ud[i].user_fd != -1) {
					if (FD_ISSET(ud[i].user_fd,&rset)) {
						if ((bytes = read(ud[i].user_fd, ud[i].u2s_i, &ud[i].u2s_buf[U2S_SIZE]
						  - ud[i].u2s_i)) < 0) {
#ifdef WIN32
							errno = WSAGetLastError();
#endif
							if (errno != EWOULDBLOCK) {
								if (errno != ECONNRESET) {
									perror("user_read");
#ifdef WIN32
									printf("WSAGETLastError = %d\n", errno);
#endif
								}
								user_close(&ud[i]);
							}
						} else if (bytes==0) {
							user_close(&ud[i]);
						} else {
							ud[i].u2s_i += bytes;
							serv_write = 1;
						}
						if (ud[i].u2s_i - ud[i].u2s_o < 0)
							sys_err("bug1");
					}
				}

				/* Write Section */

				if (ud[i].data_connected == CONN_DATA_OK)  {
					if (FD_ISSET(ud[i].serv_data_fd, &wset) && ((bytes = ud[i].dc2s_i - ud[i].dc2s_o) > 0)) {
						if (ud[i].tls_status & TLS_DATA)
							bytesW = tls_write(&ud[i], ud[i].dc2s_o, bytes, 1);
						else
							bytesW = write(ud[i].serv_data_fd, ud[i].dc2s_o, bytes);
#ifdef WIN32
						errno = WSAGetLastError();
#endif
						if (bytesW < 0) {
							if (errno == EPIPE) {
								ud[i].serv_data_close = CLOSE_WRITE;
							}
							else if (errno != EWOULDBLOCK) {
								perror("serv_data_fd_write");
								data_close(&ud[i]);
							}
							continue;
						} else {
							if (debug)
								printf("wrote %ld bytes to serv_data_fd (of %ld requested)\n", 
									(long)bytesW, (long)bytes);
							ud[i].dc2s_o += bytesW;
							if (ud[i].dc2s_o == ud[i].dc2s_i)
								ud[i].dc2s_o = ud[i].dc2s_i = ud[i].dc2s_buf;
						}
					}
						
					if (FD_ISSET(ud[i].user_data_fd, &wset) && ((bytes = ud[i].ds2c_i - ud[i].ds2c_o) > 0)) {
						bytesW = write(ud[i].user_data_fd, ud[i].ds2c_o, bytes);
						if (bytesW < 0) {
#ifdef WIN32
							errno = WSAGetLastError();
#endif
							if (errno == EPIPE) {
								ud[i].user_data_close = CLOSE_WRITE;
							}
							if (errno != EWOULDBLOCK) {
								perror("user_data_fd_write");
								data_close(&ud[i]);
							}
							continue;
						} else {
							 if (debug)
								printf("wrote %ld bytes to user_data_fd (of %ld requested)\n",
								    (long)bytesW, (long)bytes);
							ud[i].ds2c_o += bytesW;
							if (ud[i].ds2c_o == ud[i].ds2c_i)
								ud[i].ds2c_o = ud[i].ds2c_i = ud[i].ds2c_buf;
						}
					}

					if ( ( (ud[i].data_direction == DATA_DOWN && ud[i].serv_data_close == CLOSE_READ) ||
					     (ud[i].data_direction == DATA_UP && ud[i].user_data_close == CLOSE_READ) || 
					     (ud[i].serv_data_close == CLOSE_READ && ud[i].user_data_close == CLOSE_READ) ) &&
					     (ud[i].ds2c_o == ud[i].ds2c_i && ud[i].dc2s_o == ud[i].dc2s_i) )  {
						data_close(&ud[i]);
						if (debug)
							printf("data connection totally closed\n");
					}
/*
					if ( ud[i].ctrl_close ) &&
					     (ud[i].u2s_o == ud[i].u2s_i && ud[i].s2u_o == ud[i].s2u_i) )  {
						user_close(&ud[i]);
						if (debug)
							printf("user connection totally closed\n");
					}
*/
				} /* ud[i].data_connected == CONN_DATA_OK */

				/*
				if ((ud[i].connected == CONN_YES) || (ud[i].connected == CONN_IN_PROG)) {
					if (FD_ISSET(ud[i].serv_fd, &wset) && ((bytes = ud[i].u2s_i - ud[i].u2s_o) > 0))
						serv_write = 1;
				} else
				*/
				if ((bytes = ud[i].u2s_i - ud[i].u2s_o) > 0) 
					serv_write = 1; /* OK? */

				if (serv_write) {
					if (ud[i].connected != CONN_YES) {
						if ( (&ud[i].user_input[BUF_SIZE] - ud[i].user_ptr) >= bytes) {
							/* There is room in the user buffer for this data */
							memcpy(ud[i].user_ptr, ud[i].u2s_o, bytes);
							ud[i].u2s_o += bytes;
							ud[i].user_ptr += bytes;
							if (ud[i].u2s_o == ud[i].u2s_i)
								ud[i].u2s_o = ud[i].u2s_i = ud[i].u2s_buf;
						} else
							printf("could not copy user input to user buffer\n");
					} else {
						if (ud[i].prot == 'P') {
							intercept_user_buf(&ud[i], ud[i].u2s_o, &bytes);
							if (bytes == 0)
								ud[i].u2s_i = ud[i].u2s_o;
						}
						if (ud[i].tls_status & TLS_CTRL) 
							bytesW = tls_write(&ud[i], ud[i].u2s_o, bytes, 0);
						else
							bytesW = write(ud[i].serv_fd, ud[i].u2s_o, bytes);
						if (bytesW < 0) {
#ifdef WIN32
							errno = WSAGetLastError();
#endif
							if (errno != EWOULDBLOCK) {
								perror("server_write");
								user_close(&ud[i]);
							}
							continue;
						} else {
							ud[i].u2s_o += bytesW;
							if (ud[i].u2s_o == ud[i].u2s_i)
								ud[i].u2s_o = ud[i].u2s_i = ud[i].u2s_buf;
						}
					}
				}

				if ((bytes = ud[i].s2u_i - ud[i].s2u_o) > 0) {
					if (debug) {
						printf("there are %lu bytes to write", (unsigned long)bytes);
						if ((ud[i].serv_status == SERV_FLOW || ud[i].connected != CONN_YES ) && FD_ISSET(ud[i].user_fd,&wset) && 
						(memchr(ud[i].s2u_o, '\n', bytes) == NULL)) {
							printf(", but didn't write them because memchr!");
						}
						printf("\n");
					}
					if ((ud[i].serv_status == SERV_FLOW || ud[i].connected != CONN_YES ) && FD_ISSET(ud[i].user_fd,&wset) && 
						((memchr(ud[i].s2u_o, '\n', bytes) != NULL) || (ud[i].s2u_i == &ud[i].s2u_buf[S2U_SIZE])) 
						) {
							if (debug)
								printf("calling change_serv_buf\n");
							if (change_serv_buf(&ud[i], ud[i].s2u_o)) {
								bytesW = bytes;
							} else 
								bytesW = write(ud[i].user_fd, ud[i].s2u_o, bytes);

						if (bytesW < 0) {
#ifdef WIN32
							errno = WSAGetLastError();
#endif
							if (errno != EWOULDBLOCK) {
								perror("user_write");
								user_close(&ud[i]);
							}
						} else {
							ud[i].s2u_o+=bytesW;
							if (debug) {
								printf("wrote %lu bytes to user_fd\n", (unsigned long)bytesW);
								//printf("%s\n", (char*)(ud[i].s2u_o-bytesW));
							}
							if (ud[i].s2u_o==ud[i].s2u_i)
								ud[i].s2u_o = ud[i].s2u_i = ud[i].s2u_buf;
						}
					}  else if ( (ud[i].serv_status != SERV_FLOW) && (ud[i].connected==CONN_YES)) {
						if ( (&ud[i].serv_input[BUF_SIZE] - ud[i].serv_ptr) >= bytes) {
							/* There is room in the server buffer for this data */
							if (debug)
								printf("eating server bytes\n");
							memcpy(ud[i].serv_ptr, ud[i].s2u_o, bytes);
							ud[i].s2u_o += bytes;
							ud[i].serv_ptr += bytes;
							if (ud[i].s2u_o==ud[i].s2u_i)
								ud[i].s2u_o = ud[i].s2u_i = ud[i].s2u_buf;
						} else
							printf("could not copy server input to server buffer\n");
					} 
				}
				

				/* Nonblocking connect to a remote data port gave a result */


				if (ud[i].data_connected == CONN_IN_PROG && ud[i].connected == CONN_YES) {
#if defined WIN32 || defined __CYGWIN__
					if (FD_ISSET(ud[i].serv_data_fd,&eset) || 
#else
					if (FD_ISSET(ud[i].serv_data_fd,&rset) ||
#endif
						FD_ISSET(ud[i].serv_data_fd,&wset)) {
						if (debug)
							printf("nonblocking data connect\n"); 
#if defined WIN32 || defined __CYGWIN__
						conn_err = FD_ISSET(ud[i].serv_data_fd,&eset);
#else
						sock_errlen = sizeof(sock_err);
						conn_err = 0;
						if (getsockopt(ud[i].serv_data_fd, SOL_SOCKET, SO_ERROR, &sock_err,
							&sock_errlen) < 0)
							conn_err = 1; /* Solaris pending error */
						else if (sock_err)
							conn_err = 1; /* BSD pending error */
						if (!conn_err) {
							if (read(ud[i].serv_data_fd, fakebuf, 0) < 0)
								conn_err = 1; /* We are not connected */
						}
#endif					 
						if (debug)
							printf("checking if %d is connected\n", ud[i].serv_data_fd);

						if (conn_err) {
							if (debug)
								printf("data port connection failed\n");
							print_to_ud(&ud[i],"421 Connection failed.\r\n");
							data_close(&ud[i]);
						} else {
							ud[i].data_connected = CONN_YES;
							if (debug)
								printf("data port connected\n");
							open_local_dataport(&ud[i]);
							//printf("-----------1-------------%d--------\n",ud[i].lport);
						}

					}
				}

				/* Nonblocking connect to remote server gave a result */

				if (ud[i].connected == CONN_IN_PROG)
#if defined WIN32 || defined __CYGWIN__
					if (FD_ISSET(ud[i].serv_fd,&eset) ||
#else
					if (FD_ISSET(ud[i].serv_fd,&rset) ||
#endif
						FD_ISSET(ud[i].serv_fd,&wset)) {
#if defined WIN32 || defined __CYGWIN__
						conn_err = FD_ISSET(ud[i].serv_fd,&eset);
#else
						sock_errlen = sizeof(sock_err);
						conn_err = 0;
						if (getsockopt(ud[i].serv_fd, SOL_SOCKET, SO_ERROR, &sock_err,
							&sock_errlen) < 0)
							conn_err = 1; /* Solaris pending error */
						else if (sock_err)
							conn_err = 1; /* BSD pending error */

						if (!conn_err) {
							if (read(ud[i].serv_fd, fakebuf, 0) < 0)
								conn_err = 1; /* We are not connected */
						}
#endif
						if (conn_err) {
							print_to_ud(&ud[i],"421 Connection failed.\r\n");
							user_close(&ud[i]);
							if (debug)
								printf("failed connecting to server\n");
						} else {
							if (ud[i].issl) {
							// Implicit SSL crap
								ud[i].serv_status = SERV_TLS;
								tls_auth(&ud[i], 0, ucertspath, cfg_cafile);
							} else {
								ud[i].serv_status = SERV_CONN;
							}
							ud[i].connected = CONN_YES;
							if (debug)
								printf("connected to server\n");
						}
					}
			}
			if (remove_this == 1)
	      			ud[i].user_fd = -1;
			
			else	{
				if (ud[i].user_input != ud[i].user_ptr) {
					/* if (debug)
						printf("parse_buf\n"); */
					while (parse_buf(&ud[i], i, dns_write_pipe, token) == 0);
				}
				if (ud[i].serv_input != ud[i].serv_ptr) {
					/* if (debug)
						printf("parse_serv_buf\n"); */
					while (parse_serv_buf(&ud[i], i, ucertspath, cfg_cafile) == 0);
				}
			}
		}
	}
}

