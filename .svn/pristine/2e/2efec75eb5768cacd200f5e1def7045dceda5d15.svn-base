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

#include <errno.h>
#include <memory.h>
#include <stdio.h>
#include <string.h>
#ifdef WIN32
extern const char *srv_name;
extern const char *srv_name2;
extern char *srv_desc;
#include <conio.h>
#include <process.h>
#define snprintf _snprintf
#define close closesocket
#else
#include <unistd.h>
#endif

#include "tlswrap.h"
#include "misc.h"

extern int debug;
#ifdef WIN32
extern struct parm serv_param;
#endif

void sys_err(const char *err){
	perror(err);
  	exit(1);
}

void user_close(struct user_data *ud)
{
	if (ud->connected == CONN_YES || ud->connected == CONN_IN_PROG)
		close(ud->serv_fd);
	close(ud->user_fd);

	if (ud->ssl_ctrl)
		SSL_free(ud->ssl_ctrl);

	if (debug)
		printf("user_close\n");
	if (ud->data_connected != CONN_NO)
		data_close(ud);
	if (ud->ssl_sess)
		SSL_SESSION_free(ud->ssl_sess);
	if (ud->ssl_ctx)
		SSL_CTX_free(ud->ssl_ctx);
	/* memset(ud, 0, sizeof(struct user_data)); */
	ud->user_fd = -1;
	ud->serv_fd = -1;
	ud->connected = CONN_NO;
	ud->ssl_data_fd_mode = TLS_NONE;

	ud->s2u_i = ud->s2u_o = ud->s2u_buf;
	ud->u2s_i = ud->u2s_o = ud->u2s_buf;

}

void data_close(struct user_data *ud)
{
	if (ud->ssl_data) {
		if (1) {
		//if (SSL_get_shutdown(ud->ssl_data) & SSL_RECEIVED_SHUTDOWN) {
			/* SSL connection was shutdown cleanly */
			ud->ssl_sess = SSL_get1_session(ud->ssl_data);
			SSL_shutdown(ud->ssl_data);
		} else 
			SSL_clear(ud->ssl_data);
		SSL_free(ud->ssl_data);
		ud->ssl_data = NULL;
	}

	if (ud->data_connected == CONN_DATA_OK ||
	    ud->data_connected == CONN_DATA_LISTEN) 
		close(ud->user_data_fd);
	if (ud->data_connected == CONN_IN_PROG ||
	    ud->data_connected == CONN_DATA_TLS ||
	    ud->data_connected == CONN_DATA_OK) 
		close(ud->serv_data_fd);

	ud->user_data_fd = -1;
	ud->serv_data_fd = -1;

	ud->data_connected = CONN_NO;
	ud->ssl_data_fd_mode = TLS_NONE;
	ud->dc2s_i = ud->dc2s_o = ud->dc2s_buf;
	ud->ds2c_i = ud->ds2c_o = ud->ds2c_buf;

	ud->serv_data_close = CLOSE_NONE;
	ud->user_data_close = CLOSE_NONE;
	ud->user_read_cnt = 0;
	ud->serv_read_cnt = 0;
	ud->tls_status &= ~TLS_DATA;
	ud->retry_data = 0;
	ud->active = 0;
	if (debug)
		printf("data_close\n");

}

size_t
extr_str(const char *src, size_t src_len, char *dst, size_t dst_len) {

	/* Extract a \r\n (or just \n) terminated string from a binary
     	buffer. The copied string will always be null-terminated and
     	without \r\n. The function will return a pointer to the next
     	byte after the extracted string or NULL if no string could be
     	found */

  	char *ptr;
  	int ext_size,size;

  	if ((ptr = memchr(src,'\n',src_len)) == NULL)
		return 0;

  	ext_size = size = ptr - src;

  	if (src[ext_size-1] == '\r')
    		ext_size--;

  	if ( (ext_size + 1) <= dst_len) {
    		memcpy(dst, src, ext_size);
    		dst[ext_size] = 0;
  	} else {
    		printf("ext_str: dst buffer too small for extracted string\n");
    		return 0;
  	}

  	return size + 1;
}
int print_to_ud(struct user_data *ud, const char *s) {

	/* all pointers must be setup correctly prior to calling this
     	function, or it will segfault */

  	size_t slen;
  	char str[1024];
  
  	snprintf(str, sizeof(str), s);

  	slen = strlen(str); /* NOT including null char */
  
  	if ( (&ud->s2u_buf[S2U_SIZE] - ud->s2u_i) < slen) {
    		printf("print_to_ud: can't fit string to buffer\n");
    		return 1;
  	} else {
    		memcpy(ud->s2u_i,str,slen);
    		ud->s2u_i+=slen;
  	}

 	return 0;
}

int print_to_serv(struct user_data *ud, const char *s) {

	size_t slen;
	char str[130];

	snprintf(str, sizeof(str), s);
	slen = strlen(str); /* NOT including null char */
	if ( (&ud->u2s_buf[U2S_SIZE]-ud->u2s_i)<slen) {
		printf("print_to_ud: can't fit string to buffer\n");
		return 1; 
	} else {
		memcpy(ud->u2s_i,str,slen);
		ud->u2s_i+=slen;
	}
	
	return 0;
}
#if 1 
int find_max_fd(int listen, struct user_data *ud, int max_users) {
	int i, max_fd = listen;
 
  	for(i = 0; i < max_users; i++) {
    		if (ud[i].user_fd != -1) {
      			if (ud[i].user_fd > max_fd)
				max_fd = ud[i].user_fd;
      			if ((ud[i].serv_fd > max_fd) &&
			    ((ud[i].connected == CONN_YES)||
	  	   	    (ud[i].connected == CONN_IN_PROG )))
				max_fd = ud[i].serv_fd;
      			if ( (ud[i].serv_data_fd > max_fd) &&
			    ((ud[i].data_connected == CONN_YES) ||
	  	    	    (ud[i].data_connected == CONN_IN_PROG )))
				max_fd = ud[i].serv_data_fd; 
      			if (ud[i].data_connected == CONN_DATA_LISTEN)
				if (ud[i].user_data_fd > max_fd)
					max_fd = ud[i].user_data_fd;
      			if (ud[i].ssl_data_fd_mode != TLS_NONE)
	 			if (ud[i].serv_data_fd > max_fd)
					max_fd = ud[i].serv_data_fd;
      			if (ud[i].data_connected == CONN_DATA_OK) {
				if (ud[i].user_data_fd > max_fd)
					max_fd = ud[i].user_data_fd;
				if (ud[i].serv_data_fd > max_fd)
					max_fd = ud[i].serv_data_fd;
			}
      		}
    	}
  
  	return max_fd;
}
#else

int find_max_fd(fd_set *fd_r, fd_set *fd_w)
{
	int i, max_fd;

	max_fd = 0;

	for (i = FD_SETSIZE - 1; i >= 0 ; i--) {
		if ( FD_ISSET(i,fd_r) || FD_ISSET(i,fd_w) )
			return i;
	}

	return 0;
}
#endif
void init_ud(struct user_data *ud, int max_users) {

	/* Initializes the user_data structures */

	int i;
  	memset(&ud[0], 0, max_users * sizeof(struct user_data));
  	for (i = 0; i < max_users; i++)
    		ud[i].user_fd = -1;
}

int find_free_slot(struct user_data *ud, int max_users) {

	/* Returns the index of the first free ud slot, otherwise
     	   it returns -1 */

  	int i;
  
  	for (i = 0; i < max_users; i++)
    		if (ud++->user_fd == -1) return i;
  
  	return -1;
}


#ifndef HAVE_STRLCPY

/*	$Id: strlcpy.c,v 1.1 2000/07/29 13:33:34 lukem Exp $	*/
/*	$NetBSD: strlcpy.c,v 1.5 1999/09/20 04:39:47 lukem Exp $	*/
/*	from OpenBSD: strlcpy.c,v 1.4 1999/05/01 18:56:41 millert Exp 	*/

/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
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

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return(s - src - 1);	/* count does not include NUL */
}
#endif

/*
 * Copyright (c) 1987, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef HAVE_GETOPT

int	opterr = 1,		/* if error message should be printed */
	optind = 1,		/* index into parent argv vector */
	optopt,			/* character checked for validity */
	optreset;		/* reset getopt */
char	*optarg;		/* argument associated with option */

#define	BADCH	(int)'?'
#define	BADARG	(int)':'
#define	EMSG	""

char *_getprogname(void) {
	return "tlswrap";
}

/*
 * getopt --
 *	Parse argc/argv argument vector.
 */
int
getopt(int nargc, char * const nargv[], const char *ostr) {

	static char *place = EMSG;		/* option letter processing */
	char *oli;				/* option letter list index */

	if (optreset || *place == 0) {		/* update scanning pointer */
		optreset = 0;
		place = nargv[optind];
		if (optind >= nargc || *place++ != '-') {
			/* Argument is absent or is not an option */
			place = EMSG;
			return (-1);
		}
		optopt = *place++;
		if (optopt == '-' && *place == 0) {
			/* "--" => end of options */
			++optind;
			place = EMSG;
			return (-1);
		}
		if (optopt == 0) {
			/* Solitary '-', treat as a '-' option
			   if the program (eg su) is looking for it. */
			place = EMSG;
			if (strchr(ostr, '-') == NULL)
				return (-1);
			optopt = '-';
		}
	} else
		optopt = *place++;

	/* See if option letter is one the caller wanted... */
	if (optopt == ':' || (oli = strchr(ostr, optopt)) == NULL) {
		if (*place == 0)
			++optind;
		if (opterr && *ostr != ':')
			(void)fprintf(stderr,
			    "%s: illegal option -- %c\n", _getprogname(),
			    optopt);
		return (BADCH);
	}

	/* Does this option need an argument? */
	if (oli[1] != ':') {
		/* don't need argument */
		optarg = NULL;
		if (*place == 0)
			++optind;
	} else {
		/* Option-argument is either the rest of this argument or the
		   entire next argument. */
		if (*place)
			optarg = place;
		else if (nargc > ++optind)
			optarg = nargv[optind];
		else {
			/* option-argument absent */
			place = EMSG;
			if (*ostr == ':')
				return (BADARG);
			if (opterr)
				(void)fprintf(stderr,
				    "%s: option requires an argument -- %c\n",
				    _getprogname(), optopt);
			return (BADCH);
		}
		place = EMSG;
		++optind;
	}
	return (optopt);			/* return option letter */
} 
#endif /* !HAVE_GETOPT */

#ifdef WIN32
#ifndef WIN98
void service_main(DWORD argc, LPTSTR *argv)
{

	BOOL success;

	nServiceStatusHandle = RegisterServiceCtrlHandler(srv_name,
		(LPHANDLER_FUNCTION)service_ctrl_handler);
	if (!nServiceStatusHandle)
		return;
	success = update_service_status(SERVICE_START_PENDING,NO_ERROR,0,1,3000);
	if (!success)
		return;
	killServiceEvent = CreateEvent(0,TRUE,FALSE,0);
	if (killServiceEvent == NULL)
		return;
	success = update_service_status(SERVICE_START_PENDING,NO_ERROR,0,2,1000);
	if(!success)
		return;
	success = start_service_thread();
	if (!success)
		return;
	nServiceCurrentStatus = SERVICE_RUNNING;
	success = update_service_status(SERVICE_RUNNING,NO_ERROR,0,0,0);
	if (!success)
		return;
	WaitForSingleObject(killServiceEvent,INFINITE);
	CloseHandle(killServiceEvent);
	_endthread();
}

BOOL update_service_status(DWORD dwCurrentState, DWORD dwWin32ExitCode,
					 DWORD dwServiceSpecificExitCode, DWORD dwCheckPoint,
					 DWORD dwWaitHint)
{
	BOOL success;
	SERVICE_STATUS nServiceStatus;
	nServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	nServiceStatus.dwCurrentState = dwCurrentState;
	if(dwCurrentState == SERVICE_START_PENDING)
		nServiceStatus.dwControlsAccepted = 0;
	else
		nServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP			
			|SERVICE_ACCEPT_SHUTDOWN;
	if (dwServiceSpecificExitCode == 0)
		nServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
	else
		nServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
	nServiceStatus.dwServiceSpecificExitCode = dwServiceSpecificExitCode;
	nServiceStatus.dwCheckPoint = dwCheckPoint;
	nServiceStatus.dwWaitHint = dwWaitHint;

	success = SetServiceStatus(nServiceStatusHandle,&nServiceStatus);

	if (!success) {
		kill_service();
		return success;
	}
	else
		return success;
}

BOOL start_service_thread()
{
	DWORD id;
	hServiceThread = CreateThread(0,0,
		(LPTHREAD_START_ROUTINE)service_execution_thread,
		NULL,0,&id);
	if (hServiceThread == 0)
		return false;
	else
		return true;
}

void kill_service()
{
//	closesocket(pipe1[0]);
	closesocket(pipe1[1]);
//	closesocket(pipe2[0]);
//	closesocket(pipe2[1]);
	SetEvent(killServiceEvent);
	update_service_status(SERVICE_STOPPED,NO_ERROR,0,0,0);
}

void service_ctrl_handler(DWORD nControlCode)
{

	switch (nControlCode) {
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		nServiceCurrentStatus = SERVICE_STOP_PENDING;
		update_service_status(SERVICE_STOP_PENDING,NO_ERROR,0,1,3000);
		kill_service();		
		return;
	default:
		break;
	}
	update_service_status(nServiceCurrentStatus,NO_ERROR,0,0,0);
}

void install_service(char *serv, char *serv_opt, int key_wait)
{
	SC_HANDLE tlswrap_srv, scm;
	SERVICE_DESCRIPTION info[] =
	{
		{srv_desc},
		{NULL},
	};

	scm = OpenSCManager(0,0,SC_MANAGER_CREATE_SERVICE);
	
	if(!scm) {
		printf("Could not access the service control manager.\n");
		if (key_wait) {
			printf("Press any key.");
			_getch();
		}
		exit(0);
	}

	strcat(serv, "\\tlswrap.exe -S ");
	strcat(serv, serv_opt);

	tlswrap_srv = CreateService(scm, 
		srv_name, srv_name2,
		SERVICE_ALL_ACCESS,SERVICE_WIN32_OWN_PROCESS,SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL,
		serv,
		0,0,0,0,0);
		
	if (!tlswrap_srv) {
		CloseServiceHandle(scm);
		printf("CreateService failed.\n");
		if (key_wait) {
			printf("Press any key.");
			_getch();
		}
		exit(1);
	}
	
	if (!ChangeServiceConfig2(tlswrap_srv, SERVICE_CONFIG_DESCRIPTION,
		&info))
		printf("Could not set service description\n");

	printf("TLSWrap service installed.\n");
	if (StartService(tlswrap_srv, 0, NULL))
		printf("Started TLSWrap service.\n");
	else
		printf("Could not start TLSWrap service.\n");
	CloseServiceHandle(tlswrap_srv);
	CloseServiceHandle(scm);
	if (key_wait) {
		printf("Press any key.");
		_getch();
	}
	exit(0);

}

void remove_service(int key_wait)
{
	SC_HANDLE		tlswrap_srv, scm;
	SERVICE_STATUS	tlswrap_status;
	HANDLE			hpipe;

	hpipe = CreateFile( 
         "\\\\.\\pipe\\tlswrap_tray",   // pipe name 
         GENERIC_WRITE, 
         0,              // no sharing 
         NULL,           // no security attributes
         OPEN_EXISTING,  // opens existing pipe 
         0,              // default attributes 
         NULL);          // no template file 
 

	if (hpipe != INVALID_HANDLE_VALUE) {  
		CloseHandle(hpipe);
		printf("Killed the TLSWrap Tray Monitor.\n");
	} else
		printf("Could not find the TLSWrap Tray Monitor running.\n");

	scm = OpenSCManager(0,0,SC_MANAGER_CREATE_SERVICE);
	
	if(!scm) {
		printf("Could not access the service control manager.\n");
		if (key_wait) {
			printf("Press any key.");
			_getch();
		}
		exit(0);
	}
	if (!(tlswrap_srv = OpenService(scm, srv_name, SERVICE_ALL_ACCESS))) {
		printf("No TLSWrap service to remove.\n");
		if (key_wait) {
			printf("Press any key.\n");
			getch();
		}
		exit(0);
	}

	if (ControlService(tlswrap_srv, SERVICE_CONTROL_STOP, &tlswrap_status)) {
		printf("Stopping TLSWrap Service");
		Sleep(1000);
		while (QueryServiceStatus(tlswrap_srv, &tlswrap_status)) {
			if (tlswrap_status.dwCurrentState == SERVICE_STOP_PENDING) {
				printf(".");
				Sleep(1000);
			} else
				break;
		}

		if (tlswrap_status.dwCurrentState == SERVICE_STOPPED)
                    printf("\nTLSWrap service stopped.\n");
                else
                    printf("\nFailed to stop TLSWrap service.\n");
	}
	
	if (DeleteService(tlswrap_srv))
			printf("Removed TLSWrap service.\n");
	else
			printf("Could not remove TLSWrap service.\n");
	CloseServiceHandle(tlswrap_srv);
	CloseServiceHandle(scm);
	if (key_wait) {
		printf("Press any key.\n");
		getch();
	}
	exit(0);
}

#endif /* !not WIN98 */

/* Control handler */

BOOL CtrlHandler(DWORD fdwCtrlType) {

	switch(fdwCtrlType)  { 
		// Handle all signals
		default:
			closesocket(pipe1[1]);
//			closesocket(pipe1[0]);
//			closesocket(pipe2[0]);
//			closesocket(pipe2[1]);
			return TRUE;
	}
}

#endif /* !WIN32 */
