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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN	 /* Exclude rarely-used stuff from Windows headers */
#include <Winsock2.h>
#define snprintf _snprintf
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
typedef   __int32 ssize_t;
int write(SOCKET s, void *buf, int len);
int read(SOCKET s, void *buf, int len);
#else
#include <unistd.h>
#endif

#include "parse.h"
#include "misc.h"
#include "network.h"
#include "tls.h"

extern int debug;

struct ftp_cmd {
	char 	*cmd;
	int 	dir;
	};

void intercept_user_buf(struct user_data *ud, char *buf, ssize_t *len)
{
	int	i;

	struct ftp_cmd cmd[] = {
	 { "LIST", DATA_DOWN },
	 { "RETR", DATA_DOWN },
	 { "NLST", DATA_DOWN },
	 { "STOR", DATA_UP   },
	 { "APPE", DATA_UP   },
	 { "PORT", DATA_PORT },
	 { "EPRT", DATA_PORT },
	 { (char*)NULL, 0 }
	 };

	if (debug)
		printf("intercept_user_buf\n");

	if (*len < 4)
		return;

	for (i = 0; cmd[i].cmd; i++) 
	if (memcmp(buf, cmd[i].cmd, 4) == 0) {
		if (cmd[i].dir != DATA_PORT) {
			printf("new add : client cmd is %s\n", buf);
			ud->data_direction = cmd[i].dir;
			if (debug)
				printf("set direction for %s\n", cmd[i].cmd);
		} else if (!ud->active) {
			unsigned int port;
			char ip[17], *ptr;
			int r;
			struct dns_msg dns;
			if (debug)
				printf("data port\n");
			if ((r = port_to_ipport(buf, ip, sizeof(ip), &port))
				== 0) {
				ud->active = 1;
				if (debug)
					printf("PORT - ip: %s port: %u\n",ip, port);
				strlcpy(ud->serv_data_host, ip,
					sizeof(ud->serv_data_host));
				snprintf(ud->serv_data_port, sizeof(ud->serv_data_port),
				    "%u", port);
				strlcpy(dns.hostname, ip, sizeof(dns.hostname));
				strlcpy(dns.port, ud->serv_data_port, sizeof(dns.port));
				ptr = (char*)memchr(buf, '\n', *len);
			
				if (ptr != NULL)
					*len = 0;
				setup_connect_2(ud, &dns, 1);
				if (ud->data_connected == CONN_YES)
					open_local_dataport(ud);
			} else if (r == -1) { // unsupported EPRT network number
				*len = 0;
				print_to_ud(ud,"522 Network protocol not supported, use (1)\r\n");
			}
		}
	}
}

int change_serv_buf(struct user_data *ud, char *buf)
{
	unsigned int port;
	char ip[17];
	int r;
	struct dns_msg dns;
	char *ptr, *ptr2;

	if (ud->prot == 'C')
		return 0;

	if (memcmp(buf,"227 ",4) == 0) { /* PASV reply detected */
		ud->epsv = 0;
		if ((r = pasv_to_ipport(buf, ip, sizeof(ip), &port))
		    == 0) {
			if (debug)
				printf("ip: %s port: %u\n",ip, port);
			strlcpy(ud->serv_data_host, ip,
			    sizeof(ud->serv_data_host));
			snprintf(ud->serv_data_port, sizeof(ud->serv_data_port),
			    "%u", port);
			strlcpy(dns.hostname, ip, sizeof(dns.hostname));
			strlcpy(dns.port, ud->serv_data_port, sizeof(dns.port));
			setup_connect_2(ud, &dns, 1);
			if (ud->data_connected == CONN_YES) {
				open_local_dataport(ud);
			}
			return 1;
		}
		else printf("change_serv_buf failed %d (%s)\n", r, buf);
	} else if (memcmp(buf,"229 ",4) == 0) { /* EPSV reply detected */
		if (debug)
			printf("EPSV (%s)\n", buf);
		ud->epsv = 1;
		ptr = strstr(buf, "(|||");
		if (ptr == NULL)
			return 0;
		ptr += 4;
		if (strlen(ptr) < 3) return 0;
		ptr2 = strstr(ptr, "|)");
		if (ptr == NULL)
			return 0;
		*ptr2 = '\0';
		strlcpy(ud->serv_data_port, ptr, sizeof(ud->serv_data_port)); 
		strlcpy(ud->serv_data_host, ud->serv_host,
		    sizeof(ud->serv_data_host));
		/*
		strlcpy(dns.hostname, ud->serv_host, sizeof(dns.hostname));
		*/
		dns = ud->serv_dns;
		strlcpy(dns.port, ud->serv_data_port, sizeof(dns.port));
		setup_connect_2(ud, &dns, 1);
		if (ud->data_connected == CONN_YES)
			open_local_dataport(ud);
		return 1;
		
	}
	return 0;
}

void open_local_dataport(struct user_data *ud)
{
	char 	port[6];
	char 	pasv[25];
	char	tmp[80], *ep;
	char 	myip[NI_MAXHOST];
	
	port[0] = '\0';


	if (ud->active)
		get_local_ip(ud->serv_fd, myip, sizeof(myip));
	else
		get_local_ip(ud->user_fd, myip, sizeof(myip));
	if (debug)
		printf("my local ip is %s\n", myip);
	//printf("---------------------local port %d---------------", port);

	ud->user_data_fd = setup_listen(5, myip, port, sizeof(port),1);

	if (debug)
		printf("open_local_dataport: fd = %d, ----port------ = %s\n",ud->user_data_fd, port);

	strlcpy(myip, "10.204.51.27", sizeof(myip));
	ipport_to_pasv(pasv, sizeof(pasv), myip, strtol(port, &ep, 10));
//	if (ud->active) {
//		snprintf(tmp, sizeof(tmp), "PORT %s\r\n", pasv);
//		print_to_serv(ud, tmp);
//	} else {

//		if (ud->epsv)
//			snprintf(tmp, sizeof(tmp), "229 Entering Extended Passive Mode (|||%u|)\r\n",(unsigned int)strtol(port, &ep, 10));
//		else
			snprintf(tmp, sizeof(tmp), "227 Entering Passive Mode (%s)\r\n",pasv);
		write(ud->user_fd, tmp, strlen(tmp));
//	}
	if (debug)
		printf("sent %s",tmp);
	ud->data_connected = CONN_DATA_LISTEN;
}

int pasv_to_ipport(char *buf, char *ip, int iplen, unsigned int *port)
{
	char 	*ep, *ptr, *ptr2;
	int	i;
	int 	num;

	if ( (ptr = strchr(buf, '(')) == NULL)
		return 1;

	ptr2 = ++ptr;
	for (i = 0; i<4; i++) {
		if ((ptr = strchr(++ptr, ',') ) == NULL)
			return 2;
		*ptr = '.';
	}
	*ptr++ = '\0';
	strlcpy(ip, ptr2, iplen);
	ptr2 = ptr;
	if ((ptr = strchr(ptr, ',')) == NULL)
		return 3;
	*ptr++ = '\0';
	num = strtol(ptr2, &ep, 10);
	if (num < 0 || *ep != '\0')
		return 4;
	*port = num * 256;
	ptr2 = ptr;
	if ((ptr = strchr(ptr, ')')) == NULL)
		return 5;
	*ptr = '\0';
	num = strtol(ptr2, &ep, 10);
	if (num < 0 || *ep != '\0') {
		printf("pasv_to_ipport FAILED with %s that got changed into %d (at %s)\n", ptr2, num, ep);
		return 6;
	}
	*port += num;

	return 0;
}

void
ipport_to_pasv(char *buf, int len, const char *ip, unsigned int port)
{
	char 	*ptr;
	char	tmp[16];

	strlcpy(tmp, ip, sizeof(tmp));
	while ( (ptr = strchr(tmp, '.')) )
		*ptr = ',';
	snprintf(buf, len, "%s,%d,%d", tmp, port / 256, port % 256); 
}

int port_to_ipport(char *buf, char *ip, int iplen, unsigned int *port)
{
	char 	*ep, *ptr, *ptr2, sep;
	int	i;
	int 	num;

	if (memcmp(buf, "PORT", 4) == 0) {

		if ( (ptr = strchr(buf, ' ')) == NULL)
			return 1;

		ptr2 = ++ptr;
		for (i = 0; i<4; i++) {
			if ((ptr = strchr(++ptr, ',') ) == NULL)
				return 2;
			*ptr = '.';
		}
		*ptr++ = '\0';
		strlcpy(ip, ptr2, iplen);
		ptr2 = ptr;
		if ((ptr = strchr(ptr, ',')) == NULL)
			return 3;
		*ptr++ = '\0';
		num = strtol(ptr2, &ep, 10);
		if (num < 0 || *ep != '\0')
			return 4;
		*port = num * 256;
		ptr2 = ptr;
		if ((ptr = strchr(ptr, '\r')) == NULL)
			return 5;
		*ptr = '\0';
		num = strtol(ptr2, &ep, 10);
		if (num < 0 || *ep != '\0') {
			printf("port_to_ipport FAILED with %s that got changed into %d (at %s)\n", ptr2, num, ep);
			return 6;
		}
		*port += num;
	} else { // EPRT
		if ((ptr = strchr(buf, ' ')) == NULL)
			return 1;
		sep = *(++ptr);
		if ((ptr2 = strchr(++ptr, sep)) == NULL)
			return 1;
		*ptr2 = '\0';
		num = strtol(ptr, &ep, 10);
		if (num != 1)
			return -1; // unsupported network
		ptr2++; // ptr2 now points to beginning of the ip address
		if ((ptr = strchr(ptr2, sep)) == NULL)
			return 1;
		*ptr = '\0';
		strlcpy(ip, ptr2, iplen);
		ptr++; // ptr now points to beginning of the port number
		if ((ptr2 = strchr(ptr, sep)) == NULL)
			return 1;
		*ptr2 = '\0';		
		num = strtol(ptr, &ep, 10);
		if (num < 0 || *ep != '\0') {
			printf("port_to_ipport FAILED with %s that got changed into %d (at %s)\n", ptr2, num, ep);
			return 6;
		}
		*port = num;

	}
	return 0;
}

int
parse_serv_buf(struct user_data *ud, int index, char *ucertspath, char *cafile)
{
	int size;
	char dst[BUF_SIZE], s[100];

	if ( (size = extr_str(ud->serv_input, BUF_SIZE, dst, sizeof(dst))) == 0)
		return 1; /* Nothing could be extracted */


	if ((ud->serv_status == SERV_CONN) && (strncasecmp(dst,"220 ",4) == 0) ) {
		print_to_serv(ud, "AUTH TLS\r\n");
		ud->serv_status = SERV_AUTH;
	} else if ((ud->serv_status == SERV_AUTH) && (strncasecmp(dst,"234 ",4) == 0) ) {
		ud->serv_status = SERV_TLS;
		tls_auth(ud, 0, ucertspath, cafile);
	} else if ((ud->serv_status == SERV_TLS_OK) && (strncasecmp(dst,"200 ",4) == 0) ) {
		ud->serv_status = SERV_PBSZ;
		snprintf(s, sizeof(s), "PROT %c\r\n", ud->prot);
		if (debug)
			printf(s);
		print_to_serv(ud,s);
	} else if ((ud->serv_status == SERV_PBSZ) && (strncasecmp(dst,"200 ",4) == 0) ) {
		ud->serv_status = SERV_PROT;
		snprintf(s, sizeof(s), "USER %s\r\n",ud->user);
		print_to_serv(ud, s);
		ud->delay_prot = 0;
	} else if ((ud->serv_status == SERV_PBSZ) && (strncasecmp(dst,"530 ",4) == 0) ) {
		ud->serv_status = SERV_PROT;
		snprintf(s, sizeof(s), "USER %s\r\n",ud->user);
		print_to_serv(ud, s);
		ud->delay_prot = 1;
	} else if ((ud->serv_status == SERV_PROT) && (strncasecmp(dst,"331 ",4) == 0) ) {
		snprintf(s, sizeof(s), "PASS %s\r\n",ud->pass);
		print_to_serv(ud, s);
		if (!ud->delay_prot)
			ud->serv_status = SERV_FLOW;
	} else if (ud->delay_prot && (ud->serv_status == SERV_PROT) && (strncasecmp(dst,"230 ",4) == 0) ) {
		snprintf(s, sizeof(s), "PROT %c\r\n", ud->prot);
		if (debug)
			printf(s);
		print_to_serv(ud,s);
	} else if (ud->delay_prot && (ud->serv_status == SERV_PROT) && (strncasecmp(dst,"200 ",4) == 0) ) {
		write(ud->user_fd, "230 Bypassed login text because the ftpd can't handle PROT before USER.\r\n", 73);
		ud->serv_status = SERV_FLOW;
	}
	memmove(ud->serv_input, &ud->serv_input[size], BUF_SIZE - size - 1);
	ud->serv_ptr -= size;
	return 0;
}


int
parse_buf(struct user_data *ud, int index, int dns_write_pipe, char *token)
{
	int size, updated;
	char dst[BUF_SIZE], *ptr, s[100], tmp[200];

	if ( (size = extr_str(ud->user_input, BUF_SIZE, dst, sizeof(dst))) == 0)
		return 1; /* Nothing could be extracted */

	/* Parse starts here and is ugly */

	if ((ud->connected == CONN_NO) && (strncasecmp(dst,"USER ",5) == 0)) {
		strlcpy(tmp, dst + 5, sizeof(tmp));
		ptr = memchr(tmp, token[1], strlen(tmp));
		if (ptr != NULL) {
			*ptr++ = 0;
		    if ( (strlen(tmp) > 0) && (strlen(ptr) > 0) ) {
				updated = 0;
				if (tmp[0] == token[0]) {
					ud->prot = 'C'; /* Encrypt control only */
					strlcpy(ud->user, tmp + 1, sizeof(ud->user));
					memmove(tmp, tmp + 1, strlen(tmp));
					updated = 1;
				}
				if (tmp[0] == token[3]) { // Implicit SSL crap
					if (!updated)
						ud->prot = 'P'; /* Encrypt everything */
					strlcpy(ud->user, tmp + 1, sizeof(ud->user));
					memmove(tmp, tmp + 1, strlen(tmp));
					ud->issl = 1;
					updated = 1;
				}
				if (tmp[0] == token[4]) { // + Set security level
					if (!updated)
						ud->prot = 'P'; /* Encrypt everything */
					if ((tmp[1] - '0' >= 0) && (tmp[1] - '0' <= 4))
						ud->sec_level = tmp[1] - '0';
					strlcpy(ud->user, tmp + 2, sizeof(ud->user));
					updated = 1;
				}
				if (!updated) {
					ud->prot = 'P'; /* Encrypt everything */
					strlcpy(ud->user, tmp, sizeof(ud->user));
				}
				strlcpy(ud->serv_host, ptr, sizeof(ud->serv_host));
				ptr = memchr(ud->serv_host, token[2], strlen(ud->serv_host));
				if (ptr != NULL) {
					*ptr++ = 0;
					if (strlen(ptr) > 0)
						strlcpy(ud->serv_port, ptr, sizeof(ud->serv_port));
					else
						ptr = NULL;
				}

				if (ptr == NULL)
					strlcpy(ud->serv_port, "21", sizeof(ud->serv_port));
				ud->connected = CONN_USER;
				if (debug)
					printf("Username: %s, Host: %s, Port: %s\n",ud->user,
					    ud->serv_host, ud->serv_port);
				snprintf(s, sizeof(s), "331 Password required for %s.\r\n", ud->user);
				print_to_ud(ud, s);
			}
		} else {
			if (debug)
				printf("don't find any @\n");
			user_close(ud);
		}
	} else
	
	/* Attempt connection directly after receiving PASS */

	if ((ud->connected == CONN_USER) && (strncasecmp(dst,"PASS ",5) == 0)) {
		strlcpy(ud->pass, dst + 5, sizeof(ud->pass));
		ud->connected = CONN_PASS;
		setup_connect_1(ud, index, ud->serv_host, ud->serv_port, dns_write_pipe);
	} else

	/* Reject AUTH stuff */

	if ((ud->connected == CONN_NO) && (strncasecmp(dst,"AUTH ",5) == 0)) {
		snprintf(s, sizeof(s), "502 RFC 2228 authentication not implemented.\r\n");
		print_to_ud(ud, s);
	}

	memmove(ud->user_input, &ud->user_input[size], BUF_SIZE - size - 1);
	ud->user_ptr -= size;
	return 0;
}

