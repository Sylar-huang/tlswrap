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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef WIN32
#include <Winsock2.h>
#define snprintf _snprintf
#define strcasecmp _stricmp
#else
#include <unistd.h>
#include <syslog.h>
#include <arpa/ftp.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pwd.h>
#endif
#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <fcntl.h>

#include "tlswrap.h"
#include "tls.h"
#include "misc.h"

extern int debug;
/* extern int sec_mode; 

int global_user_cert;
X509_STORE *ca_store; */

void tls_init(char *egd_sock) {

	if (!SSL_library_init())
		sys_err("OpenSSL initialization failed");

	SSL_load_error_strings(); /* load readable error messages */
/*
	if (!(tls_ctx = SSL_CTX_new(SSLv23_method()))) {
		printf("SSL_CTX_new() %s\r\n",(char *)ERR_error_string(ERR_get_error(), NULL));
		exit(1);
	}*/
	if (debug)
		printf("egd_sock is %s\n", egd_sock);
#ifdef HAVE_RAND_STATUS
	if (RAND_status() != 1) {
		if ( RAND_egd(egd_sock) == -1 ) {
			fprintf(stderr, "egd_sock is %s\n", egd_sock);
			sys_err("RAND_egd failed\n");
		}
		if (RAND_status() != 1)
			sys_err("ssl_init: System without /dev/urandom, PRNG seeding must be done manually.\r\n");
	}
#endif
	/*
	SSL_CTX_set_options(tls_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
	SSL_CTX_set_default_verify_paths(tls_ctx);
	*/
//	global_user_cert = 0;

	/*
	if (sec_mode > 0) {
		if (SSL_CTX_use_certificate_chain_file(tls_ctx, "usercert.pem") == 1) {
			if (SSL_CTX_use_PrivateKey_file(tls_ctx, "usercert.pem", SSL_FILETYPE_PEM) != 1)
				sys_err("Unable to load private key from file.");
			else
				global_user_cert = 1;
			if (debug)
				printf("Global user certificate chain loaded.\n");
		} else {
			if (debug)
				printf("No global user certificate loaded.\n");
  	}
	*/
  
	/*
	if (cafile[0] != '\0') { // CA verifications. 
  		if (SSL_CTX_load_verify_locations(tls_ctx, cafile, NULL) != 1)
  			sys_err("could not load certificates from CA file.");
  		else if (debug)
  			printf("Loaded CA file.\n");
		ca_store = SSL_CTX_get_cert_store(tls_ctx);
	} else
		ca_store = NULL;

	SSL_CTX_set_cert_store(tls_ctx, NULL);
	SSL_CTX_free(tls_ctx);
*/
	if (debug)
		printf("TLS initialization successful.\n");
	
}

void
tls_auth(struct user_data *ud, int data, char *ucertspath, char *cafile)
{
	SSL *ssl;
	char fn[NI_MAXHOST];

#ifdef WIN32
	char sep = '\\';
#else
	char sep = '/';
#endif

	if (!data) {
		if ((ud->ssl_ctx = SSL_CTX_new(SSLv23_method())) == NULL) {
			printf("SSL_CTX_new() %s\n",(char *)ERR_error_string(ERR_get_error(), NULL));
			exit(1);
		}
		if (cafile[0] != '\0') { // CA verifications. 
  			if (SSL_CTX_load_verify_locations(ud->ssl_ctx, cafile, NULL) != 1)
  				sys_err("could not load certificates from CA file.");
  			else if (debug)
  				printf("Loaded CA file.\n");
		}
		SSL_CTX_set_options(ud->ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
		SSL_CTX_set_default_verify_paths(ud->ssl_ctx);
		
		if (ucertspath[0] != '\0') { /* Try to load user certificate chain */
			if (ucertspath[strlen(ucertspath)] == sep)
				snprintf(fn, sizeof(fn), "%s%s.pem",ucertspath, ud->serv_dns.hostname);
			else
				snprintf(fn, sizeof(fn), "%s%c%s.pem",ucertspath, sep, ud->serv_dns.hostname);
			if (SSL_CTX_use_certificate_chain_file(ud->ssl_ctx, fn) != 1) {
				if (debug)
					printf("failed to load %s\n", fn);
			} else {
				if (debug)
					printf("loaded %s\n", fn);
			}
		}
	}

	ssl = SSL_new(ud->ssl_ctx);

	if (ssl == NULL) {
			printf("SSL_new() %s\r\n",(char *)ERR_error_string(ERR_get_error(), NULL));
			exit(1);
	}
	
	if (data)
		ud->ssl_data = ssl;
	else
		ud->ssl_ctrl = ssl;
	if (debug)
		printf("tls_auth: ciphers: %s\n", cfg_tlsciphers);

	SSL_set_cipher_list(ssl, cfg_tlsciphers);
	
	/* if (sec_mode >= 3)
		SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL); */
	
	if (data) {
		if (SSL_set_fd(ssl, ud->serv_data_fd) != 1)
			printf("SSL_set_fd_error\n");
		if (ud->ssl_sess) { /* There is a cached SSL session */
			SSL_set_session(ssl, ud->ssl_sess);
			SSL_SESSION_free(ud->ssl_sess);
			ud->ssl_sess = NULL;
		}
	} else {
		if (SSL_set_fd(ssl, ud->serv_fd) != 1)
			printf("SSL_set_fd_error\n");
	}

	SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	tls_auth_cont(ud, data);
}

int tls_cert(struct user_data *ud, int data) /* save new key or verify saved key */
{
	X509 	*x509_peer, *x509_stored;
	FILE 	*fp;
	char 	filename[1024];
	int 	cert_ok;
	
	cert_ok = 0;
	x509_stored = NULL;

	if (debug)
		printf("tls_cert\n");

	if ((x509_peer = SSL_get_peer_certificate((data) ? ud->ssl_data : ud->ssl_ctrl)) == NULL)
		return 0; /* SSL_get_peer* can only be NULL on  'anonymous DH connections' so shouldn't happen. */ 
	
	snprintf(filename, sizeof(filename), "%s-%s.pem", (data && !ud->epsv) ? ud->serv_data_host : ud->serv_dns.hostname,
		(data) ? "data" : "ctrl");
	if ( (fp = fopen(filename, "r")) == NULL) { /* key doesn't exist, store it */
		if (debug)
			printf("key %s doesn't exist, store it\n", filename);
		if (ud->sec_level == 2) { /* don't add new certs */
			X509_free(x509_peer);
			return 0;
		}
		if ( (fp = fopen(filename, "w")) == NULL) {
			X509_free(x509_peer);
			sys_err(filename);
		 } else {
			PEM_write_X509(fp, x509_peer);
			cert_ok = 1;
		}
	} else { /* KEY already exists, verify it */
		if (debug)
			printf("key %s exists, verifying it\n", filename);
		if((x509_stored = PEM_read_X509(fp, NULL, 0, NULL)) == NULL)
	  		sys_err("can't read certificate");
		if (X509_cmp(x509_peer, x509_stored) == 0)
	  		cert_ok = 1;
		else {
			if (debug)
				printf("X509_cmp failed\n");
		}

		if (debug && cert_ok)
	  		printf("verified cert ok\n");
	}

	fclose(fp);
	
	X509_free(x509_peer);
	if (x509_stored != NULL)
		X509_free(x509_stored);
	return cert_ok;
}

long tls_cert2(struct user_data *ud, int data) /* save new key or verify saved key */
{
	X509 				*x509_peer;
	X509_NAME			*x509_subj;
	X509_EXTENSION 		*x509_ext;
	X509V3_EXT_METHOD	*x509_meth;
	int					ok, extcount, i, j;
	char 				*extstr;
	SSL					*ssl;
#if (OPENSSL_VERSION_NUMBER > 0x00908000L)
	unsigned char const		*data1;
#else
	unsigned char	*data1;
#endif
	char				data2[256];
	STACK_OF(CONF_VALUE) *val;
	CONF_VALUE			*nval;
	void				*ext_str = NULL;
	int					subjectaltname;

	ok = subjectaltname = 0;
	ssl = (data) ? ud->ssl_data : ud->ssl_ctrl;

	if (debug)
		printf("tls_cert2\n");
	
	if ((x509_peer = SSL_get_peer_certificate(ssl)) == NULL)
		return X509_V_ERR_APPLICATION_VERIFICATION; /* SSL_get_peer* can only be NULL on  'anonymous DH connections' so shouldn't happen. */

	if (ud->sec_level == 3) {
		X509_free(x509_peer);
		return SSL_get_verify_result(ssl);
	}
	
	if ((extcount = X509_get_ext_count(x509_peer)) > 0) {
		if (debug) printf("extcount = %d\n", extcount);
		for (i = 0; i < extcount; i++) {
			x509_ext = X509_get_ext(x509_peer, i);
			extstr = (char*)OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(x509_ext)));
			if (debug) printf("extstr = %s\n", extstr);
			if (!strcmp(extstr, "subjectAltName")) {
				subjectaltname = 1;
				if	(!(x509_meth = X509V3_EXT_get(x509_ext)))
					break;
				data1 = x509_ext->value->data;
#if (OPENSSL_VERSION_NUMBER > 0x00907000L)     
				if (x509_meth->it)
					ext_str = ASN1_item_d2i(NULL, &data1, x509_ext->value->length, ASN1_ITEM_ptr(x509_meth->it));
				else
					ext_str = x509_meth->d2i(NULL, &data1, x509_ext->value->length);
#else
				ext_str = x509_meth->d2i(NULL, &data1, x509_ext->value->length);
#endif
				val = x509_meth->i2v(x509_meth, ext_str, NULL);
				for (j = 0; j < sk_CONF_VALUE_num(val); j++) {
						nval = sk_CONF_VALUE_value(val, j);
						if (debug)
							printf("X509 extension : %s - %s\n", nval->name, nval->value);
						if (!strcmp(nval->name, "DNS") && !strcasecmp(nval->value, ud->serv_host)) {
							ok = 1;
							break;
						} else if (!strcmp(nval->name, "IP Address") &&
							( (data == 0 && !strcmp(nval->value, ud->serv_dns.hostname)) ||
							  (data == 1 && !strcmp(nval->value, ud->serv_data_host)) ) ) {
							ok = 1;
							break;
						}
				}
			}
			if (ok) break;
		}
  }

  if (!ok && (x509_subj = X509_get_subject_name(x509_peer)) && X509_NAME_get_text_by_NID(x509_subj, NID_commonName, data2, sizeof(data2)) > 0) {
  	data2[255] = 0;
  	if ((strcasecmp(data2, ud->serv_host) != 0) || subjectaltname) {
  		X509_free(x509_peer);
  		return X509_V_ERR_APPLICATION_VERIFICATION;
  	}
  }
  X509_free(x509_peer);
	return SSL_get_verify_result(ssl);
}

void
tls_auth_cont(struct user_data *ud, int data)
{
	int status, sslerr, cert_ok;
	SSL_CIPHER *cipher;
	char cipher_info[128];
	SSL *ssl;

	if (debug)
		printf("tls_auth_cont\n");
	ssl = (data) ? ud->ssl_data : ud->ssl_ctrl;
	
	if (ssl == NULL) printf("SSL == NULL!\n");

	status = SSL_connect(ssl);
	sslerr = SSL_get_error(ssl, status);
	if (data)
		ud->ssl_data_fd_mode = TLS_NONE;
	else
		ud->ssl_ctrl_fd_mode = TLS_NONE;
	
  /*	if ((data) && (status == 1)) {
		status = -1; sslerr = 1; } */

	if (status == 1) { /* The TLS/SSL handshake was successfully completed */
		cipher = SSL_get_current_cipher(ssl);
		SSL_CIPHER_description(cipher, cipher_info, sizeof(cipher_info));
		if (debug)
			printf("cipher %s, sec_level %d\n", cipher_info, ud->sec_level);
		cert_ok = (ud->sec_level == 1 || ud->sec_level == 2) ? tls_cert(ud, data) : (ud->sec_level >= 3) ? tls_cert2(ud, data) == X509_V_OK : 1;
		if (debug)
			printf("cert_ok = %d, data = %d\n", cert_ok, data);

		if (data) {
			ud->tls_status |= TLS_DATA;
			ud->data_connected = CONN_DATA_OK;
		} else {
			ud->serv_status = SERV_TLS_OK;
			ud->tls_status |= TLS_CTRL;
			print_to_serv(ud, "PBSZ 0\r\n");
			if (debug)
				printf("printed pbsz\n");
		}
		if (!cert_ok) {
			if (!data) {
				ud->serv_status = SERV_FLOW;
				print_to_ud(ud, "530 TLSWrap certificate verification failed, disconnecting.\r\n");
				print_to_serv(ud, "QUIT\r\n");
			} else {
				print_to_ud(ud, "425 TLSWrap data certificate verification failed.\r\n");
				SSL_clear(ud->ssl_data); /* Prevent reuse */
				data_close(ud);	
			}
			if (debug)
				printf("printed that certificate verification failed.\n");
			//user_close(ud);
		}
	} else {
		switch (sslerr) {
			case SSL_ERROR_WANT_READ:
				if (debug)
					printf("setting TLS_READ\n");
				if (data)
					ud->ssl_data_fd_mode = TLS_READ;
				else
					ud->ssl_ctrl_fd_mode = TLS_READ;
				break;
			case SSL_ERROR_WANT_WRITE:
				if (debug)
					printf("setting TLS_WRITE\n");
				if (data)
					ud->ssl_data_fd_mode = TLS_WRITE;
				else
					ud->ssl_ctrl_fd_mode = TLS_WRITE;
				break;
			case SSL_ERROR_SSL:
			case SSL_ERROR_SYSCALL: // assorted I/O error
				if (debug)
					printf("tls_auth_cont got SSL_ERROR_SSL or SSL_ERROR_SYSCALL\n");
				if (!data) {
					ud->serv_status = SERV_NONE;
					print_to_ud(ud, "530 TLSWrap SSL/TLS connection to server failed.\r\n");
					ud->connected = CONN_NO;
				} else {
					/* ud->serv_data_close = CLOSE_READ;
					  ud->user_data_close = CLOSE_READ; */
					print_to_ud(ud, "230 TLSWrap SSL/TLS DATA connection to server failed.\r\n");
					SSL_clear(ssl);
					data_close(ud);
				}
				break;
			default:
				if (debug)
					printf("tls_auth_cont failed (%d)\n", sslerr);
				if (sslerr)
					perror("tls_auth_cont");
				if (data) {
					SSL_clear(ud->ssl_data);
					data_close(ud);
				}
		}
	}
}

int
tls_write(struct user_data *ud, const void *buf, int num, int data)
{
	SSL 	*ssl;
	int	status, sslerr;

	ssl = (data) ? ud->ssl_data : ud->ssl_ctrl;

	status = SSL_write(ssl, buf, num);
	sslerr = SSL_get_error(ssl, status);

	if (status == -1) {
		if (data)
			ud->ssl_data_func = TLS_WRITE;
		else
			ud->ssl_ctrl_func = TLS_WRITE;
		switch (sslerr) {
			case SSL_ERROR_WANT_READ:
				if (data)
					ud->ssl_data_fd_mode = TLS_READ;
				else
					ud->ssl_ctrl_fd_mode = TLS_READ;
				break;
			case SSL_ERROR_WANT_WRITE:
		 		if (data)
					ud->ssl_data_fd_mode = TLS_WRITE;
				else
					ud->ssl_ctrl_fd_mode = TLS_WRITE;
				break;
			default:
				if (debug)
					printf("tls_write_error\n");
				return -1;
		}
	} else {
		if (data)
			ud->ssl_data_fd_mode = TLS_NONE;
		else
			ud->ssl_ctrl_fd_mode = TLS_NONE;
	}

	return status;
}

int
tls_read(struct user_data *ud, void *buf, int num, int data)
{
	SSL     *ssl;
	int     status, sslerr;

	ssl = (data) ? ud->ssl_data : ud->ssl_ctrl;

	status = SSL_read(ssl, buf, num);
	sslerr = SSL_get_error(ssl, status);

	if (status == -1) {
		if (data)
			ud->ssl_data_func = TLS_READ;
		else
			ud->ssl_ctrl_func = TLS_READ;
		switch (sslerr) {
			case SSL_ERROR_WANT_READ:
				if (data)
					ud->ssl_data_fd_mode = TLS_READ;
				else
					ud->ssl_ctrl_fd_mode = TLS_READ;
				break;
			case SSL_ERROR_WANT_WRITE:
				if (data)
					ud->ssl_data_fd_mode = TLS_WRITE;
				else
					ud->ssl_ctrl_fd_mode = TLS_WRITE;
				break;
			default:
				if (debug)
					printf("tls_read_error\n");
				return -2;
		}
	} else {
		if (data)
			ud->ssl_data_fd_mode = TLS_NONE;
		else
			ud->ssl_ctrl_fd_mode = TLS_NONE;
	}
	
	return status;
}
