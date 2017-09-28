#ifndef __TLSWRAP_H__
#define __TLSWRAP_H__

#include "conf.h"

//#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define U2S_SIZE 4096 /* Buffered data going from user to server */
#define S2U_SIZE 4096 /* Buffered data going from server to user */
#define BUF_SIZE 4096 /* Input from user to program */


#if !defined __CYGWIN__ && !defined WIN32
#define DBUF_SIZE 8192 /* Data buffer */
#else
#define DBUF_SIZE 4096 //16384
#endif

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

enum {	CONN_NO,
	CONN_NICK,
	CONN_USER,
	CONN_PASS,
	CONN_CMD,
	CONN_DNS,
	CONN_IN_PROG,
	CONN_YES, 

	/* data only */
	CONN_DATA_LISTEN,
	CONN_DATA_TLS,
	CONN_DATA_OK
};

enum {	AUTH_NO,
	AUTH_YES };

enum {  DATA_UP,
		DATA_DOWN,
		DATA_PORT};

enum {	TLS_NONE,
	TLS_READ,
	TLS_WRITE };

enum {	CLOSE_NONE,
	CLOSE_READ,
	CLOSE_WRITE };

enum {	SERV_NONE,
	SERV_CONN,	/* Connected to server */
	SERV_AUTH, 	/* Sent AUTH TLS to server */
	SERV_TLS, 	/* TLS negotiation in progress */
	SERV_TLS_OK,
	SERV_PBSZ,
	SERV_PROT,
	SERV_FLOW };

#define TLS_DATA 1
#define TLS_CTRL 2

struct dns_msg{                 /* Stucture to communicate with the DNS child */
  int ud;                       /* Index of iud structure doing this request */
  char port[6];                 /* Just convenient */
  char hostname[NI_MAXHOST];    /* Use for both request and reply */
};

struct user_data {
  int user_fd;
  int user_data_fd;
  int serv_fd;
  int serv_data_fd;
  char serv_host[NI_MAXHOST];
  char serv_port[6];
  char serv_data_host[NI_MAXHOST];	/* Remote host from PASV */
  char serv_data_port[6];
  struct dns_msg serv_dns;
  char local_data_host[NI_MAXHOST];	/* PASV */
  char local_data_port[6];
  char u2s_buf[U2S_SIZE];  /* from user to server        */
  char s2u_buf[S2U_SIZE];  /* from server to user        */
  char *u2s_i;        /* user to server, input ptr  */
  char *u2s_o;        /* user to server, output ptr */
  char *s2u_i;        /* server to user, input ptr  */
  char *s2u_o;        /* server to user, output ptr */
  char *user_ptr, user_input[BUF_SIZE]; /* Not really a string */
  char *serv_ptr, serv_input[BUF_SIZE];
  char dc2s_buf[DBUF_SIZE]; /* Data - Client to Server */
  char ds2c_buf[DBUF_SIZE]; /* Data - Server to Client */
  char *dc2s_i;
  char *dc2s_o;
  char *ds2c_i;
  char *ds2c_o;
  unsigned int user_read_cnt;
  unsigned int serv_read_cnt;
  char prot; /* PROT C or PROT P */
  int connected;
  int data_connected;
  int serv_data_close;
  int user_data_close;
  int data_direction;
  int authenticated;
  int serv_status;
  int tls_status;
  SSL *ssl_ctrl;
  SSL *ssl_data;
  int ssl_ctrl_fd_mode;		/* the RESYNC mode */
  int ssl_data_fd_mode;
  int ssl_ctrl_func;		/* Called from what function */
  int ssl_data_func;
  char user[160];              /* complete USER command */
  char pass[160];
  unsigned int lport; /* Local port */
  unsigned int rport; /* Remote port */
  int active;
  int epsv;
  int issl; /* implicit ssl */
  int retry; /* We filled the buffer, so there is probably more to read */
  int retry_data;
  SSL_SESSION *ssl_sess;
  SSL_CTX *ssl_ctx;
  int sec_level;
  int delay_prot;
};

extern char *cfg_tlsrsafile;
extern char *cfg_tlsciphers;

//int print_to_user(struct user_data *, const char *);
#endif /* !__TLSWRAP_H__ */
