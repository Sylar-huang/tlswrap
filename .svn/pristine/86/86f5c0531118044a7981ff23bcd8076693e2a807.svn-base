#ifndef __TLS_H__
#define __TLS_H__

void 	tls_init(char *);
void 	tls_auth(struct user_data *, int, char *, char *);
void 	tls_auth_cont(struct user_data *, int);
int 	tls_write(struct user_data *, const void *buf, int, int);
int		tls_read(struct user_data *, void *, int, int);
int		tls_cert(struct user_data *, int);
long	tls_cert2(struct user_data *, int);
#endif
