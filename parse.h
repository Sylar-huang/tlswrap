#ifndef __PARSE_H__
#define __PARSE_H__
#include <sys/types.h>
#include "tlswrap.h"

int parse_buf(struct user_data *, int, int, char *);
int parse_serv_buf(struct user_data *, int, char *, char *);
int change_serv_buf( struct user_data *ud, char *buf);
void intercept_user_buf(struct user_data *ud, char *buf, ssize_t *len);
int pasv_to_ipport(char *buf, char *ip, int iplen, unsigned int *port);
void ipport_to_pasv(char *buf, int len, const char *ip, unsigned int port);
void open_local_dataport(struct user_data *ud);
int port_to_ipport(char *buf, char *ip, int iplen, unsigned int *port);
#endif
