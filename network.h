#ifndef _NETWORK_H_
#define _NETWORK_H_
#include <sys/types.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netdb.h>
#endif

#include "tlswrap.h"

void setup_connect_1(struct user_data *, int, char *, char *, int);
void setup_connect_2(struct user_data *, struct dns_msg *, int);
#ifdef WIN32
SOCKET
#else
int
#endif
setup_connect(const char *, const char *, unsigned int *, int *);
#ifdef WIN32
void dns_helper(void *); // __cdecl 
#else
void dns_helper(int, int);
#endif
#ifdef WIN32
SOCKET
#else
int
#endif
setup_listen(int, const char *, char *, int, int);
int get_local_ip(int, char *, int);
int get_remote_ip(int, char *, int);
#endif
