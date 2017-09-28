#include "config.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <io.h>
#define F_OK 00
#define snprintf _snprintf
#define access _access
#else
#include <unistd.h>
#endif

#include "tlswrap.h"

#ifndef HAVE_STRLCPY
#include "misc.h"
#endif

/*
extern char *optarg;
extern int optind;
extern int optopt;
extern int opterr;
extern int optreset;
*/

/*
	Check the "default" egd-pool locations.
*/

void 	egd_check(char *cfg_egdsock, int cfg_egdsock_max)
{
	const char std_loc[3][18]= {"/var/run/egd-pool",
		"/dev/egd-pool", "/etc/egd-pool"};
	int i;

	for (i = 0; i < 3; i++) {
		if (access(std_loc[i], F_OK) == 0) {
			strlcpy(cfg_egdsock, std_loc[i], cfg_egdsock_max);
			return;
		}
	}

	cfg_egdsock[0] = '\0';
}

/*
	Configure everything.
*/

void	read_config(int argc, char * const *argv, unsigned int *users,
	char *listenport, int listenmax, int *debug, char *cfg_egdsock,
	int cfg_egdsock_max, char *tlsciphers, int tlsciphersmax,
	unsigned int *tcpbufsize, unsigned int *tcpsndlowat, char
	*listenhost, int listenhostmax, char *token, int tokenmax, int *sec_mode,
	char *certspath, int certspathmax, int *serv_install, int *serv_remove, 
	int *key_wait, char *serv_install_opt, int serv_install_max,
	char *ucertspath, int ucertspathmax, char *cafile, int cafilemax,
	char *crlfile, int crlfilemax)
{
	signed char ch; /* StrongARM fix */
	char *ep;

	/* Set defaults first */

	*users = 5;
	*certspath = '\0';
	*ucertspath = '\0';
	*cafile = '\0';
	*crlfile = '\0';
	strlcpy(listenport, "7000", listenmax);
	strlcpy(listenhost, "127.0.0.1", listenhostmax);
	strlcpy(token, "#@:%+", tokenmax);
	*debug = 0;
	*sec_mode = 0;
	*tcpbufsize = 32768;
	*tcpsndlowat = DBUF_SIZE;
	egd_check(cfg_egdsock, cfg_egdsock_max);
	*serv_remove = *serv_install = 0;
	*key_wait = 0;

	strlcpy(tlsciphers,"DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:RC4-SHA:RC4-MD5:DHE-DSS-RC4-SHA:DES-CBC3-SHA:DES-CBC3-MD5:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA",
	    tlsciphersmax);

	while ((ch = getopt(argc, argv, "a:b:B:c:C:dE:h:I:kl:p:P:r:Rs:St:")) != -1)
		switch (ch) {
		case 'a':
			strlcpy(cafile, optarg, cafilemax);
			break;
		case 'b':
			*tcpbufsize = strtol(optarg, &ep, 10);
			if (*tcpbufsize <= 0 || *ep != '\0') {
				fprintf(stderr,"illegal number -- %s", optarg);
				exit(1);
			}
		case 'B':
			*tcpsndlowat = strtol(optarg, &ep, 10);
			if (*tcpsndlowat <= 0 || *ep != '\0') {
				fprintf(stderr, "illegal number -- %s", optarg);
				exit(1);
			}
		case 'c':
			*users = strtol(optarg, &ep, 10);
			if (*users <= 0 || *ep != '\0') {
				fprintf(stderr, "illegal number -- %s", optarg);
				exit(1);
			}
			break;
		case 'C':
			strlcpy(tlsciphers, optarg, tlsciphersmax);
			break;
		case 'd':
			*debug = 1;
			break;
		case 'E':
			strlcpy(cfg_egdsock, optarg, cfg_egdsock_max);
			break;
		case 'h':
			strlcpy(listenhost, optarg, listenhostmax);
			break;
		case 'I':
			*serv_install = 1;
			strlcpy(serv_install_opt, optarg, serv_install_max);
			break;
		case 'k':
			*key_wait = 1;
			break;
		case 'l':
			strlcpy(listenport, optarg, listenmax);
			break;
		case 'p':
			strlcpy(certspath, optarg, certspathmax);
			break;
		case 'P':
			strlcpy(ucertspath, optarg, ucertspathmax);
			break;
		case 's':
			*sec_mode = strtol(optarg, &ep, 10);
			if (*sec_mode < 0 || *ep != '\0') {
				fprintf(stderr, "illegal number -- %s", optarg);
				exit(1);
			}
			break;
		case 'r':
			strlcpy(crlfile, optarg, crlfilemax);
			break;
		case 'R':
			*serv_remove = 1;
			break;
		case 'S': break; /* empty for WIN32 service */
		case 't':
			if (strlen(optarg) == (tokenmax - 1))
				strlcpy(token, optarg, tokenmax);
			else {
				fprintf(stderr, "tokens must be %d characters\n", tokenmax - 1);
				exit(1);
			}
			break;
		default:
			usage();
		}
		
	argc -= optind;
     	argv += optind;

}
void usage()
{
	(void)fprintf(stderr, "usage: %s [-c max] [-C list] [-d] [-E socket] [-h host] [-l port] [-p certs_path] [-s mode] [-t tokens]\n","tlswrap");
	exit(1);
}
