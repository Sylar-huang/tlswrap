#ifndef _MISC_H_
#define _MISC_H_
#include "tlswrap.h"

#ifndef HAVE_STRLCPY
#include <stdio.h>
size_t
strlcpy(char *dst, const char *src, size_t siz);
#endif 

extern int dns_write_pipe, dns_read_pipe, pipe1[2], pipe2[2];

#ifndef HAVE_GETOPT
#ifndef _GETOPT_DECLARED
#define _GETOPT_DECLARED
int      getopt(int, char * const [], const char *);
char *_getprogname(void);
extern char *optarg;                    /* getopt(3) external variables */
extern int optind, opterr, optopt;
#endif /* _GETOPT_DECLARED */
#endif /*!HAVE_GETOPT */
void sys_err(const char *);
size_t extr_str(const char *, size_t , char *, size_t);
int print_to_ud(struct user_data *, const char *);
/* int find_max_fd(fd_set *fd_r, fd_set *fd_w); */
int find_max_fd(int, struct user_data *, int);
void init_ud(struct user_data *, int);
int find_free_slot(struct user_data *, int);
int print_to_serv(struct user_data *, const char *);
void user_close(struct user_data *);
void data_close(struct user_data *);
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN	/* Exclude rarely-used stuff from Windows headers */
#define BOOL int
#define true 1
#define false 0

HANDLE hServiceThread;
SERVICE_STATUS_HANDLE nServiceStatusHandle; 
HANDLE killServiceEvent;
DWORD nServiceCurrentStatus;
#include <windows.h>
#include <winsvc.h>
struct parm {
	int argc;
	char **argv;
};
void service_main(DWORD argc, LPTSTR *argv); 
void service_ctrl_handler(DWORD nControlCode);
BOOL update_service_status(DWORD dwCurrentState, DWORD dwWin32ExitCode,
					 DWORD dwServiceSpecificExitCode, DWORD dwCheckPoint,
					 DWORD dwWaitHint);
BOOL start_service_thread(void);
DWORD service_execution_thread(LPDWORD param);
void install_service(char*, char*, int);
void remove_service(int);
void kill_service(void);
BOOL CtrlHandler(DWORD fdwCtrlType);
#endif
#endif
