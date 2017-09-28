srcdir	= .

SHELL	= /bin/sh

prefix	= /usr/local
exec_prefix = ${prefix}
bindir	= ${exec_prefix}/bin
mandir	= ${prefix}/man
sbindir	= ${exec_prefix}/sbin
ssldir=/usr
openssl=$(ssldir)/bin/openssl

mandircat5 = ${mandir}/cat5
mandircat8 = ${mandir}/cat8

CC	= gcc
CFLAGS	= -I${srcdir}  -g -O2 -Wall -Wmissing-prototypes -I/usr/include
LIBS	= -lnsl -lresolv  -L/usr/lib -lssl -lcrypto
LDFLAGS	= 

INSTALL	= /usr/bin/install -c

PROG	= tlswrap
OBJS	= config.o misc.o network.o parse.o tls.o tlswrap.o

all:	${PROG}

install: all
	-mkdir -p ${bindir}
	${INSTALL} -m 555 ${PROG} ${bindir}

${PROG}: ${OBJS}
	${CC} ${CFLAGS} ${LDFLAGS} -o ${PROG} ${OBJS} ${LIBS}

clean:
	rm -f core ${PROG} ${OBJS}

distclean: clean
	rm -f Makefile
	rm -f config.cache
