#bin_PROGRAMS = tlswrap
#tlswrap_SOURCES = config.c misc.c network.c parse.c tls.c tlswrap.c config.h misc.h network.h parse.h tls.h tlswrap.h
#tlswrap_LDADD = @LIBOBJS@
#tlswrap_CPPFLAGS = -Wall -Wmissing-prototypes

CORESRC = config.c misc.c network.c parse.c tls.c tlswrap.c
INCSRC = config.h misc.h network.h parse.h tls.h tlswrap.h

#EXTRA_tlwrap_SOURCES=$(CORESRC) $(INCSRC)

bin_PROGRAMS=tlswrap
tlswrap_SOURCES=$(CORESRC) $(INCSRC)
#tlswrap_LDADD=@dents_LDADD@ @STATIC_MODS@ ../support/libsupport.la
#tlswrap_LDFLAGS=-export-dynamic @LDFLAGS_ORB@
#tlswrap_LDADD = @LIBOBJS@
tlswrap_CPPFLAGS = -Wall -Wmissing-prototypes

 
 