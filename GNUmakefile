###############################################################################
# Configuration section

ifndef XLIBPATH
XLIBPATH = /usr/X11/lib
endif

ifndef XBINPATH
XBINPATH = /usr/X11/bin
endif

# Set these if you have Karma installed and want to accumulate message size
# statistics in real time
#KARMAINCLDUEPATH = /usr/local/karma/include
#KARMALIBPATH = /usr/local/karma/lib

###############################################################################
# No user servicable parts below

TARGETS := halve-duplicatedb unquote-printables \
		milter-size milter-dnsrbl milter-regexp
ifdef KARMAINCLUDEPATH
TARGETS += kemail-size-logd kemail-size-query
endif

all:	$(TARGETS)

ifdef KARMAINCLUDEPATH
include $(KARMAINCLUDEPATH)/gmakedefs/general.h1
endif   # KARMAINCLUDEPATH

ifeq ($(OSTYPE), freebsd)
LDMILTER = -lmilter -pthread
else
LDMILTER = -L/usr/lib/libmilter -lmilter -lsm -lpthread
endif
ifeq ($(OSTYPE), solaris)
LDDNS = -lresolv -lnsl
LDMILTER += -lsocket
endif


halve-duplicatedb:	halve-duplicatedb.c
	cc -s -O2 -o halve-duplicatedb halve-duplicatedb.c


unquote-printables:	unquote-printables.c
	cc -s -o unquote-printables -O2 unquote-printables.c

milter-size:		milter-size.c
	cc -s -o milter-size milter-size.c -O2 -D_REENTRANT \
	$(LDMILTER)

milter-dnsrbl:		milter-dnsrbl.c
	cc -s -o milter-dnsrbl milter-dnsrbl.c -O2 -D_REENTRANT \
	$(LDDNS) $(LDMILTER)

milter-regexp:		milter-regexp.c
	cc -s -o milter-regexp milter-regexp.c -O2 -D_REENTRANT \
	$(LDDNS) $(LDMILTER)

kemail-size-logd:	kemail-size-logd.o
	$(LD) $(KOPTIMISE) -o kemail-size-logd kemail-size-logd.o -lkarma -lm

kemail-size-query:	kemail-size-query.o
	$(LD) $(KOPTIMISE) -o kemail-size-query kemail-size-query.o -lkarma -lm


clean:
	-rm -f *~ *.o


distclean:	clean
	-rm -f $(TARGETS)
