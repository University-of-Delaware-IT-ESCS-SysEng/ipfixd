# $Id: Makefile,v 1.12 2005/05/25 16:31:07 mike Exp $

BINDIR=/usr/local/bin
TGTS=readflows
HASHDIR=../hash
VPATH=${HASHDIR}

CC=gcc -O2

# 64 bit
#CFLAGS=-g -fast -xmemalign=8s -xarch=v9

# 32 bit

#CFLAGS=-g -mt -xmemalign=8s -xarch=v8plusa -I${HASHDIR}
#CFLAGS=-g -fast -mt -I${HASHDIR}
CFLAGS=-I${HASHDIR} -D_POSIX_SOURCE

all: ${TGTS}

readflows: readflows.o hash.o
	gcc -o $@ readflows.o hash.o -lnsl -lpthread

readflows.o: readflows.c
hash.o: hash.c

install:
	rm -f ${BINDIR}/readflows
	cp readflows ${BINDIR}
	chmod 755 ${BINDIR}/readflows

install-root:
	cp readflows-init.d /etc/init.d/readflows
#	cp flowscan-init.d /etc/init.d/flowscan
	chmod 755 /etc/init.d/readflows
#	chmod 755 /etc/init.d/flowscan

clean:
	rm -f *.o ${TGTS}
