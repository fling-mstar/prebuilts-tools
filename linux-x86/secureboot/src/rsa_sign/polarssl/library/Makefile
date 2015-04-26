
# Also see "include/polarssl/config.h"
POLARSSL_DISTDIR = ..

CFLAGS	= -I../include -D_FILE_OFFSET_BITS=64 \
	  -I$(POLARSSL_DISTDIR)/include/polarssl

OFLAGS	= -O -lm

#POLARSSL_DISTDIR = ..

#INC_DIR = \
        -I$(POLARSSL_DISTDIR)/include/polarssl \

LD_LIB_PATH  = \
	-L$(POLARSSL_DISTDIR)/library \
#	-L$(POLARSSL_DISTDIR)/library -lsimplepolarssl 

#SIMPLE_LDLIB = $(LD_LIB_PATH)

#LDLIB	+= -lpolarssl
#SIMPLE_LDLIB	+= -lsimplepolarssl

LDLIB = $(LD_LIB_PATH)

LDLIB   += -lpolarssl

#CFLAGS  = -I$(POLARSSL_DISTDIR)/include/polarssl \

# MicroBlaze specific options:
# CFLAGS += -mno-xl-soft-mul -mxl-barrel-shift

# To compile on Plan9:
# CFLAGS += -D_BSD_EXTENSION

# To compile as a shared library:
# CFLAGS += -fPIC

DLEXT=so
# OSX shared library extension:
# DLEXT=dylib

OBJS=	aes.o		arc4.o		base64.o	\
	bignum.o	certs.o		debug.o		\
	des.o		dhm.o		havege.o	\
	md2.o		md4.o		md5.o		\
	net.o		padlock.o	rsa.o		\
	sha1.o		sha2.o		sha4.o		\
	ssl_cli.o	ssl_srv.o	ssl_tls.o	\
	timing.o	x509parse.o	xtea.o		\
	camellia.o      polarssl_api.o  prng.o		\
	base32.o        CommonUtility.o	\

#SIMPLE_OBJS= aes.o timing.o prng.o \
      padlock.o

.SILENT:

all: static pwd_out GenDataBase

static: libpolarssl.a

GenDataBase:
	echo "compile GenDataBase"
	$(CC) $(CFLAGS) -lm -o GenDataBase.exe GenDataBase.c $(LDLIB)
	echo "compile GenDataBase end"

pwd_out:
	echo "compile pwd out"
	$(CC) $(CFLAGS) -lm -o PWD_OUT.exe pwd_out_for_production.c $(LDLIB)
	echo "compile pwd out end"

shared: libpolarssl.$(DLEXT)

#libsimplepolarssl.a: $(SIMPLE_OBJS)
#	echo "  AR    $@"
#	ar r $@ $(SIMPLE_OBJS)
#	echo "  RL    $@"
#	ranlib $@

libpolarssl.a: $(OBJS)
	echo "  AR    $@"
	ar r $@ $(OBJS)
	echo "  RL    $@"
	ranlib $@

libpolarssl.so: libpolarssl.a
	echo "  LD    $@"
	$(CC) -shared -Wl,-soname,$@ -o $@ $(OBJS)

libpolarssl.dylib: libpolarssl.a
	echo "  LD    $@"
	$(CC) -dynamiclib -o $@ $(OBJS)

.c.o:
	echo "  CC    $<"
	$(CC) $(CFLAGS) $(OFLAGS) -c $<

clean:
	rm -f *.o libsimplepolarssl.* PWD_OUT.exe
	rm -f *.o libpolarssl.* GenDataBase.exe


