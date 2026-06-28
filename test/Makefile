# Standalone build for the composer CLI test.
# Compiles a minimal subset of lib/ + composer test driver. Links against
# the system libVES + libcrypto. Run from this directory:
#
#   make
#   ./composertest < samples/text.eml
#   ./composertest 1 < samples/multipart.eml > /tmp/out.eml     # byte-at-a-time
#
# clean: rm composertest

CC      ?= cc
CFLAGS  ?= -O0 -g -Wall -Wno-deprecated-declarations
INCLUDES = -I.. -I/usr/include
LDLIBS   = -lVES -lcrypto -lssl

LIBSRC = \
    ../lib/composer.c \
    ../lib/mail.c \
    ../lib/parse.c \
    ../lib/header.c \
    ../lib/xform.c \
    ../lib/multi.c \
    ../lib/cte.c \
    ../lib/util.c \
    ../lib/banner.c \
    ../lib/optns.c \
    ../lib/encrypt.c \
    ../lib/decrypt.c \
    ../lib/ves.c

composertest: composertest.c $(LIBSRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ composertest.c $(LIBSRC) $(LDLIBS)

clean:
	rm -f composertest

.PHONY: clean
