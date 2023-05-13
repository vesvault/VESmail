LIB_CFILES = lib/mail.c \
lib/optns.c \
lib/parse.c \
lib/header.c \
lib/xform.c \
lib/multi.c \
lib/cte.c \
lib/ves.c \
lib/encrypt.c \
lib/decrypt.c \
lib/banner.c \
lib/util.c

LIB_HFILES = lib/mail.h \
lib/optns.h \
lib/parse.h \
lib/header.h \
lib/xform.h \
lib/multi.h \
lib/cte.h \
lib/ves.h \
lib/encrypt.h \
lib/decrypt.h \
lib/banner.h \
lib/util.h

SRV_CFILES = srv/server.c \
srv/arch.c \
srv/tls.c \
srv/sasl.c \
srv/conf.c \
srv/daemon.c \
srv/proc.c \
srv/override.c \
srv/guard.c

SRV_HFILES = srv/server.h \
srv/arch.h \
srv/tls.h \
srv/sasl.h \
srv/conf.h \
srv/daemon.h \
srv/proc.h \
srv/override.h \
srv/guard.h

if VESMAIL_X509STORE
SRV_CFILES += srv/x509store.c
SRV_HFILES += srv/x509store.h
endif
if VESMAIL_CURLSH
SRV_CFILES += srv/curlsh.c
SRV_HFILES += srv/curlsh.h
endif

IMAP_CFILES = imap/imap.c \
imap/imap_xform.c \
imap/imap_token.c \
imap/imap_track.c \
imap/imap_start.c \
imap/imap_proxy.c \
imap/imap_msg.c \
imap/imap_fetch.c \
imap/imap_result.c \
imap/imap_result_proc.c \
imap/imap_sect.c \
imap/imap_append.c \
imap/imap_xves.c

IMAP_HFILES = imap/imap.h \
imap/imap_xform.h \
imap/imap_token.h \
imap/imap_track.h \
imap/imap_start.h \
imap/imap_proxy.h \
imap/imap_msg.h \
imap/imap_fetch.h \
imap/imap_result.h \
imap/imap_sect.h \
imap/imap_append.h \
imap/imap_xves.h

SMTP_CFILES = smtp/smtp.c \
smtp/smtp_cmd.c \
smtp/smtp_reply.c \
smtp/smtp_track.c \
smtp/smtp_start.c \
smtp/smtp_proxy.c \
smtp/smtp_xves.c

SMTP_HFILES = smtp/smtp.h \
smtp/smtp_cmd.h \
smtp/smtp_reply.h \
smtp/smtp_track.h \
smtp/smtp_start.h \
smtp/smtp_proxy.h \
smtp/smtp_xves.h

NOW_CFILES = now/now.c \
now/now_store.c \
now/now_probe.c \
now/now_post.c \
now/now_manifest.c \
now/now_options.c \
now/now_websock.c

NOW_HFILES = now/now.h \
now/now_store.h \
now/now_probe.h \
now/now_post.h \
now/now_manifest.h \
now/now_options.h \
now/now_websock.h

if VESMAIL_NOW_OAUTH
NOW_CFILES += now/now_oauth.c
NOW_HFILES += now/now_oauth.h
endif


CLI_CFILES = cli/vesmail.c \
cli/cli.c \
cli/help.c \
cli/tty.c

CLI_HFILES = cli/vesmail.h \
cli/cli.h \
cli/help.h \
cli/tty.h

UTIL_CFILES = util/jTree.c

UTIL_HFILES = util/jTree.h

VESMAIL_HFILES = VESmail.h

bin_PROGRAMS = vesmail

vesmail_LDADD = -lVES -lcrypto -lcurl -lssl
if HAVE_PTHREAD_H
vesmail_LDADD += -lpthread
endif

vesmail_CFLAGS =

if VESMAIL_X509STORE
vesmail_CFLAGS += -DVESMAIL_X509STORE
endif
if VESMAIL_CURLSH
vesmail_CFLAGS += -DVESMAIL_CURLSH
endif
if VESMAIL_NOW_OAUTH
vesmail_CFLAGS += -DVESMAIL_NOW_OAUTH
endif

vesmail_SOURCES = $(LIB_CFILES) $(SRV_CFILES) $(IMAP_CFILES) $(SMTP_CFILES) $(NOW_CFILES) $(CLI_CFILES) \
$(LIB_HFILES) $(SRV_HFILES) $(IMAP_HFILES) $(SMTP_HFILES) $(NOW_HFILES) $(CLI_HFILES) $(UTIL_CFILES) $(UTIL_HFILES) \
$(VESMAIL_HFILES)
