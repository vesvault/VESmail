#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.


AC_PREREQ([2.69])
AC_INIT([VESmail], [1.66], [bugs@vesvault.com])
AC_CONFIG_SRCDIR([cli/vesmail.c])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([1.0 subdir-objects])

AM_MAINTAINER_MODE([disable])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB

# Checks for libraries.

AC_ARG_WITH([x509store],
    [AS_HELP_STRING([--without-x509store],
	[Disable openssl X509_STORE, expect the trusted root certs to be loaded for each SSL_CTX separately]
    )],
    [],
    [VESMAIL_X509STORE=1]
)
AC_ARG_WITH([curlsh],
    [AS_HELP_STRING([--without-curlsh],
	[Disable shared cURL context]
    )],
    [],
    [VESMAIL_CURLSH=1]
)
AC_ARG_WITH([now_oauth],
    [AS_HELP_STRING([--without-now-oauth],
	[Disable OAuth Server]
    )],
    [],
    [VESMAIL_NOW_OAUTH=1]
)

# Checks for header files.
AC_CHECK_HEADERS([string.h stddef.h fcntl.h unistd.h sys/ioctl.h openssl/evp.h curl/curl.h termios.h windows.h libVES.h jVar.h poll.h])
AC_CHECK_HEADERS([pthread.h], [AM_CONDITIONAL([HAVE_PTHREAD_H], [test 1])])

AM_CONDITIONAL([VESMAIL_CURLSH], [test "$VESMAIL_CURLSH" != ""])
AM_CONDITIONAL([VESMAIL_X509STORE], [test "$VESMAIL_X509STORE" != ""])
AM_CONDITIONAL([VESMAIL_NOW_OAUTH], [test "$VESMAIL_NOW_OAUTH" != ""])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_OFF_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([strdup strndup memmove memset strerror nanosleep])

AC_PREFIX_DEFAULT(/usr)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

