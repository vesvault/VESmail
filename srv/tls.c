/***************************************************************************
 *  _____
 * |\    | >                   VESmail
 * | \   | >  ___       ___    Email Encryption made Convenient and Reliable
 * |  \  | > /   \     /   \                               https://vesmail.email
 * |  /  | > \__ /     \ __/
 * | /   | >    \\     //        - RFC5322 MIME Stream Encryption & Decryption
 * |/____| >     \\   //         - IMAP4rev1 Transparent Proxy Server
 *       ___      \\_//          - ESMTP Transparent Proxy Server
 *      /   \     /   \          - VES Encryption Key Exchange & Recovery
 *      \__ /     \ __/
 *         \\     //    _____                     ______________by______________
 *          \\   //  > |\    |
 *           \\_//   > | \   |                    VESvault
 *           /   \   > |  \  |                    Encrypt Everything
 *           \___/   > |  /  |                    without fear of losing the Key
 *                   > | /   |                              https://vesvault.com
 *                   > |/____|                                  https://ves.host
 *
 * (c) 2020-2026 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * Apache License, Version 2.0
 * You may use, copy, modify, merge, publish, distribute and/or sell copies
 * of the Software under the terms of the Apache License, Version 2.0, a copy
 * of which is provided in the COPYING file, or http://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
 *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_CURL_CURL_H
#include <curl/curl.h>
#endif

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include "../VESmail.h"
#include <jVar.h>
#include <libVES.h>
#include "server.h"
#include "../lib/xform.h"
#include "arch.h"

#ifdef VESMAIL_CURLSH
#include "curlsh.h"
#endif

#ifdef VESMAIL_X509STORE
#include "x509store.h"
#endif

#include "tls.h"

#if	(OPENSSL_VERSION_NUMBER < 0x10100000L)
#pragma message ("! Using an external thread locking function for OpenSSL < 1.1")
#define	VESMAIL_OPENSSL_LOCKFN	1
void **VESmail_tls_extLocks;
void VESmail_tls_extLockFn(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK) {
	VESmail_arch_mutex_lock(VESmail_tls_extLocks + n);
    } else {
	VESmail_arch_mutex_unlock(VESmail_tls_extLocks + n);
    }
}
#endif

#ifndef VESMAIL_X509STORE
char *VESmail_tls_caBundle = NULL;

void VESmail_tls_applyCA(void *ctx) {
    if (VESmail_tls_caBundle) SSL_CTX_load_verify_locations(ctx, VESmail_tls_caBundle, NULL);
    else SSL_CTX_set_default_verify_paths(ctx);
}
#endif

int VESmail_tls_init() {
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    if (SSL_library_init() < 0) return VESMAIL_E_TLS;
#ifdef VESMAIL_OPENSSL_LOCKFN
    int n = CRYPTO_num_locks();
    VESmail_tls_extLocks = malloc(n * sizeof(*VESmail_tls_extLocks));
    while (n > 0) VESmail_tls_extLocks[--n] = NULL;
    CRYPTO_set_locking_callback(&VESmail_tls_extLockFn);
#endif
#ifdef HAVE_CURL_CURL_H
    curl_global_init(CURL_GLOBAL_ALL);
#endif
#ifdef VESMAIL_CURLSH
    VESmail_curlsh_init();
#endif
    return 0;
}

#define VESMAIL_VERB(verb, str)	str,
const char *VESmail_tls_levels[] = { VESMAIL_TLS_LEVELS() NULL };
#undef VESMAIL_VERB

VESmail_tls_client *VESmail_tls_client_new(jVar *conf, char *host) {
    VESmail_tls_client *tls = malloc(sizeof(VESmail_tls_client));
    int lvl = jVar_getEnum(jVar_get(conf, "level"), VESmail_tls_levels);
    tls->level = lvl >= 0 ? lvl : VESMAIL_TLS_HIGH;
    tls->persist = jVar_getBool(jVar_get(conf, "persist"));
    tls->peer = host;
    return tls;
}

int VESmail_tls_client_cert_ok(VESmail_server *srv, X509 *crt) {
#if	(OPENSSL_VERSION_NUMBER >= 0x10002000L)
    return srv->tls.client->level <= VESMAIL_TLS_UNSECURE
	|| X509_check_host(crt, srv->tls.client->peer, 0, 0, NULL) > 0;
#else
#pragma message ("!")
#pragma message ("! ********************************************************")
#pragma message ("! Peer host validation is not supported in OpenSSL < 1.0.2")
#pragma message ("! ********************************************************")
#pragma message ("!")
	return 1;
#endif
}

int VESmail_tls_client_start(VESmail_server *srv, int starttls) {
    if (!starttls && !srv->tls.client->persist) return 0;
#if	(OPENSSL_VERSION_NUMBER >= 0x10100000L)
    const SSL_METHOD *method = TLS_client_method();
#else
    const SSL_METHOD *method = SSLv23_client_method();
#endif
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) return VESMAIL_E_TLS;
    VESmail_tls_applyCA(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify_depth(ctx, 8);
    if (srv->tls.client->level > VESMAIL_TLS_MEDIUM) {
	SSL_CTX_set_options(ctx, VESMAIL_TLS_HIGHOPTNS | VESMAIL_TLS_CLNOPTNS);
    } else if (VESMAIL_TLS_CLNOPTNS) {
	SSL_CTX_set_options(ctx, VESMAIL_TLS_CLNOPTNS);
    }
#ifdef VESMAIL_TLS_CLNMODE
    SSL_CTX_set_mode(ctx, VESMAIL_TLS_CLNMODE);
#endif
    VESmail_arch_set_nb(BIO_get_fd(srv->rsp_bio, NULL), 0);
    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, srv->tls.client->peer);
    SSL_set_bio(ssl, srv->rsp_bio, srv->req_out->bio);
    int r = SSL_connect(ssl);
    SSL_CTX_free(ctx);
    BIO *bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl((srv->rsp_bio = bio), ssl, BIO_NOCLOSE);
    bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl((srv->req_out->bio = bio), ssl, BIO_CLOSE);
    if (r != 1) return VESMAIL_E_TLS;
    int crt_ok;
    X509 *crt = SSL_get_peer_certificate(ssl);
    VESMAIL_SRV_DEBUG(srv, 1, sprintf(debug, "[tls peer] %s", srv->tls.client->peer))
    if (crt) {
	VESMAIL_SRV_DEBUG(srv, 1, {
	    X509_NAME *sn = X509_get_subject_name(crt);
	    sprintf(debug, "[crt subject] ");
	    int l = strlen(debug);
	    X509_NAME_oneline(sn, debug + l, sizeof(debug) - l);
	})
	VESMAIL_SRV_DEBUG(srv, 1, {
	    X509_NAME *sn = X509_get_issuer_name(crt);
	    sprintf(debug, "[crt issuer] ");
	    int l = strlen(debug);
	    X509_NAME_oneline(sn, debug + l, sizeof(debug) - l);
	})
	long vrfy = SSL_get_verify_result(ssl);
	VESMAIL_SRV_DEBUG(srv, 1, sprintf(debug, "[crt verify] %ld %s", vrfy, X509_verify_cert_error_string(vrfy)))
	crt_ok = (vrfy == X509_V_OK && VESmail_tls_client_cert_ok(srv, crt));
	X509_free(crt);
    } else {
	VESMAIL_SRV_DEBUG(srv, 1, sprintf(debug, "[crt] NULL"))
	crt_ok = 0;
    }
    if (!crt_ok && srv->tls.client->level > VESMAIL_TLS_UNSECURE) {
	return VESMAIL_E_TLS;
    }
    srv->flags |= VESMAIL_SRVF_TLSC;
    return 0;
}

void VESmail_tls_client_done(VESmail_server *srv) {
    VESmail_tls_client *tls = srv->tls.client;
    if (tls) {
	SSL *ssl = NULL;
	BIO_get_ssl(srv->rsp_bio, &ssl);
	if (ssl) SSL_shutdown(ssl);
	free(tls->peer);
	free(tls);
	srv->tls.client = NULL;
    }
}

VESmail_tls_server *VESmail_tls_server_new() {
    VESmail_tls_server *tls = malloc(sizeof(VESmail_tls_server));
    tls->ctx = NULL;
    tls->cert = NULL;
    tls->key = NULL;
    tls->level = VESMAIL_TLS_HIGH;
    tls->persist = 0;
    tls->snifn = NULL;
    return tls;
}

VESmail_tls_server *VESmail_tls_server_clone(VESmail_tls_server *tls) {
    VESmail_tls_server *srv = malloc(sizeof(VESmail_tls_server));
    memcpy(srv, tls, sizeof(*tls));
    srv->ctx = NULL;
    return srv;
}

SSL_CTX *VESmail_tls_server_ctx(VESmail_server *srv, int force) {
    if (!force && srv->tls.server->ctx) return srv->tls.server->ctx;
#if	(OPENSSL_VERSION_NUMBER >= 0x10100000L)
    const SSL_METHOD *method = TLS_server_method();
#else
    const SSL_METHOD *method = TLSv1_2_server_method();
#endif
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) return NULL;
    if ((srv->tls.server->cert && SSL_CTX_use_certificate_chain_file(ctx, srv->tls.server->cert) <= 0)
	|| (srv->tls.server->key && (
	    SSL_CTX_use_PrivateKey_file(ctx, srv->tls.server->key, SSL_FILETYPE_PEM) <= 0
	    || SSL_CTX_check_private_key(ctx) <= 0))
	) {
	SSL_CTX_free(ctx);
	return NULL;
    }
    if (srv->tls.server->level > VESMAIL_TLS_MEDIUM) {
	SSL_CTX_set_options(ctx, VESMAIL_TLS_HIGHOPTNS | VESMAIL_TLS_SRVOPTNS);
    } else if (VESMAIL_TLS_SRVOPTNS) {
	SSL_CTX_set_options(ctx, VESMAIL_TLS_SRVOPTNS);
    }
#ifdef VESMAIL_TLS_SRVMODE
    SSL_CTX_set_mode(ctx, VESMAIL_TLS_SRVMODE);
#endif
    if (!force) srv->tls.server->ctx = ctx;
    return ctx;
}

#ifndef VESMAIL_LOCAL

int VESmail_tls_server_snifn(SSL *ssl, int *al, void *arg) {
    VESmail_server *srv = arg;
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!sni) return SSL_TLSEXT_ERR_NOACK;
    int r = srv->tls.server->snifn(srv, sni);
    if (r < 0) return SSL_TLSEXT_ERR_ALERT_FATAL;
    SSL_CTX *ctx = VESmail_tls_server_ctx(srv, 0);
    if (!ctx) return SSL_TLSEXT_ERR_ALERT_FATAL;
    SSL_CTX *ctx2 = SSL_set_SSL_CTX(ssl, ctx);
    if (ctx2 != ctx) return SSL_TLSEXT_ERR_NOACK;
    return SSL_TLSEXT_ERR_OK;
}

#endif

int VESmail_tls_server_start(VESmail_server *srv, int starttls) {
    if (!srv->tls.server) return starttls ? VESMAIL_E_PARAM : 0;
    if (!starttls && !srv->tls.server->persist) return 0;
    if (srv->tls.server->level == VESMAIL_TLS_NONE) return VESMAIL_E_PARAM;
    SSL_CTX *ctx = VESmail_tls_server_ctx(srv, !!srv->tls.server->snifn);
    if (!ctx) return VESMAIL_E_TLS;
#ifndef VESMAIL_LOCAL
    if (srv->tls.server->snifn && (
	SSL_CTX_set_tlsext_servername_callback(ctx, &VESmail_tls_server_snifn) <= 0
	|| SSL_CTX_set_tlsext_servername_arg(ctx, srv) <= 0
    )) {
	SSL_CTX_free(ctx);
	return VESMAIL_E_TLS;
    }
#endif
    VESmail_arch_set_nb(BIO_get_fd(srv->req_bio, NULL), 0);
    SSL *ssl = SSL_new(ctx);
    SSL_set_bio(ssl, srv->req_bio, srv->rsp_out->bio);
    int r = SSL_accept(ssl);
    if (srv->tls.server->snifn) SSL_CTX_free(ctx);
    BIO *bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl((srv->req_bio = bio), ssl, BIO_NOCLOSE);
    bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl((srv->rsp_out->bio = bio), ssl, BIO_CLOSE);
    if (r != 1) return VESMAIL_E_TLS;
    srv->flags |= VESMAIL_SRVF_TLSS;
    return 0;
}

void VESmail_tls_server_ctxinit(VESmail_server *srv) {
    VESmail_tls_server_ctx(srv, 0);
}

void VESmail_tls_server_ctxreset(VESmail_tls_server *tls) {
    if (!tls) return;
    if (tls->ctx) SSL_CTX_free(tls->ctx);
    tls->ctx = NULL;
}

void VESmail_tls_server_done(VESmail_server *srv) {
    VESmail_tls_server *tls = srv->tls.server;
    if (tls) {
	SSL *ssl = NULL;
	BIO_get_ssl(srv->req_bio, &ssl);
	if (ssl) SSL_shutdown(ssl);
	srv->tls.server = NULL;
    }
}

void VESmail_tls_server_free(VESmail_tls_server *tls) {
    if (tls) {
	VESmail_tls_server_ctxreset(tls);
    }
    free(tls);
}


void VESmail_tls_initclientctx(void *sslctx) {
    SSL_CTX_set_options(sslctx, VESMAIL_TLS_HIGHOPTNS | VESMAIL_TLS_CLNOPTNS);
#ifdef VESMAIL_TLS_CLNMODE
    SSL_CTX_set_mode(sslctx, VESMAIL_TLS_CLNMODE);
#endif
}

#if defined(HAVE_CURL_CURL_H) && defined(__ANDROID__)
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>

// fdsan tagging was introduced in Android Q (API 29). minSdk on this app
// is 21, so the public header hides the prototypes behind __ANDROID_API__
// >= 29. Forward-declare with weak linkage so we compile against older
// platform headers; at runtime, null-check before calling — pre-29 devices
// have no fdsan, so raw close() is fine there.
enum android_fdsan_owner_type {
    ANDROID_FDSAN_OWNER_TYPE_GENERIC_00 = 0,
};
uint64_t android_fdsan_create_owner_tag(enum android_fdsan_owner_type, uint64_t)
    __attribute__((weak));
void android_fdsan_exchange_owner_tag(int, uint64_t, uint64_t) __attribute__((weak));
int android_fdsan_close_with_tag(int, uint64_t) __attribute__((weak));
uint64_t android_fdsan_get_owner_tag(int) __attribute__((weak));
enum android_fdsan_error_level {
    ANDROID_FDSAN_ERROR_LEVEL_DISABLED,
    ANDROID_FDSAN_ERROR_LEVEL_WARN_ONCE,
    ANDROID_FDSAN_ERROR_LEVEL_WARN_ALWAYS,
    ANDROID_FDSAN_ERROR_LEVEL_FATAL,
};
enum android_fdsan_error_level android_fdsan_set_error_level(enum android_fdsan_error_level)
    __attribute__((weak));

// Tag every curl-owned socket FD with fdsan ownership, so the Android
// network stack cannot silently take over a recycled FD number, and so a
// stray double-close from curl/openssl cleanup gets noticed at the
// offending close rather than aborting on a later, unrelated close from
// Parcel/unique_fd. Without this, the snif and libVES curl call sites
// race with Binder/Parcel FD handout and trigger SIGABRT in fdsan_error.
static uint64_t VESmail_tls_curl_fdtag() {
    // The NDK helper just packs (type, value) into a u64 — pure function
    // of fixed inputs. Cache the result so each open/close/get does one
    // load instead of three weak-symbol calls. Benign race if first hit
    // is concurrent: both threads compute the same tag and overwrite.
    static uint64_t cached = 0;
    if (cached) return cached;
    if (!android_fdsan_create_owner_tag) return 0;
    cached = android_fdsan_create_owner_tag(ANDROID_FDSAN_OWNER_TYPE_GENERIC_00,
	(uint64_t)(uintptr_t) &VESmail_tls_curl_fdtag);
    return cached;
}

static curl_socket_t VESmail_tls_curl_open(void *clientp, curlsocktype purpose,
	struct curl_sockaddr *addr) {
    int fd = socket(addr->family, addr->socktype, addr->protocol);
    if (fd >= 0 && android_fdsan_exchange_owner_tag) {
	android_fdsan_exchange_owner_tag(fd, 0, VESmail_tls_curl_fdtag());
    }
    return fd;
}

static int VESmail_tls_curl_close(void *clientp, curl_socket_t fd) {
    if (android_fdsan_close_with_tag) {
	// libcurl/openssl teardown is known to issue close() twice for the
	// same socket in some paths. The first close clears our tag; on
	// the second call, the FD slot is either freed or has been handed
	// to another subsystem — either way fdsan would abort. Skip when
	// the FD no longer carries our tag.
	if (android_fdsan_get_owner_tag &&
	    android_fdsan_get_owner_tag(fd) != VESmail_tls_curl_fdtag()) {
	    return 0;
	}
	return android_fdsan_close_with_tag(fd, VESmail_tls_curl_fdtag());
    }
    return close(fd);
}
#endif

void VESmail_tls_initcurl(void *curl) {
#if defined(HAVE_CURL_CURL_H) && defined(__ANDROID__)
    static int level_set = 0;
    if (!level_set) {
	level_set = 1;
	if (android_fdsan_set_error_level) {
	    android_fdsan_set_error_level(ANDROID_FDSAN_ERROR_LEVEL_WARN_ALWAYS);
	}
    }
    curl_easy_setopt((CURL *) curl, CURLOPT_OPENSOCKETFUNCTION, &VESmail_tls_curl_open);
    curl_easy_setopt((CURL *) curl, CURLOPT_CLOSESOCKETFUNCTION, &VESmail_tls_curl_close);
#endif
}

#ifndef VESMAIL_X509STORE
#ifdef HAVE_CURL_CURL_H
CURLcode VESmail_tls_fn_curlctx(CURL *curl, void *sslctx, void *parm) {
    VESmail_tls_initclientctx(sslctx);
    return 0;
}
#endif

void VESmail_tls_setcurlctx(void *curl) {
    VESmail_tls_initcurl(curl);
#ifdef HAVE_CURL_CURL_H
    curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, &VESmail_tls_fn_curlctx);
    if (VESmail_tls_caBundle) curl_easy_setopt(curl, CURLOPT_CAINFO, VESmail_tls_caBundle);
#else
#pragma message ("Cannot set CA bundle for libVES - need curl/curl.h")
#endif
#ifdef VESMAIL_CURLSH
    VESmail_curlsh_apply(curl);
#endif
}
#endif

static void VESmail_tls_fn_veshttp(libVES *ves) {
    VESmail_tls_setcurlctx(ves->curl);
}

static char *VESmail_tls_VES_apiUrl = NULL;
static char *VESmail_tls_VES_wwwUrl = NULL;

/* Replace the cached URL strings, freeing any previous copy. The function
 * owns its storage — callers can pass transient pointers (JNI UTF chars,
 * stack buffers) without strdup'ing. Pass NULL to clear a slot. */
void VESmail_tls_setVESurls(const char *apiUrl, const char *wwwUrl) {
    if (apiUrl != VESmail_tls_VES_apiUrl) {
	free(VESmail_tls_VES_apiUrl);
	VESmail_tls_VES_apiUrl = apiUrl ? strdup(apiUrl) : NULL;
    }
    if (wwwUrl != VESmail_tls_VES_wwwUrl) {
	free(VESmail_tls_VES_wwwUrl);
	VESmail_tls_VES_wwwUrl = wwwUrl ? strdup(wwwUrl) : NULL;
    }
}

libVES *VESmail_tls_initVES(libVES *ves) {
    ves->httpInitFn = &VESmail_tls_fn_veshttp;
#ifdef LIBVES_SESS_TMOUT
    ves->sessionTimeout = LIBVES_SESS_TMOUT;
#endif
    if (VESmail_tls_VES_apiUrl) libVES_setOption(ves, LIBVES_O_APIURL, (void *)VESmail_tls_VES_apiUrl);
    if (VESmail_tls_VES_wwwUrl) libVES_setOption(ves, LIBVES_O_WWWURL, (void *)VESmail_tls_VES_wwwUrl);
    return ves;
}

void VESmail_tls_done() {
#ifdef VESMAIL_CURLSH
    VESmail_curlsh_done();
#endif
#ifdef HAVE_CURL_CURL_H
    curl_global_cleanup();
#endif
#ifdef VESMAIL_OPENSSL_LOCKFN
    CRYPTO_set_locking_callback(NULL);
    int n = CRYPTO_num_locks();
    int i;
    for (i = 0; i < n; i++) VESmail_arch_mutex_done(VESmail_tls_extLocks[i]);
    free(VESmail_tls_extLocks);
#endif
#ifdef VESMAIL_X509STORE
    VESmail_x509store_done();
#endif
}
