/***************************************************************************
 *  _____
 * |\    | >                   VESmail Project
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
 * (c) 2020 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include "../VESmail.h"
#include <jVar.h>
#include "server.h"
#include "../lib/xform.h"
#include "arch.h"
#include "tls.h"

int VESmail_tls_init() {
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    if (SSL_library_init() < 0) return VESMAIL_E_TLS;
    return 0;
}

VESmail_tls_client *VESmail_tls_client_new(jVar *conf, char *host) {
    static const char *levels[] = { "none", "optional", "unsecure", "medium", "high", NULL };
    VESmail_tls_client *tls = malloc(sizeof(VESmail_tls_client));
    int lvl = jVar_getEnum(jVar_get(conf, "level"), levels);
    tls->level = lvl >= 0 ? lvl : VESMAIL_TLS_HIGH;
    tls->persist = jVar_getBool(jVar_get(conf, "persist"));
    tls->peer = host;
    return tls;
}

int VESmail_tls_cert_ok(VESmail_server *srv, X509 *crt) {
#if	(OPENSSL_VERSION_NUMBER >= 0x10002000L)
    return srv->tls.client->level <= VESMAIL_TLS_UNSECURE
	|| X509_check_host(crt, srv->tls.client->peer, 0, 0, NULL) > 0;
#else
#warning
#warning ********************************************************
#warning Peer host validation is not supported in OpenSSL < 1.0.2
#warning ********************************************************
#warning
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
    SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify_depth(ctx, 8);
    if (srv->tls.client->level > VESMAIL_TLS_MEDIUM) {
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    }
    VESmail_arch_set_nb(BIO_get_fd(srv->rsp_bio, NULL), 0);
    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, srv->tls.client->peer);
    SSL_set_bio(ssl, srv->rsp_bio, srv->req_out->bio);
    int r = SSL_connect(ssl);
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
	crt_ok = (vrfy == X509_V_OK && VESmail_tls_cert_ok(srv, crt));
	X509_free(crt);
    } else {
	VESMAIL_SRV_DEBUG(srv, 1, sprintf(debug, "[crt] NULL"))
	crt_ok = 0;
    }
    if (!crt_ok && srv->tls.client->level > VESMAIL_TLS_UNSECURE) {
	SSL_free(ssl);
	return VESMAIL_E_TLS;
    }
    BIO *bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl((srv->rsp_bio = bio), ssl, BIO_NOCLOSE);
    bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl((srv->req_out->bio = bio), ssl, BIO_CLOSE);
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
    tls->ca = NULL;
    tls->key = NULL;
    tls->persist = 0;
    tls->snifn = NULL;
    return tls;
}

SSL_CTX *VESmail_tls_server_ctx(VESmail_server *srv) {
    if (srv->tls.server->ctx) return srv->tls.server->ctx;
#if	(OPENSSL_VERSION_NUMBER >= 0x10100000L)
    const SSL_METHOD *method = TLS_server_method();
#else
    const SSL_METHOD *method = TLSv1_2_server_method();
#endif
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) return NULL;
    if ((srv->tls.server->cert && SSL_CTX_use_certificate_file(ctx, srv->tls.server->cert, SSL_FILETYPE_PEM) <= 0)
	|| (srv->tls.server->key && (
	    SSL_CTX_use_PrivateKey_file(ctx, srv->tls.server->key, SSL_FILETYPE_PEM) <= 0
	    || SSL_CTX_check_private_key(ctx) <= 0))
	|| (srv->tls.server->ca && SSL_CTX_use_certificate_chain_file(ctx, srv->tls.server->ca) <= 0)
	) {
	SSL_CTX_free(ctx);
	return NULL;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    return srv->tls.server->ctx = ctx;
}

int VESmail_tls_server_snifn(SSL *ssl, int *al, void *arg) {
    VESmail_server *srv = arg;
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!sni) return SSL_TLSEXT_ERR_NOACK;
    int r = srv->tls.server->snifn(srv, sni);
    if (r < 0) return SSL_TLSEXT_ERR_ALERT_FATAL;
    SSL_CTX *ctx = VESmail_tls_server_ctx(srv);
    if (!ctx) return SSL_TLSEXT_ERR_ALERT_FATAL;
    SSL_CTX *ctx2 = SSL_set_SSL_CTX(ssl, ctx);
    if (ctx2 != ctx) return SSL_TLSEXT_ERR_NOACK;
    return SSL_TLSEXT_ERR_OK;
}

int VESmail_tls_server_start(VESmail_server *srv, int starttls) {
    if (!srv->tls.server) return starttls ? VESMAIL_E_PARAM : 0;
    if (!starttls && !srv->tls.server->persist) return 0;
    SSL_CTX *ctx = VESmail_tls_server_ctx(srv);
    if (!ctx) return VESMAIL_E_TLS;
    if (srv->tls.server->snifn && (
	SSL_CTX_set_tlsext_servername_callback(ctx, &VESmail_tls_server_snifn) <= 0
	|| SSL_CTX_set_tlsext_servername_arg(ctx, srv) <= 0
    )) {
	SSL_CTX_free(ctx);
	return VESMAIL_E_TLS;
    }
    VESmail_arch_set_nb(BIO_get_fd(srv->req_bio, NULL), 0);
    SSL *ssl = SSL_new(ctx);
    SSL_set_bio(ssl, srv->req_bio, srv->rsp_out->bio);
    int r = SSL_accept(ssl);
    if (r != 1) return VESMAIL_E_TLS;
    BIO *bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl((srv->req_bio = bio), ssl, BIO_NOCLOSE);
    bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl((srv->rsp_out->bio = bio), ssl, BIO_CLOSE);
    srv->flags |= VESMAIL_SRVF_TLSS;
    return 0;
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
	VESmail_tls_server_ctxreset(tls);
	srv->tls.server = NULL;
    }
}
