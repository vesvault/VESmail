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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/ssl.h>
#include <curl/curl.h>
#include <libVES.h>
#include "../VESmail.h"
#include "tls.h"

#ifdef VESMAIL_CURLSH
#include "curlsh.h"
#endif

#include "x509store.h"


void *VESmail_x509store = NULL;

int VESmail_x509store_addcert(const unsigned char *der, int len) {
    if (!VESmail_x509store) {
	VESmail_x509store = X509_STORE_new();
    }
    X509 *crt = d2i_X509(NULL, &der, len);
    if (crt) {
	X509_STORE_add_cert(VESmail_x509store, crt);
	return 0;
    }
    return VESMAIL_E_TLS;
}

int VESmail_x509store_caBundle(const char *fname) {
    if (!VESmail_x509store) {
	VESmail_x509store = X509_STORE_new();
    }
    return (fname
	? X509_STORE_load_locations(VESmail_x509store, fname, NULL)
	: X509_STORE_set_default_paths(VESmail_x509store)
    ) > 0 ? 0 : VESMAIL_E_TLS;
}

static CURLcode VESmail_x509store_fn_curlctx(CURL *curl, void *sslctx, void *parm) {
    VESmail_tls_applyCA(sslctx);
    VESmail_tls_initclientctx(sslctx);
    return 0;
}


// Compatibility with older openssl X509_STORE
#ifndef VESMAIL_X509STORE_FIX
#define VESMAIL_X509STORE_FIX	(OPENSSL_VERSION_NUMBER < 0x10002000L)
#endif

#if VESMAIL_X509STORE_FIX
static struct VESmail_x509store_fix {
    SSL_CTX *ctx;
    struct VESmail_x509store_fix *chain;
} *VESmail_x509store_fix = NULL;
static void *VESmail_x509store_fixmutex = NULL;

static void VESmail_x509store_fixflush() {
    struct VESmail_x509store_fix **pfx, *fx;
    VESmail_arch_mutex_lock(&VESmail_x509store_fixmutex);
    for (pfx = &VESmail_x509store_fix; (fx = *pfx); ) {
	if (fx->ctx->references <= 1) {
	    fx->ctx->cert_store = NULL;
	    SSL_CTX_free(fx->ctx);
	    *pfx = fx->chain;
	    free(fx);
	} else {
	    pfx = &fx->chain;
	}
    }
    VESmail_arch_mutex_unlock(&VESmail_x509store_fixmutex);
}

static void VESmail_x509store_fixadd(SSL_CTX *ctx) {
    CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
    VESmail_arch_mutex_lock(&VESmail_x509store_fixmutex);
    struct VESmail_x509store_fix *fx = malloc(sizeof(*fx));
    fx->ctx = ctx;
    fx->chain = VESmail_x509store_fix;
    VESmail_x509store_fix = fx;
    VESmail_arch_mutex_unlock(&VESmail_x509store_fixmutex);
}
#endif

// VESmail must be compiled with -DVESMAIL_X509STORE to avoid conflicts
// with the functions defined in src/tls.c


void VESmail_tls_setcurlctx(void *curl) {
    curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, &VESmail_x509store_fn_curlctx);
#ifdef VESMAIL_X509STORE_CAINFO
    curl_easy_setopt(curl, CURLOPT_CAINFO, VESMAIL_X509STORE_CAINFO);
#endif
}

void VESmail_tls_applyCA(void *ctx) {
    if (!VESmail_x509store) {
	VESmail_x509store = X509_STORE_new();
	X509_STORE_set_default_paths(VESmail_x509store);
    }
#if	(OPENSSL_VERSION_NUMBER >= 0x10002000L)
    SSL_CTX_set1_verify_cert_store(ctx, VESmail_x509store);
#else
    SSL_CTX_set_cert_store(ctx, VESmail_x509store);
#endif
#if VESMAIL_X509STORE_FIX
    VESmail_x509store_fixflush();
    VESmail_x509store_fixadd(ctx);
#endif
}

void VESmail_x509store_done() {
#if VESMAIL_X509STORE_FIX
    VESmail_x509store_fixflush();
    VESmail_arch_mutex_done(VESmail_x509store_fixmutex);
#endif
    X509_STORE_free(VESmail_x509store);
}

