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


CURLcode VESmail_x509store_fn_curlctx(CURL *curl, void *sslctx, void *parm) {
    VESmail_tls_applyCA(sslctx);
    return 0;
}

void VESmail_x509store_fn_veshttp(libVES *ves) {
    curl_easy_setopt(ves->curl, CURLOPT_SSL_CTX_FUNCTION, &VESmail_x509store_fn_curlctx);
#ifdef VESMAIL_CURLSH
    VESmail_curlsh_apply(ves->curl);
#endif
}


// VESmail must be compiled with -DVESMAIL_X509STORE to avoid conflicts
// with the functions defined in src/tls.c


void VESmail_tls_applyCA(void *ctx) {
    if (VESmail_x509store) SSL_CTX_set1_verify_cert_store(ctx, VESmail_x509store);
}

libVES *VESmail_tls_initVES(libVES *ves) {
    ves->httpInitFn = &VESmail_x509store_fn_veshttp;
    return ves;
}
