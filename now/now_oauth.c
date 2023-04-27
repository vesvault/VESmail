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

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <libVES.h>
#include <libVES/VaultKey.h>
#include <libVES/KeyAlgo_EVP.h>
#include "../VESmail.h"
#include "../srv/server.h"
#include "../srv/conf.h"
#include "../srv/arch.h"
#include "../lib/util.h"
#include "../lib/xform.h"
#include "../lib/optns.h"
#include "now.h"
#include "now_oauth.h"


struct VESmail_now_oauth *VESmail_now_oauth_new(const char *path, const char *passphrase, const char *algo) {
    libVES_VaultKey dummy_vkey = { .ves = libVES_new(NULL) };
    if (!algo) algo = VESMAIL_NOW_OAUTH_KEYALGO;
    const libVES_KeyAlgo *a = libVES_VaultKey_algoFromStr(algo);
    if (!a || !a->str2privfn) return NULL;
    if (!passphrase) passphrase = VESMAIL_NOW_OAUTH_KEYPASSWD;
    libVES_veskey *veskey = libVES_veskey_new(strlen(passphrase), passphrase);
    char *pem = VESmail_conf_get_content(path);
    void *priv = a->str2privfn(&dummy_vkey, pem, veskey);
    libVES_VaultKey *vkey = priv || !pem ? libVES_VaultKey_new(LIBVES_VK_PENDING, a, priv, veskey, dummy_vkey.ves) : NULL;
    if (!vkey) {
	free(pem);
#if LIBVES_VERSION >= 0x01020000
	libVES_KeyAlgo_pkeyfree(a, priv);
#endif
	pem = NULL;
    } else if (!pem) {
	int fd = VESmail_arch_creat(path);
	if (fd >= 0) {
	    int l = strlen(vkey->privateKey);
	    int w = VESmail_arch_write(fd, vkey->privateKey, l);
	    if (VESmail_arch_close(fd) >= 0 && w == l) pem = vkey->privateKey;
	}
    }
    if (!pem) {
	libVES_VaultKey_free(vkey);
	libVES_free(dummy_vkey.ves);
	vkey = NULL;
    }
    libVES_veskey_free(veskey);
    free(pem);
    return (void *) vkey;
}

int VESmail_now_oauth_decrypt(struct VESmail_now_oauth *oauth, char **ppass, const char *token, int len) {
    *ppass = NULL;
    char *t = VESmail_strndup(token, len);
    int l = libVES_VaultKey_decrypt((void *) oauth, t, ppass);
    free(t);
    return l;
}

void VESmail_now_oauth_free(struct VESmail_now_oauth *oauth) {
    libVES_VaultKey *vkey = (void *) oauth;
    libVES *ves = vkey ? vkey->ves : NULL;
    libVES_VaultKey_free(vkey);
    libVES_free(ves);
}

int VESmail_now_oauth_reqStack(VESmail_now_req *req) {
    if (strcmp(req->method, "GET") || req->uri.search - req->uri.path < 5 || memcmp(req->uri.path, "oauth", 5)) return VESMAIL_E_HOLD;
    VESmail_server *srv = req->xform->server;
    libVES_VaultKey *vkey = (void *) VESmail_now_CONF(srv, oauth);
    if (!vkey || !vkey->publicKey) return VESmail_now_error(srv, 404, "OAuth server not initialized\r\n");
    int rs = VESmail_now_send_status(srv, 200);
    if (rs < 0) return rs;
    int r = VESmail_now_sendcl(srv, vkey->publicKey);
    if (r < 0) return r;
    rs += r;
    r = VESmail_now_send(srv, 0, "Content-Type: application/x-pem-file\r\n");
    if (r < 0) return r;
    rs += r;
    r = VESmail_now_sendhdrs(srv);
    if (r < 0) return r;
    rs += r;
    r = VESmail_now_send(srv, 1, vkey->publicKey);
    if (r < 0) return r;
    rs += r;
    srv->flags |= VESMAIL_SRVF_SHUTDOWN;
    return rs;
}
