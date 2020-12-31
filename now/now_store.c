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
#include <openssl/evp.h>
#include "../VESmail.h"
#include "../lib/mail.h"
#include "../lib/optns.h"
#include "../lib/xform.h"
#include "../lib/parse.h"
#include "../srv/arch.h"
#include "now_store.h"


int VESmail_now_store_xform_fn(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    if (xform->fd == VESMAIL_E_HOLD) {
	VESmail *mail = xform->parse->mail;
	if (mail->flags & VESMAIL_F_PASS) {
	    xform->fd = VESMAIL_E_PARAM;
	} else {
	    char *fname = VESmail_now_filename(mail->msgid, mail->optns);
	    if (fname) {
		int fd = VESmail_arch_creat(fname);
		xform->fd = fd < 0 ? VESMAIL_E_IO : fd;
		free(fname);
	    } else if (!final) {
		return *srclen = 0;
	    }
	}
    }
    if (xform->fd >= 0) {
	int l = *srclen;
	const char *s = src;
	while (l > 0) {
	    int w = VESmail_arch_write(xform->fd, s, l);
	    if (w < 0) {
		VESmail_arch_close(xform->fd);
		xform->fd = VESMAIL_E_IO;
		break;
	    }
	    s += w;
	    l -= w;
	}
	if (final) VESmail_arch_close(xform->fd);
    }
    return VESmail_xform_process(xform->chain, final, src, *srclen);
}

char *VESmail_now_filename(const char *msgid, VESmail_optns *optns) {
    if (!msgid || !optns->now.dir) return NULL;
    int l = strlen(optns->now.dir);
    char *fname = malloc(l + 40);
    strcpy(fname, optns->now.dir);
    unsigned char *d = (unsigned char *) fname + l;
    *d++ = '/';
    void *mdctx = EVP_MD_CTX_create();
    unsigned int shalen = 32;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) > 0
	&& EVP_DigestUpdate(mdctx, msgid, strlen(msgid)) > 0
	&& EVP_DigestFinal_ex(mdctx, d, &shalen) > 0) {
	while (shalen > 0) {
	    unsigned char v = *d % 36;
	    *d++ = (v >= 10 ? 'a' - 10 : '0') + v;
	    shalen--;
	}
	*d = 0;
    } else {
	free(fname);
	fname = NULL;
    }
    EVP_MD_CTX_destroy(mdctx);
    return fname;
}

VESmail *VESmail_now_store_apply(VESmail *mail) {
    if (!mail || !mail->optns->now.dir) return mail;
    mail->root->xform = VESmail_xform_new(&VESmail_now_store_xform_fn, mail->root->xform, mail->root);
    mail->root->xform->fd = VESMAIL_E_HOLD;
    return mail;
}
