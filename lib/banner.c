/***************************************************************************
 *  _____
 * |\    | >                   VESmail Project
 * | \   | >  ___       ___    Email Encryption made Convenient and Reliable
 * |  \  | > /   \     /   \                              https://mail.ves.world
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
#include <stdio.h>
#include <libVES/Cipher.h>
#include "../VESmail.h"
#include "mail.h"
#include "optns.h"
#include "parse.h"
#include "xform.h"
#include "banner.h"


char *VESmail_banner_get_var(VESmail *mail, const char *var) {
    if (!strcmp(var, "url")) {
	const char *now = VESmail_nowUrl(mail);
	if (now) return strdup(now);
    }
    return NULL;
}

int VESmail_banner_resolve(VESmail *mail, VESmail_xform *xform, const char *banner, int len) {
    const char *s = banner;
    const char *s0 = s;
    const char *tail = banner + len;
    const char *v;
    int r;
    int rs = 0;
    while (s < tail && (v = memchr(s, '{', tail - s))) {
	s = v + 1;
	if (s < tail && *s == '$') {
	    char var[32];
	    char *d = var;
	    s++;
	    while (s < tail && d < var + sizeof(var) - 1) {
		char c = *s++;
		if (c == '}') {
		    *d = 0;
		    char *val = VESmail_banner_get_var(mail, var);
		    if (val) {
			r = VESmail_xform_process(xform, 0, s0, v - s0);
			s0 = s;
			if (r >= 0) {
			    rs += r;
			    r = VESmail_xform_process(xform, 0, val, strlen(val));
			    if (r >= 0) rs += r;
			}
			free(val);
			if (r < 0) return r;
		    }
		    break;
		} else if ((c >= 'a' && c <= 'z') || c == '_') {
		    *d++ = c;
		} else break;
	    }
	}
    }
    if (tail > s0) {
	r = VESmail_xform_process(xform, 0, s0, tail - s0);
	if (r < 0) return r;
	rs += r;
    }
    return rs;
}

const char *VESmail_banner_DEFAULT[] = {
	"Content-Type: text/plain\r\n\r\n"
	"This is a VESmail encrypted message."
	"\r\n\r\n"
	"If you are new to VES, check your inbox for another email message\r\n"
	"sent to you by onboard@vesvault.com, the subject line is\r\n"
	"\"Set up your VES account\", and follow the link in that email.\r\n\r\n"
	"If you already have your VES account set up, use the following\r\n"
	"link to set up your VESmail:\r\n\r\n"
	"https://mail.ves.world\r\n\r\n",

	"Content-Type: text/html\r\n\r\n"
	"<html><head></head><body>\r\n"
	"<p>This is a VESmail encrypted message.</p>\r\n"
	"<p>If you are new to VES, check your inbox for another email message\r\n"
	"sent to you by <q>onboard@vesvault.com</q>, the subject line is\r\n"
	"<q>Set up your VES account</q>, and follow the link in that email.</p>\r\n"
	"<p>If you already have your VES account set up, use the following\r\n"
	"link to set up your VESmail:<br/>\r\n"
	"<a href=\"https://mail.ves.world\">https://mail.ves.world</a></p>\r\n"
	"</body></html>\r\n",

	NULL
};

const char *VESmail_banner_DEFAULT_now[] = {
	"Content-Type: text/plain\r\n\r\n"
	"This is a VESmail encrypted message."
	"\r\n\r\n"
	"If you are new to VES, check your inbox for another email message\r\n"
	"sent to you by onboard@vesvault.com, the subject line is\r\n"
	"\"Set up your VES account\", and follow the link in that email.\r\n\r\n"
	"If you already have your VES account set up, use the following\r\n"
	"link to view this email online through the online viewer provided by\r\n"
	"the Sender:\r\n\r\n"
	"{$url}\r\n\r\n",
	
	"Content-Type: text/html\r\n\r\n"
	"<html><head></head><body>\r\n"
	"<p>This is a VESmail encrypted message.</p>\r\n"
	"<p>If you are new to VES, check your inbox for another email message\r\n"
	"sent to you by <q>onboard@vesvault.com</q>, the subject line is\r\n"
	"<q>Set up your VES account</q>, and follow the link in that email.</p>\r\n"
	"<p>If you already have your VES account set up, use the following\r\n"
	"link to view this email online through the online viewer provided by\r\n"
	"the Sender:<br/>\r\n<a href=\"{$url}\">{$url}</a></p>\r\n"
	"</body></html>\r\n",

	NULL
};

int VESmail_check_inject(VESmail_parse *parse) {
    if (parse->mail->flags & VESMAIL_F_BANNER_ADDED) return 0;
    switch (parse->encap) {
	case VESMAIL_EN_ROOT:
	case VESMAIL_EN_MULTI:
	    switch (parse->ctype) {
		case VESMAIL_T_UNDEF:
		    return VESMAIL_E_HOLD;
		case VESMAIL_T_ALT:
		case VESMAIL_T_MULTI:
		    return 0;
		default:
		    return 1;
	    }
	default:
	    return 0;
    }
}

int VESmail_banner_render(VESmail *mail, VESmail_xform *xform, const char *boundary) {
    int rs = 0;
    int r = 0;
    char *bnd = malloc(strlen(boundary) + 256);
    sprintf(bnd, "\r\n--%s\r\nX-VESmail-Part: banner\r\n", boundary);
    int bndl = strlen(bnd);
    const char **b = mail->optns->getBanners ? mail->optns->getBanners(mail->optns) : NULL;
    if (!b) {
	b = VESmail_nowUrl(mail) ? VESmail_banner_DEFAULT_now : VESmail_banner_DEFAULT;
    }
    for (; *b; b++) {
	r = VESmail_xform_process(xform, 0, bnd, bndl);
	if (r < 0) break;
	rs += r;
	int len = strlen(*b);
	r = VESmail_banner_resolve(mail, xform, *b, len);
	if (r < 0) break;
	rs += r;
    }
    free(bnd);
    if (r < 0) return r;
    mail->flags |= VESMAIL_F_BANNER_ADDED;
    return rs;
}

int VESmail_banner_alt_inject_fn(VESmail_xform *xform) {
    VESmail *mail = xform->parse->mail;
    int rs = VESmail_banner_render(mail, xform->chain, xform->parse->injboundary);
    if (rs < 0) return rs;
    char buf[256];
    sprintf(buf, "\r\n--%s--\r\n", xform->parse->injboundary);
    int r = VESmail_xform_process(xform->chain, 1, buf, strlen(buf));
    if (r < 0) return r;
    return rs + r;
}

struct VESmail_xform_inject VESmail_banner_alt_inject = {
    .prefn = NULL,
    .postfn = &VESmail_banner_alt_inject_fn
};
