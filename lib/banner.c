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

#define VESmail_banner_PUTS(xform, str, rs)	{\
    int r = VESmail_xform_process(xform, 0, str, strlen(str));\
    if (r < 0) return r;\
    rs += r;\
}

int VESmail_banner_fn_text(VESmail_xform *xform, VESmail *mail) {
    int rs = 0;
    VESmail_banner_PUTS(xform,
	"Content-Type: text/plain\r\n\r\n"
	"This email message is encrypted with VESmail by the sender.\r\n\r\n"
	"Create a free VESmail account to decrypt this message,\r\n"
	"and to be able to send and receive encrypted emails:\r\n\r\n"
	"https://mail.ves.world\r\n",
	rs
    )
    const char *now = VESmail_nowUrl(mail);
    if (now) {
	VESmail_banner_PUTS(xform,
	    "\r\nOr, use the following link to decrypt this email online through the sender's portal:\r\n\r\n",
	    rs
	)
	VESmail_banner_PUTS(xform, now, rs)
	VESmail_banner_PUTS(xform, "\r\n\r\n", rs)
    }
    return rs;
}

int VESmail_banner_fn_html(VESmail_xform *xform, VESmail *mail) {
    int rs = 0;
    VESmail_banner_PUTS(xform,
	"Content-Type: text/html\r\n\r\n"
	"<html><head></head><body>\r\n"
	"<p>This email message is encrypted with VESmail by the sender.</p>\r\n"
	"<p>Create a free VESmail account to decrypt this message,<br/>\r\n"
	"and to be able to send and receive encrypted emails:<br/>\r\n"
	"<a href=\"https://mail.ves.world\">https://mail.ves.world</a></p>\r\n",
	rs
    )
    const char *now = VESmail_nowUrl(mail);
    if (now) {
	VESmail_banner_PUTS(xform,
	    "<p>Or, use the following link to decrypt this email online through the sender's portal:<br/>\r\n<a href=\"",
	    rs
	)
	VESmail_banner_PUTS(xform, now, rs)
	VESmail_banner_PUTS(xform, "\">", rs)
	VESmail_banner_PUTS(xform, now, rs)
	VESmail_banner_PUTS(xform, "</a></p>\r\n", rs)
    }
    VESmail_banner_PUTS(xform,
	"</body></html>\r\n",
	rs
    )
    return rs;
}

int (* VESmail_banner_DEFAULT[])(VESmail_xform *, VESmail *) = {&VESmail_banner_fn_text, &VESmail_banner_fn_html, NULL};

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
    const char **b;
    int rs = 0;
    int r = 0;
    char *bnd = malloc(strlen(boundary) + 256);
    sprintf(bnd, "\r\n--%s\r\nX-VESmail-Part: banner\r\n", boundary);
    int bndl = strlen(bnd);
    int (** bp)(VESmail_xform *xform, VESmail *mail);
    for (bp = mail->optns->banner; *bp; bp++) {
	r = VESmail_xform_process(xform, 0, bnd, bndl);
	if (r < 0) break;
	rs += r;
	r = (*bp)(xform, mail);
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
    int rs = VESmail_banner_render(mail, xform, xform->parse->injboundary);
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
