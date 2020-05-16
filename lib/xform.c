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
#include "../VESmail.h"
#include "parse.h"
#include "mail.h"
#include "util.h"
#include "xform.h"

VESmail_xform *VESmail_xform_new(int (* xformfn)(VESmail_xform *xform, int final, const char *src, int *srclen), VESmail_xform *chain, void *obj) {
    VESmail_xform *xform = malloc(sizeof(VESmail_xform));
    xform->xformfn = xformfn;
    xform->freefn = NULL;
    xform->obj = obj;
    xform->chain = chain;
    xform->buf = NULL;
    xform->buflen = xform->bufmax = xform->offset = 0;
    xform->eof = 0;
    xform->data = NULL;
    return xform;
}

void VESmail_xform_chkbuf(VESmail_xform *xform, int len) {
    if (len > xform->bufmax) {
	xform->bufmax = len + 256;
	xform->buf = realloc(xform->buf, xform->bufmax);
    }
}

int VESmail_xform_process(VESmail_xform *xform, int final, const char *src, int srclen) {
    if (!xform) return 0;
    if (xform->eof) {
	if (xform->eof < 0) return xform->eof;
	return srclen ? VESMAIL_E_BUF : 0;
    }
    int rs = 0;
    int r;
    int cplen = 0;
    int len;
    int ctr = 0;
    while (xform->buflen > cplen) {
	int total = xform->buflen - cplen + srclen;
	len = total;
	r = xform->xformfn(xform, final, NULL, &len);
	if (r < 0) return xform->eof = r;
	rs += r;
	len += ctr++;
	if (len > total) len = total;
	int dl;
	if (len > xform->buflen) {
	    VESmail_xform_chkbuf(xform, len);
	    dl = len - xform->buflen;
	    memcpy(xform->buf + xform->buflen, src + cplen, dl);
	    cplen += dl;
	    xform->buflen = len;
	} else {
	    len = xform->buflen;
	    dl = 0;
	}
	int lfinal = final && len >= total;
	r = xform->xformfn(xform, lfinal, xform->buf, &len);
	if (r < 0) return xform->eof = r;
	rs += r;
	if (lfinal) {
	    xform->eof = 1;
	    return rs;
	}
	if (len + cplen >= xform->buflen) {
	    cplen -= xform->buflen - len;
	    xform->buflen = 0;
	    if (len >= total) return rs;
	    break;
	}
	if (len > 0) {
	    memmove(xform->buf, xform->buf + len, xform->buflen - len);
	    xform->buflen -= len;
	} else if (!dl) {
	    break;
	}
    }
    int total = srclen - cplen;
    if (xform->buflen <= 0) {
	len = total;
	r = xform->xformfn(xform, final, src + cplen, &len);
	if (r < 0) return xform->eof = r;
	rs += r;
    } else {
	len = 0;
    }
    int dl = total - len;
    if (final) {
	xform->eof = 1;
    } else if (dl > 0) {
	VESmail_xform_chkbuf(xform, xform->buflen + dl);
	memcpy(xform->buf + xform->buflen, src + srclen - dl, dl);
	xform->buflen += dl;
    }
    return rs;
}


int VESmail_xform_fn_inject(VESmail_xform *xform, int final, const char *src, int *srclen) {
    int rs = 0;
    if (!xform->offset) {
	if (final && *srclen <= xform->buflen) xform->buflen = 0;
	else if (*srclen > 0 && xform->inject->prefn) {
	    int r = xform->inject->prefn(xform);
	    if (r < 0) return r;
	    rs += r;
	}
    }
    if (!src) {
	*srclen = xform->buflen;
	return rs;
    }
    xform->offset += *srclen;
    int postf = final && xform->inject->postfn;
    int r = VESmail_xform_process(xform->chain, final && !postf, src, *srclen);
    if (r < 0) return r;
    rs += r;
    if (postf) {
	int r = xform->inject->postfn(xform);
	if (r < 0) return r;
	rs += r;
    }
    return rs;
}

VESmail_xform *VESmail_xform_new_inject(VESmail_parse *parse, struct VESmail_xform_inject *inject) {
    VESmail_xform *xform = VESmail_xform_new(&VESmail_xform_fn_inject, (parse ? parse->xform : NULL), parse);
    xform->inject = inject;
    return xform;
}

int VESmail_xform_capture_buf(VESmail_xform *xform, char **buf) {
    if (!xform) return 0;
    if (buf) *buf = xform->buf;
    else free(xform->buf);
    xform->buf = NULL;
    int l = xform->buflen;
    xform->buflen = xform->bufmax = 0;
    return l;
}

VESmail_xform *VESmail_xform_free_chain(VESmail_xform *xform, void *obj) {
    VESmail_xform *next;
    for (; xform && (!obj || xform->obj == obj); xform = next) {
	next = xform->chain;
	VESmail_xform_free(xform);
    }
    return xform;
}

void VESmail_xform_free(VESmail_xform *xform) {
    if (xform) {
	free(xform->buf);
	if (xform->freefn) xform->freefn(xform);
    }
    free(xform);
}
