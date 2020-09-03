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
#include "../VESmail.h"
#include "parse.h"
#include "mail.h"
#include "util.h"
#include "xform.h"
#include "cte.h"


int VESmail_xform_fn_b64dec(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) {
	*srclen = xform->buflen + 16;
	return 0;
    }
    const char *e = NULL;
    char *buf = NULL;
    int len = VESmail_b64decode(&buf, src, srclen, &e);
    if (e) xform->parse->error |= VESMAIL_PE_CTE;
    int r = VESmail_xform_process(xform->chain, final, buf, len);
    free(buf);
    return r;
}

int VESmail_xform_fn_qpdec(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) {
	*srclen = xform->buflen + 16;
	return 0;
    }
    const char *s = src;
    const char *tail = s + *srclen;
    char *dst = malloc(*srclen * 2);
    char *d = dst;
    const char *sp = NULL;
    const char *eq = NULL;
    unsigned int eqv;
    *srclen = 0;
    while (s < tail) {
	char c = *s++;
	switch (c) {
	    case '=': {
		if (eq) break;
		eq = s - 1;
		if (sp) {
		    int l = eq - sp;
		    memcpy(d, sp, l);
		    d += l;
		    *srclen = eq - src;
		    sp = NULL;
		}
		eqv = 1;
		continue;
	    }
	    case ' ': case '\t': case '\r':
		if (!sp) sp = s - 1;
		continue;
	    case '\n':
		if (!eq) {
		    *d++ = '\r';
		    *d++ = '\n';
		}
		eq = sp = NULL;
		*srclen = s - src;
		continue;
	    default:
		break;
	}
	if (eq) {
	    eqv <<= 4;
	    if (sp) c = 0;
	    if (c >= '0' && c <= '9') {
		eqv |= c - 0x30;
	    } else if (c >= 'A' && c <= 'F') {
		eqv |= c - 0x37;
	    } else if (c >= 'a' && c <= 'f') {
		eqv |= c - 0x57;
	    } else {
		xform->parse->error |= VESMAIL_PE_CTE;
		sp = eq;
		eq = NULL;
		eqv = 0;
	    }
	    if (eqv >= 0x0100) {
		c = eqv;
		eq = NULL;
	    } else if (eqv) {
		continue;
	    }
	}
	if (sp) {
	    int l = s - sp;
	    memcpy(d, sp, l);
	    d += l;
	    sp = NULL;
	} else {
	    *d++ = c;
	}
	*srclen = s - src;
    }
    if (final) {
	if (eq) {
	    xform->parse->error |= VESMAIL_PE_CTE;
	    int l = tail - eq;
	    memcpy(d, eq, l);
	    *srclen += l;
	    d += l;
	} else if (sp) {
	    *srclen += tail - sp;
	}
    }
    int r = VESmail_xform_process(xform->chain, final, dst, d - dst);
    free(dst);
    return r;
}

#define VESMAIL_B64LEN		57
#define VESMAIL_QPLEN		76

int VESmail_xform_fn_b64enc(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) {
	*srclen = 3;
	return 0;
    }
    char *dst = malloc((*srclen / VESMAIL_B64LEN + 2 ) * ((VESMAIL_B64LEN + 2) / 3 * 4 + 2));
    char *d = dst;
    const char *s = src;
    const char *tail = src + *srclen;
    while (s < tail) {
	int l = VESMAIL_B64LEN - xform->offset;
	if (s + l > tail) {
	    l = tail - s;
	    if (!final) l = (l / 3) * 3;
	}
	if (l > 0) VESmail_b64encode(s, l, d);
	s += l;
	d += VESmail_b64encsize(l) - 1;
	xform->offset += l;
	if (xform->offset >= VESMAIL_B64LEN || (final && s >= tail)) {
	    xform->offset = 0;
	    *d++ = '\r';
	    *d++ = '\n';
	}
	*srclen = s - src;
	if (!l) break;
    }
    int r = VESmail_xform_process(xform->chain, final, dst, d - dst);
    free(dst);
    return r;
}

int VESmail_xform_fn_qpenc(VESmail_xform *xform, int final, const char *src, int *srclen) {
    static const char hex[16] = "0123456789ABCDEF";
    if (!src) {
	*srclen = xform->buflen + 16;
	return 0;
    }
    char *dst = malloc(*srclen * 3 + 3);
    char *d = dst;
    char *d0 = d - xform->offset;
    const char *s = src;
    const char *tail = s + *srclen;
    char *sp = NULL;
    while (s < tail) {
	unsigned char c = *s++;
	switch (c) {
	    case '\r':
		if (s >= tail) {
		    (*srclen)--;
		    if (sp >= d0) (*srclen)--;
		} else if (*s == '\n') {
		    s++;
		    if (sp >= d0) {
			*d++ = '=';
			*d++ = '\r';
			*d++ = '\n';
		    }
		    *d++ = '\r';
		    *d++ = '\n';
		    d0 = d;
		}
		continue;
	    case ' ': case '\t':
		if (s >= tail) {
		    (*srclen)--;
		} else {
		    sp = d;
		    *d++ = c;
		}
		continue;
	    case '=':
		break;
	    default:
		if (c >= 0x21 && c <= 0x7e) {
		    if (d - d0 >= VESMAIL_QPLEN) {
			*d++ = '=';
			*d++ = '\r';
			*d++ = '\n';
			d0 = d;
		    }
		    sp = NULL;
		    *d++ = c;
		    continue;
		}
	}
	if (d - d0 >= VESMAIL_QPLEN - 2) {
	    *d++ = '=';
	    *d++ = '\r';
	    *d++ = '\n';
	    d0 = d;
	}
	sp = NULL;
	*d++ = '=';
	*d++ = hex[c >> 4];
	*d++ = hex[c & 0x0f];
    }
    xform->offset = d - d0;
    int r = VESmail_xform_process(xform->chain, final, dst, d - dst);
    free(dst);
    return r;
}

VESmail_xform *VESmail_xform_new_b64dec(VESmail_parse *parse) {
    return VESmail_xform_new(&VESmail_xform_fn_b64dec, parse->xform, parse);
}

VESmail_xform *VESmail_xform_new_qpdec(VESmail_parse *parse) {
    return VESmail_xform_new(&VESmail_xform_fn_qpdec, parse->xform, parse);
}

VESmail_xform *VESmail_xform_new_b64enc(VESmail_parse *parse) {
    return VESmail_xform_new(&VESmail_xform_fn_b64enc, parse->xform, parse);
}

VESmail_xform *VESmail_xform_new_qpenc(VESmail_parse *parse) {
    return VESmail_xform_new(&VESmail_xform_fn_qpenc, parse->xform, parse);
}
