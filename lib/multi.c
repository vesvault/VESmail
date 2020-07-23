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
#include "xform.h"
#include "banner.h"
#include "util.h"
#include "multi.h"


int VESmail_xform_fn_silence(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return *srclen = 0;
    return final ? VESmail_xform_process(xform->chain, 1, "", 0) : 0;
}

int VESmail_multi_post_fn_part(VESmail_xform *xform) {
    return 0;
}

VESmail_parse *VESmail_multi_new_part(VESmail_xform *xform, int len, const char *pre) {
    static struct VESmail_xform_inject injectPart = {
	.prefn = NULL,
	.postfn = &VESmail_multi_post_fn_part
    };
    VESmail_xform *xnext = VESmail_xform_new_inject(NULL, &injectPart);
    if (xform->parse->vespart != VESMAIL_VP_INJ) xnext->buf = VESmail_strndup(pre, (xnext->buflen = xnext->bufmax = len));
    xnext->chain = xform->chain;
    int encap;
    switch (xform->parse->encap) {
	case VESMAIL_EN_UNDEF:
	case VESMAIL_EN_ROOT:
	case VESMAIL_EN_MULTI:
	    encap = xform->parse->ctype == VESMAIL_T_ALT ?
		(xform->parse->vespart == VESMAIL_VP_INJ ? VESMAIL_EN_INJ : VESMAIL_EN_ALT)
		: VESMAIL_EN_MULTI;
	    break;
	default:
	    encap = VESMAIL_EN_DEEP;
	    break;
    }
    VESmail_parse *parse = VESmail_parse_new(xform->parse->mail, xform->parse->hdrfn, xnext, encap);
    if (xform->parse->partfn) xform->parse->partfn(xform->parse, parse);
    return xnext->parse = parse;
}

int VESmail_multi_pre_fn_post(VESmail_xform *xform) {
    if (!xform->parse) return VESMAIL_E_INTERNAL;
    if (xform->parse->ctype == VESMAIL_T_ALT && xform->parse->vespart == VESMAIL_VP_UNDEF) switch (xform->parse->encap) {
	case VESMAIL_EN_ROOT:
	case VESMAIL_EN_MULTI:
	    return VESmail_banner_render(xform->parse->mail, xform->chain, xform->parse->mpboundary + 2);
	default:
	    break;
    }
    return 0;
}

int VESmail_multi_xform_fn(VESmail_xform *xform, int final, const char *src, int *srclen) {
    static struct VESmail_xform_inject injectPost = {
	.prefn = &VESmail_multi_pre_fn_post,
	.postfn = NULL
    };
    if (!src) {
	*srclen = xform->buflen + 256 + strlen(xform->parse->mpboundary);
	return 0;
    }
    const char *s0 = src;
    const char *s;
    const char *tail = src + *srclen;
    int rs = 0;
    char *b = xform->parse->mpboundary;
    VESmail_parse *next = NULL;
    int nextl, nextl2;
    int bl = strlen(b);
    for (s = src - 1; ; s = (s < tail ? memchr(s, '\n', tail - s) : NULL)) {
	int len;
	if (s) s++;
	int endf = 0;
	if (xform->multi->post) {
	    len = tail - s0;
	    s = NULL;
	    endf = 1;
	} else if (s) {
	    int l = tail - s;
	    if (strncmp(s, b, (l > bl ? bl : l))) continue;
	    if (final && l < bl) continue;
	    const char *s2 = s;
	    if (s2 > s0) s2--;
	    if (s2 > s0 && s2[-1] == '\r') s2--;
	    len = s2 - s0;
	    if (l < bl) {
		s = NULL;
	    } else {
		endf = 1;
		if (l > bl + 1 && s[bl] == '-' && s[bl + 1] == '-') {
		    xform->multi->post = (xform->parse->vespart == VESMAIL_VP_INJ
			? VESmail_xform_new(&VESmail_xform_fn_silence, NULL, xform->parse)
			: VESmail_xform_new_inject(xform->parse, &injectPost));
		    xform->multi->post->chain = xform->chain;
		} else {
		    const char *s1 = memchr(s, '\n', l);
		    if (s1) {
			s1++;
			nextl = s1 - s;
			nextl2 = s1 - s2;
			next = VESmail_multi_new_part(xform, nextl2, s2);
		    } else {
			s = NULL;
		    }
		}
	    }
	} else {
	    len = tail - s0;
	    if (!final && len && tail[-1] == '\r') len--;
	}
	int r;
	if (xform->parse->nested) {
	    r = VESmail_parse_process(xform->parse->nested, endf, s0, &len);
	    if (r < 0) return r;
	    if (endf) {
		VESmail_parse_free(xform->parse->nested);
		xform->parse->nested = NULL;
	    }
	} else {
	    r = VESmail_xform_process((xform->multi->post ? xform->multi->post : xform->chain), (final && s0 + len >= tail), s0, len);
	    if (r < 0) return r;
	}
	rs += r;
	s0 += len;
	if (next) {
	    xform->parse->nested = next;
	    s += nextl;
	    s0 += nextl2;
	    next = NULL;
	}
	if (!s) break;
    }
    *srclen = s0 - src;
    return rs;
}

void VESmail_xform_free_multi(VESmail_xform *xform) {
    if (xform->multi) {
	VESmail_xform_free(xform->multi->post);
    }
    free(xform->multi);
}

VESmail_xform *VESmail_xform_new_multi(VESmail_parse *parse) {
    VESmail_xform *xform = VESmail_xform_new(&VESmail_multi_xform_fn, parse->xform, parse);
    xform->multi = malloc(sizeof(*(xform->multi)));
    xform->freefn = &VESmail_xform_free_multi;
    xform->multi->post = NULL;
    xform->chain = parse->xform;
    return xform;
}
