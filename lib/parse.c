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
#include "../VESmail.h"
#include "mail.h"
#include "header.h"
#include "xform.h"
#include "cte.h"
#include "multi.h"
#include "optns.h"
#include "parse.h"

const struct {
    const char *key;
    int type;
} VESmail_header_KEYS[] = {
    {.key = "", .type = VESMAIL_H_BLANK},
    {.key = "message-id", .type = VESMAIL_H_MSGID},
    {.key = "x-vesmail-id", .type = VESMAIL_H_VESID},
    {.key = "content-type", .type = VESMAIL_H_CTYPE},
    {.key = "content-transfer-encoding", .type = VESMAIL_H_CTENC},
    {.key = "content-disposition", .type = VESMAIL_H_CDISP},
    {.key = "subject", .type = VESMAIL_H_SUBJ},
    {.key = "received", .type = VESMAIL_H_RCVD},
    {.key = "x-vesmail-header", .type = VESMAIL_H_VES},
    {.key = "x-vesmail-part", .type = VESMAIL_H_PART},
    {.key = "x-vesmail-xchg", .type = VESMAIL_H_XCHG},
    {.key = "to", .type = VESMAIL_H_RCPT},
    {.key = "cc", .type = VESMAIL_H_RCPT},
    {.key = "bcc", .type = VESMAIL_H_RCPT},
    {.key = "date", .type = VESMAIL_H_NOENC},
    {.key = "mime-version", .type = VESMAIL_H_NOENC},
    {.key = "reply-to", .type = VESMAIL_H_NOENC},
    {.key = "return-path", .type = VESMAIL_H_NOENC},
    {.key = "envelope-to", .type = VESMAIL_H_NOENC},
    {.key = "from", .type = VESMAIL_H_NOENC},
    {.key = "in-reply-to", .type = VESMAIL_H_NOENC},
    {.key = "references", .type = VESMAIL_H_NOENC},
    {.type = VESMAIL_H_OTHER}
};

VESmail_parse *VESmail_parse_new(VESmail *mail, int (* hdrfn)(struct VESmail_parse *, struct VESmail_header *), struct VESmail_xform *xform, int encap) {
    VESmail_parse *parse = malloc(sizeof(VESmail_parse));
    parse->mail = mail;
    parse->state = VESMAIL_S_INIT;
    parse->ctype = VESMAIL_T_UNDEF;
    parse->ctenc = parse->dstenc = VESMAIL_CTE_UNDEF;
    parse->encap = encap;
    parse->vespart = VESMAIL_VP_UNDEF;
    parse->dechdrs = 0;
    parse->hdrbuf = parse->divertbuf = NULL;
    parse->hdrfn = hdrfn;
    parse->outfn = &VESmail_header_output;
    parse->partfn = NULL;
    parse->xform = xform;
    parse->mpboundary = NULL;
    parse->injboundary = NULL;
    parse->nested = NULL;
    parse->in = NULL;
    return parse;
}

int VESmail_parse_header_type(VESmail_parse *parse, const char *lckey) {
    int i;
    for (i = 0; ; i++) {
	if (VESmail_header_KEYS[i].type == VESMAIL_H_OTHER || !strcmp(lckey, VESmail_header_KEYS[i].key)) {
	    return VESmail_header_KEYS[i].type;
	}
    }
}

VESmail_header *VESmail_parse_blank_inj(const char *src, int srclen) {
    static VESmail_header blank = {
	.type = VESMAIL_H_BLANK
    };
    if (srclen > 0 && src[srclen - 1] == '\n') {
	blank.key = src + srclen - 1;
	if (blank.key > src && blank.key[-1] == '\r') {
	    blank.key--;
	    blank.len = 2;
	} else blank.len = 1;
    } else {
	blank.key = "\r\n";
	blank.len = 2;
    }
    return &blank;
}

int VESmail_parse_hdr(struct VESmail_parse *parse, const char *src, int *srclen) {
    enum { S_INIT, S_BLANK, S_KEY, S_COLON, S_PVAL, S_VAL, S_NEXT, S_PNEXT, S_CONT, S_PCONT, S_ERROR, S_SEND, S_FINISH } st = S_INIT;
    const char *tail = src + *srclen;
    *srclen = 0;
    const char *s = src;
    struct VESmail_header hdr = {.key = s};
    char lckey[48];
    char *plckey;
    int rs = 0;
    while (s < tail) {
	if (st == S_INIT) {
	    hdr.val = NULL;
	    plckey = lckey;
	    hdr.type = VESMAIL_H_UNDEF;
	}
	char c = *s++;
	switch (c) {
	    case ' ': case 9: {
		switch (st) {
		    case S_INIT:
			st = S_BLANK;
			break;
		    case S_KEY:
			st = S_COLON;
			break;
		    case S_NEXT:
			st = S_CONT;
			break;
		    case S_PNEXT:
			st = S_PCONT;
		    default:
			break;
		}
		break;
	    }
	    case 13:
		break;
	    case 10: {
		switch (st) {
		    case S_INIT: case S_BLANK:
			st = S_FINISH;
			hdr.len = s - hdr.key;
			break;
		    case S_CONT: case S_PCONT:
			if (!(parse->mail->flags & VESMAIL_O_HDR_WHITE)) {
			    switch (st) {
				case S_CONT:
				    st = S_NEXT;
				    break;
				case S_PCONT:
				    st = S_PNEXT;
				default:
				    break;
			    }
			    hdr.len = s - hdr.key;
			    break;
			}
		    case S_NEXT: case S_PNEXT:
			st = S_SEND;
			break;
		    case S_PVAL:
			st = S_PNEXT;
			hdr.len = s - hdr.key;
			break;
		    case S_KEY: case S_COLON:
			st = S_ERROR;
			break;
		    default:
			st = S_NEXT;
			hdr.len = s - hdr.key;
			break;
		}
		break;
	    }
	    case ':': {
		if (st == S_KEY || st == S_COLON) {
		    st = S_PVAL;
		    break;
		}
	    }
	    default: {
		switch (st) {
		    case S_INIT:
			st = S_KEY;
		    case S_KEY:
			if (plckey < lckey + sizeof(lckey) - 1) *plckey++ = (c >= 'A' && c <= 'Z') ? c + 0x20 : c;
			break;
		    case S_BLANK:
			st = S_ERROR;
			break;
		    case S_NEXT: case S_PNEXT:
			st = S_SEND;
			break;
		    case S_PVAL: case S_PCONT:
			hdr.val = s - 1;
		    case S_CONT:
			st = S_VAL;
		    default:
			break;
		}
	    }
	}
	switch (st) {
	    case S_ERROR: {
		int r = parse->hdrfn(parse, VESmail_parse_blank_inj(src, *srclen));
		if (r < 0) return r;
		rs += r;
		break;
	    }
	    case S_SEND:
		s--;
	    case S_FINISH: {
		*plckey = 0;
		hdr.type = VESmail_parse_header_type(parse, lckey);
		int r = parse->hdrfn(parse, &hdr);
		if (r < 0) return r;
		rs += r;
		*srclen += hdr.len;
		break;
	    }
	    default:
		break;
	}
	switch (st) {
	    case S_SEND:
		hdr.key += hdr.len;
		st = S_INIT;
		break;
	    case S_ERROR:
		parse->error |= VESMAIL_PE_HDR_BAD;
	    case S_FINISH:
		if (parse->partfn) parse->partfn(parse, NULL);
		parse->state = VESMAIL_S_BODY;
		return rs;
	    default:
		break;
	}
    }
    if (s - hdr.key > VESMAIL_HEADER_SAFEBYTES) return VESMAIL_E_BUF;
    return rs;
}

int VESmail_parse_process(struct VESmail_parse *parse, int final, const char *src, int *srclen) {
    int rs = 0;
    if (parse->state == VESMAIL_S_INIT) parse->state = VESMAIL_S_HDR;
    int srch;
    if (parse->state == VESMAIL_S_HDR) {
	srch = *srclen;
	int r = VESmail_parse_hdr(parse, src, &srch);
	if (r < 0) return r;
	rs += r;
    } else srch = 0;
    if (parse->state == VESMAIL_S_BODY || final) {
	if (parse->state != VESMAIL_S_BODY) {
	    parse->error |= VESMAIL_PE_HDR_END;
	    int r = parse->hdrfn(parse, VESmail_parse_blank_inj(src, srch));
	    if (r < 0) return r;
	    rs += r;
	}
	int r = VESmail_xform_process(parse->xform, final, src + srch, *srclen - srch);
	if (r < 0) return r;
	rs += r;
    } else {
	*srclen = srch;
    }
    if (final && parse->partfn) parse->partfn(parse, NULL);
    return rs;
}

char *VESmail_parse_get_boundary(VESmail_parse *parse) {
    return parse->mpboundary && parse->mpboundary[0] && parse->mpboundary[1] ? parse->mpboundary + 2 : NULL;
}

int VESmail_parse_set_boundary(VESmail_parse *parse, const char *bnd) {
    if (!bnd || !parse || parse->mpboundary) return VESMAIL_E_PARAM;
    char *b = parse->mpboundary = malloc(strlen(bnd) + 3);
    *b = *(b + 1) = '-';
    strcpy(b + 2, bnd);
    return 0;
}

int VESmail_parse_apply_nested(VESmail_parse *parse) {
    switch (parse->ctype) {
	case VESMAIL_T_MULTI:
	case VESMAIL_T_ALT:
	    parse->xform = VESmail_xform_new_multi(parse);
	    break;
	case VESMAIL_T_MSG:
	    parse->xform = VESmail_xform_new_rfc822(parse);
	    break;
	default:
	    break;
    }
    return 0;
}

int VESmail_parse_apply_decode(VESmail_parse *parse) {
    switch (parse->ctenc) {
	case VESMAIL_CTE_B64:
	    parse->xform = VESmail_xform_new_b64dec(parse);
	    break;
	case VESMAIL_CTE_QP:
	    parse->xform = VESmail_xform_new_qpdec(parse);
	default:
	    break;
    }
    return 0;
}

int VESmail_parse_apply_encode(VESmail_parse *parse) {
    switch (parse->dstenc) {
	case VESMAIL_CTE_B64:
	    parse->xform = VESmail_xform_new_b64enc(parse);
	    break;
	case VESMAIL_CTE_QP:
	    parse->xform = VESmail_xform_new_qpenc(parse);
	default:
	    break;
    }
    return 0;
}

int VESmail_xform_fn_in(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    return VESmail_parse_process(xform->parse, final, src, srclen);
}

int VESmail_parse_convert(VESmail_parse *parse, char **dst, int final, const char *src, int srclen) {
    if (!parse) return VESMAIL_E_PARAM;
    if (!parse->in) parse->in = VESmail_xform_new(&VESmail_xform_fn_in, NULL, parse);
    int rs = VESmail_xform_process(parse->in, final, src, srclen);
    if (!dst) return rs;
    if (rs != 0) {
	*dst = NULL;
	return rs;
    }
    return VESmail_xform_capture_buf(parse->mail->out, dst);
}

int VESmail_parse_skip(VESmail_parse *parse) {
    VESmail_header hdr = {
	.key = "",
	.len = 0,
	.type = VESMAIL_H_BLANK
    };
    parse->state = VESMAIL_S_BODY;
    return parse->hdrfn(parse, &hdr);
}

VESmail_xform *VESmail_parse_xform_null(VESmail_parse *parse) {
    return VESmail_xform_new(&VESmail_xform_fn_silence, parse->xform, parse);
}

void VESmail_parse_free(struct VESmail_parse *parse) {
    if (parse) {
	VESmail_header *h;
	for (h = parse->hdrbuf; h;) {
	    VESmail_header *hchain = h->chain;
	    VESmail_header_free(h);
	    if (hchain) h = hchain;
	    else {
		h = parse->divertbuf;
		parse->divertbuf = NULL;
	    }
	}
	VESmail_parse_free(parse->nested);
	VESmail_xform_free(parse->in);
	VESmail_xform_free_chain(parse->xform, parse);
	free(parse->mpboundary);
	free(parse->injboundary);
    }
    free(parse);
}
