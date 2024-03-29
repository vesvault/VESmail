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
#include <stdio.h>
#include "../VESmail.h"
#include "../srv/server.h"
#include "imap_token.h"
#include "imap.h"
#include "../lib/parse.h"
#include "../lib/mail.h"
#include "../lib/header.h"
#include "../lib/xform.h"
#include "../lib/decrypt.h"
#include "../lib/util.h"
#include "imap_result.h"
#include "imap_sect.h"
#include "imap_fetch.h"
#include "imap_xform.h"
#include "imap_msg.h"

VESmail_imap_msg *VESmail_imap_msg_init(VESmail_imap_msg *msg, int flags) {
    msg->flags = flags;
    msg->sections = msg->chain = NULL;
    msg->boundary = NULL;
    msg->cphdrs = NULL;
    int i;
    for (i = 0; i < sizeof(msg->headers) / sizeof(msg->headers[0]); i++) msg->headers[i] = NULL;
    return msg;
}

VESmail_imap_msg *VESmail_imap_msg_new(VESmail_server *srv) {
    VESmail_imap_msg *msg = VESmail_imap_msg_init(malloc(sizeof(VESmail_imap_msg) + offsetof(VESmail, root)), VESMAIL_IMAP_MF_INIT | VESMAIL_IMAP_MF_ROOT);
    VESmail_init(VESMAIL_IMAP_MAIL(msg), srv->ves, srv->optns);
    msg->server = srv;
    msg->result = NULL;
    msg->rcount = 0;
    return msg;
}

VESmail_imap_msg *VESmail_imap_msg_new_part(VESmail_imap_msg *parent) {
    VESmail_imap_msg *msg = VESmail_imap_msg_init(malloc(offsetof(VESmail_imap_msg, result)), VESMAIL_IMAP_MF_INIT);
    msg->server = parent->server;
    return msg;
}

static union VESmail_imap_msg_page *VESmail_imap_msg_page_alloc(int pagesize) {
    union VESmail_imap_msg_page *pg = malloc(pagesize * sizeof(*pg));
    int i;
    for (i = 0; i < pagesize; i++) pg[i].ptr = NULL;
    return pg;
}

union VESmail_imap_msg_page *VESmail_imap_msg_page_ptr(VESmail_imap *imap, unsigned int idx, int depth) {
    if (depth <= 0) {
	if (idx == 0) return &imap->msgs.page;
	void *p = imap->msgs.page.ptr;
	if (p) {
	    imap->msgs.page.page = VESmail_imap_msg_page_alloc(imap->msgs.pagesize);
	    imap->msgs.page.page[0].ptr = p;
	}
	imap->msgs.depth++;
	depth = 1;
    }
    union VESmail_imap_msg_page *pp = VESmail_imap_msg_page_ptr(imap, (idx / imap->msgs.pagesize), depth - 1);
    if (!pp->ptr) {
	pp->page = VESmail_imap_msg_page_alloc(imap->msgs.pagesize);
    }
    return &pp->page[idx % imap->msgs.pagesize];
}

int VESmail_imap_msg_pass(VESmail_imap_msg *msg) {
    return msg == &VESmail_imap_msg_PASS || (msg && (msg->flags & VESMAIL_IMAP_MF_PASS));
}

VESmail_imap_msg **VESmail_imap_msg_ptr(VESmail_imap *imap, unsigned int seq) {
    VESmail_imap_msg **msgptr = &VESmail_imap_msg_page_ptr(imap, seq, imap->msgs.depth)->msg;
    if (msgptr && *msgptr != &VESmail_imap_msg_PASS && VESmail_imap_msg_pass(*msgptr) && !((*msgptr)->flags & VESMAIL_IMAP_MF_Q)) {
	VESmail_imap_msg_free(*msgptr);
	*msgptr = &VESmail_imap_msg_PASS;
    }
    return msgptr;
}

VESmail_imap_msg *VESmail_imap_msg_section(VESmail_imap_msg *msg, int seclen, unsigned long int *secn) {
    if (!msg) return NULL;
    if (seclen <= 0) return msg;
    int sn = *secn;
    if (sn < 1) return NULL;
    VESmail_imap_msg *m;
    for (m = msg->sections; m && sn > 1; m = m->chain) sn--;
    if (seclen <= 1) return m;
    if (m && (m->flags & VESMAIL_IMAP_MF_RFC822)) m = m->rfc822;
    return VESmail_imap_msg_section(m, seclen - 1, secn + 1);
}

char *VESmail_imap_msg_set_msgid(VESmail_imap_msg *msg, const char *msgid, int len) {
    if (!msg) return NULL;
    if (msgid) {
	VESmail_header hdr;
	hdr.key = hdr.val = msgid;
	hdr.len = len;
	hdr.type = VESMAIL_H_MSGID;
	VESmail_header_apply_msgid(&hdr, VESMAIL_IMAP_MAIL(msg));
	if (VESMAIL_IMAP_MAIL(msg)->flags & VESMAIL_F_ENCD) msg->flags |= VESMAIL_IMAP_MF_ENCD;
    }
    return VESMAIL_IMAP_MAIL(msg)->msgid;
}

void VESmail_imap_msg_fn_key_val(void *arg, const char *key, const char *val) {
    char **kvp = (char **) arg;
    if (!key || !val) return;
    strcpy(*kvp, key);
    *kvp += strlen(key) + 1;
    strcpy(*kvp, val);
    *kvp += strlen(val) + 1;
}

void VESmail_imap_msg_collect(VESmail_imap_msg *msg, VESmail_parse *parse) {
    if (parse->vespart == VESMAIL_VP_BANNER) return;
    if (parse->ctype == VESMAIL_T_VES) msg->flags |= VESMAIL_IMAP_MF_VES;
    else if (parse->vespart == VESMAIL_VP_INJ) msg->flags |= VESMAIL_IMAP_MF_INJ;
    char *b = VESmail_parse_get_boundary(parse);
    if (b && !msg->boundary) msg->boundary = strdup(b);
    if (msg->flags & VESMAIL_IMAP_MF_ROOT) {
	msg->flags |= ((parse->mail->flags & VESMAIL_F_ENCD) ? VESMAIL_IMAP_MF_ENCD : VESMAIL_IMAP_MF_PASS);
    }
}

void VESmail_imap_msg_set_parse(VESmail_imap_msg *msg, int flags) {
    msg->flags = (msg->flags & ~(VESMAIL_IMAP_MF_CHKBUG)) | (flags & (
	VESMAIL_IMAP_MF_CHKBUG |
	((msg->flags & VESMAIL_IMAP_MF_HDR) ? 0 : VESMAIL_IMAP_MF_PHDR) |
	((msg->flags & VESMAIL_IMAP_MF_BODY) ? 0 : VESMAIL_IMAP_MF_PBODY) |
	((msg->flags & (VESMAIL_IMAP_MF_RANGE | VESMAIL_IMAP_MF_BODY)) ? 0 : VESMAIL_IMAP_MF_PRANGE)));
}

int VESmail_imap_msg_fn_hdr(VESmail_parse *parse, VESmail_header *hdr) {
#define VESMAIL_IMAP_HEADER(tag, hdr)	hdr,
    static const char *hdrs[] = { VESMAIL_IMAP_HEADERS() NULL };
#undef VESMAIL_IMAP_HEADER
    VESmail_imap_msg *msg = (VESmail_imap_msg *) parse->ref;
    VESmail_imap *imap = VESMAIL_IMAP(msg->server);
    if ((msg->flags & VESMAIL_IMAP_MF_PHDR) || imap->results.filter) {
	char lckey[64];
	char *d = lckey;
        const char *k;
	for (k = hdr->key; k < hdr->val && d < lckey + sizeof(lckey) - 1; k++) {
	    char c = *k;
	    switch (c) {
		case ':': case ' ': case 9: case 10: case 13:
		    c = 0;
		default:
		    break;
	    }
	    if (!c) break;
	    *d++ = (c >= 'A' && c <= 'Z') ? c + 0x20 : c;
	}
	*d = 0;
	if (msg->flags & VESMAIL_IMAP_MF_PHDR) {
	    const char **h;
	    int hidx = 0;
	    char **hval = msg->headers;
	    if (*lckey) for (h = hdrs; *h; h++, hidx++, hval++) {
		if (*hval) continue;
		if (!strcmp(lckey, *h)) {
		    VESmail_header *hp = hdr;
		    VESmail_header htmp;
		    int l = hdr->val ? hdr->len - (hdr->val - hdr->key) : 0;
		    if (l > VESMAIL_IMAP_MSG_MAXHDR) {
			int dl = l - VESMAIL_IMAP_MSG_MAXHDR;
			htmp.key = hdr->key;
			htmp.val = hdr->val;
			htmp.len = hdr->len - dl;
			l -= dl;
			hp = &htmp;
		    }
		    *hval = malloc(l + 1);
		    switch (hidx) {
			case VESMAIL_IMAP_H_CONTENT_TYPE:
			case VESMAIL_IMAP_H_CONTENT_TRANSFER_ENCODING:
			case VESMAIL_IMAP_H_CONTENT_DISPOSITION: {
			    const char *extra = NULL;
			    if (VESmail_header_get_val(hp, *hval, &extra)) {
				char *kv = *hval + strlen(*hval) + 1;
				if (extra) VESmail_header_keys_values(extra, hp->len - (extra - hp->key), &VESmail_imap_msg_fn_key_val, &kv);
				*kv = 0;
			    } else {
				free(*hval);
				*hval = NULL;
			    }
			    break;
			}
			default: {
			    char *d = *hval;
			    const char *tail = hp->key + hp->len;
			    const char *s;
			    for (s = hp->val; s && s < tail; s++) {
				char c = *s;
				switch (c) {
				    case 10: case 13: break;
				    default:
					*d++ = c;
					break;
				}
			    }
			    *d++ = 0;
			    *d = 0;
			    break;
			}
		    }
		    break;
		}
	    } else {
		VESmail_imap_msg_collect(msg, parse);
	    }
	}
	if (VESmail_imap_sect_hdr_skip(imap->results.filter, lckey)) return 0;
    }
    if ((msg->flags & (VESMAIL_IMAP_MF_PBODY | VESMAIL_IMAP_MF_ROOT)) == VESMAIL_IMAP_MF_PBODY) {
	msg->flags &= ~VESMAIL_IMAP_MF_CHKBUG;
	if (!(imap->flags & VESMAIL_IMAP_F_MIMEOK) && hdr->type != VESMAIL_H_BLANK) {
	    msg->cphdrs = VESmail_header_dup(hdr, msg->cphdrs);
	}
    }
    if (!(msg->flags & VESMAIL_IMAP_MF_VES) || (imap->flags & VESMAIL_IMAP_F_MIMEOK)) {
	msg->flags &= ~VESMAIL_IMAP_MF_CHKBUG;
    }
    if (msg->flags & VESMAIL_IMAP_MF_CHKBUG) {
	if (imap->flags & VESMAIL_IMAP_F_MIMEBUG) {
	    if (hdr->type == VESMAIL_H_BLANK) {
		msg->flags &= ~VESMAIL_IMAP_MF_CHKBUG;
		VESmail_header *h;
		int rs = 0;
		int r;
		for (h = msg->cphdrs; h; h = h->chain) {
		    r = VESmail_header_output(parse, h);
		    if (r < 0) return r;
		    rs += r;
		}
		r = VESmail_header_output(parse, hdr);
		if (r < 0) return r;
		return rs + r;
	    } else {
		return 0;
	    }
	} else if (msg->headers[VESMAIL_IMAP_H_CONTENT_TYPE]) {
	    msg->flags &= ~VESMAIL_IMAP_MF_CHKBUG;
	    imap->flags |= VESMAIL_IMAP_F_MIMEOK;
	    VESMAIL_SRV_DEBUG(msg->server, 1, sprintf(debug, "[mimebug] MIME bug is refuted"));
	} else if (hdr->type == VESMAIL_H_BLANK) {
	    msg->flags &= ~VESMAIL_IMAP_MF_CHKBUG;
	    msg->flags |= VESMAIL_IMAP_MF_CFMBUG;
	    VESMAIL_SRV_DEBUG(msg->server, 1, sprintf(debug, "[mimebug] MIME bug is suspected, confirmation needed"))
	}
    } else if (msg->flags & VESMAIL_IMAP_MF_CFMBUG) {
	if (msg->headers[VESMAIL_IMAP_H_CONTENT_TYPE]) {
	    msg->flags &= ~VESMAIL_IMAP_MF_CFMBUG;
	    imap->flags |= VESMAIL_IMAP_F_MIMEBUG;
	    VESMAIL_SRV_DEBUG(msg->server, 1, sprintf(debug, "[mimebug] MIME bug is confirmed, workaround activated"))
	} else if (hdr->type == VESMAIL_H_BLANK) {
	    msg->flags &= ~VESMAIL_IMAP_MF_CFMBUG;
	}
    }
    return VESmail_header_output(parse, hdr);
}

int VESmail_imap_msg_fn_xform_calc(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return *srclen = 0;
    VESmail_imap_msg *msg = (VESmail_imap_msg *) xform->data;
    msg->bbytes += *srclen;
    const char *tail = src + *srclen;
    const char *lf;
    for (lf = src; lf < tail && (lf = memchr(lf, '\n', tail - lf)); lf++) {
	msg->lines++;
    }
    if (msg->flags & VESMAIL_IMAP_MF_PRANGE) {
	msg->flags |= VESMAIL_IMAP_MF_RANGE;
	msg->flags &= ~VESMAIL_IMAP_MF_PRANGE;
    }
    return VESmail_xform_process(xform->chain, final, src, *srclen);
}

VESmail_parse *VESmail_imap_msg_parse_set_calc(VESmail_parse *parse) {
    VESmail_imap_msg *msg = (VESmail_imap_msg *) parse->ref;
    if (!(msg->flags & (VESMAIL_IMAP_MF_PHDR | VESMAIL_IMAP_MF_PBODY | VESMAIL_IMAP_MF_PRANGE))) return NULL;
    parse->xform = VESmail_xform_new(&VESmail_imap_msg_fn_xform_calc, parse->xform, parse);
    parse->xform->data = msg;
    msg->bbytes = 0;
    msg->lines = 1;
    return parse;
}

void VESmail_imap_msg_fn_part(VESmail_parse *parse, VESmail_parse *child) {
    VESmail_imap_msg *msg = (VESmail_imap_msg *) parse->ref;
    if (!msg) return;
    if (!(msg->flags & (VESMAIL_IMAP_MF_PHDR | VESMAIL_IMAP_MF_PBODY))) return;
    msg->flags &= ~VESMAIL_IMAP_MF_PHDR;
    int inj = (parse->vespart == VESMAIL_VP_INJ);
    VESmail_imap_msg **ptr;
    if (child) {
	VESmail_imap_msg *prev;
	if (inj) {
	    ptr = &msg;
	} else if (child->encap == VESMAIL_EN_MSG) {
	    ptr = &msg->rfc822;
	} else if (parse->nested) {
	    prev = (VESmail_imap_msg *) parse->nested->ref;
	    ptr = parse->nested->vespart == VESMAIL_VP_BANNER ? &prev : &prev->chain;
	} else {
	    ptr = &msg->sections;
	}
	if (!*ptr) *ptr = VESmail_imap_msg_new_part(msg);
	child->ref = *ptr;
	child->outfn = parse->outfn;
	child->partfn = parse->partfn;
	VESmail_imap_msg_set_parse(*ptr, VESMAIL_IMAP_MF_PHDR | VESMAIL_IMAP_MF_PBODY);
	if (!inj) VESmail_imap_msg_parse_set_calc(child);
    } else if (!inj) {
	if (parse->vespart != VESMAIL_VP_BANNER) {
	    if (parse->encap == VESMAIL_EN_INJ) VESmail_imap_msg_collect(msg, parse);
	    msg->flags |= VESMAIL_IMAP_MF_HDR;
	}
	switch (parse->state) {
	    case VESMAIL_S_HDR:
		msg->hbytes = msg->bbytes;
		msg->bbytes = 0;
		msg->lines = 1;
		break;
	    case VESMAIL_S_BODY: {
		VESmail_imap_msg *m;
		for (ptr = &msg->sections; (m = *ptr); ) {
		    if (m->flags & VESMAIL_IMAP_MF_HDR) {
			ptr = &m->chain;
		    } else {
			*ptr = m->chain;
			m->chain = NULL;
			VESmail_imap_msg_free(m);
		    }
		}
		msg->flags |= VESMAIL_IMAP_MF_BODY | VESMAIL_IMAP_MF_STRUCT;
		msg->flags &= ~VESMAIL_IMAP_MF_PBODY;
		break;
	    }
	    default:
		break;
	}
    } else {
	msg->flags |= VESMAIL_IMAP_MF_HDR;
    }
}

int VESmail_imap_msg_parse_xform_fn(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    if (final && xform->data) {
	int r = VESmail_parse_process(xform->parse, 0, src, srclen);
	if (r < 0) return r;
	if (xform->parse->state == VESMAIL_S_BODY) {
	    int rl = 0;
	    int rr = VESmail_parse_process(xform->parse, 1, "", &rl);
	    if (rr >= 0) return rr + r;
	}
	int r2 = VESmail_xform_process(xform->data, 1, "", 0);
	return r2 < 0 ? r2 : r2 + r;
    } else {
	return VESmail_parse_process(xform->parse, final, src, srclen);
    }
}

void VESmail_imap_msg_parse_xform_freefn(VESmail_xform *xform) {
    VESmail_parse_free(xform->parse);
}

int VESmail_imap_msg_decrypt(VESmail_imap_msg *msg, VESmail_imap_msg *root, int flags, VESmail_imap_token *token, VESmail_imap_fetch *filter) {
    if (!root || !msg) return VESMAIL_E_PARAM;
    if (token->xform) return token->literal || !token->len ? 0 : VESMAIL_E_BUF;
    VESmail_imap_fetch_free(VESMAIL_IMAP(msg->server)->results.filter);
    VESMAIL_IMAP(msg->server)->results.filter = filter;
    if (flags & VESMAIL_IMAP_MF_HDR) {
	if (!(msg->flags & VESMAIL_IMAP_MF_HDR)) return VESMAIL_E_UNKNOWN;
    }
    VESmail_xform *out = VESmail_imap_token_xform_new(token);
    VESmail_parse *parse = VESmail_parse_new(VESMAIL_IMAP_MAIL(root), &VESmail_header_process_dec, out, VESMAIL_EN_UNDEF);
    out->parse = parse;
    parse->ref = msg;
    parse->outfn = &VESmail_imap_msg_fn_hdr;
    VESmail_imap_msg_set_parse(msg, flags);
    if (token->len > VESMAIL_IMAP(msg->server)->maxBufd) {
	token->state = VESMAIL_IMAP_P_RESYNC;
	VESMAIL_SRV_DEBUG(msg->server, 2, sprintf(debug, "token len = %lu > %lu (flags=%x, msg->flags=%x)", token->len, VESMAIL_IMAP(msg->server)->maxBufd, flags, msg->flags))
	if ((msg->flags & (VESMAIL_IMAP_MF_HDR | VESMAIL_IMAP_MF_BODY | VESMAIL_IMAP_MF_RANGE))
	    && !(msg->flags & (VESMAIL_IMAP_MF_PHDR | VESMAIL_IMAP_MF_PBODY | VESMAIL_IMAP_MF_PRANGE))) {
	    token->state = VESMAIL_IMAP_P_SYNC;
	    token->len = (flags & VESMAIL_IMAP_MF_HDR) ? 0 : msg->hbytes;
	    if (flags & (VESMAIL_IMAP_MF_PBODY | VESMAIL_IMAP_MF_PRANGE)) token->len += msg->bbytes;
	}
	(out->chain = VESmail_imap_xform_sync(msg->server->rsp_in))->chain = NULL;
	out->chain->obj = out;
    }
    if (!(msg->flags & VESMAIL_IMAP_MF_BODY)) {
	parse->partfn = &VESmail_imap_msg_fn_part;
	VESmail_imap_msg_parse_set_calc(parse);
    }
    if (flags & VESMAIL_IMAP_MF_HDR) {
	parse->ctype = ((msg->flags & VESMAIL_IMAP_MF_INJ) ? VESMAIL_T_ALT
	    : ((msg->flags & VESMAIL_IMAP_MF_VES) ? VESMAIL_T_VES
	    : VESmail_header_get_ctype(VESmail_imap_msg_header(msg, VESMAIL_IMAP_H_CONTENT_TYPE, NULL, NULL), parse)));
	parse->vespart = ((msg->flags & VESMAIL_IMAP_MF_INJ) ? VESMAIL_VP_INJ
	    : ((parse->ctype == VESMAIL_T_ALT) ? VESMAIL_VP_ALT
	    : VESMAIL_VP_UNDEF));
	parse->dstenc = VESmail_header_get_ctenc(VESmail_imap_msg_header(msg, VESMAIL_IMAP_H_CONTENT_TRANSFER_ENCODING, NULL, NULL));
	parse->ctenc = (msg->flags & VESMAIL_IMAP_MF_VES) ? ((msg->flags & VESMAIL_IMAP_MF_INJ) ? VESMAIL_CTE_BIN : VESMAIL_CTE_B64) : parse->dstenc;
	switch (parse->ctype) {
	    case VESMAIL_T_MULTI:
	    case VESMAIL_T_ALT:
		VESmail_parse_set_boundary(parse, msg->boundary ? msg->boundary : VESmail_imap_msg_hparam(msg, VESMAIL_IMAP_H_CONTENT_TYPE, "boundary"));
	    default:
		break;
	}
	int r = VESmail_parse_skip(parse);
	if (r < 0) {
	    VESmail_parse_free(parse);
	    return r;
	}
    } else {
	if (msg->flags & VESMAIL_IMAP_MF_INJ) parse->vespart = VESMAIL_VP_INJ;
    }
    VESmail_xform *in = VESmail_xform_new(&VESmail_imap_msg_parse_xform_fn, NULL, parse);
    in->data = ((flags & VESMAIL_IMAP_MF_PBODY) ? NULL : out);
    in->freefn = &VESmail_imap_msg_parse_xform_freefn;
    return VESmail_imap_token_xform_apply(token, in);
}

const char *VESmail_imap_msg_header(VESmail_imap_msg *msg, int hdr, int (* callbk)(void *arg, const char *key, const char *val), void *arg) {
    if (hdr < 0 || hdr >= sizeof(msg->headers) / sizeof(msg->headers[0]) || !msg->headers[hdr]) return NULL;
    if (callbk) {
	const char *s = msg->headers[hdr] + strlen(msg->headers[hdr]) + 1;
	while (*s) {
	    const char *v = s + strlen(s) + 1;
	    if (callbk(arg, s, v) < 0) break;
	    s = v + strlen(v) + 1;
	}
    }
    return msg->headers[hdr];
}

int VESmail_imap_msg_fn_hdrpar(void *arg, const char *key, const char *val) {
    if (!strcmp(key, ((char **) arg)[0])) {
	((const char **) arg)[1] = val;
	return -1;
    }
    return 0;
}

const char *VESmail_imap_msg_hparam(VESmail_imap_msg *msg, int hdr, const char *key) {
    struct {
	const char *key;
	char *val;
    } kv = {
	.key = key,
	.val = NULL
    };
    VESmail_imap_msg_header(msg, hdr, &VESmail_imap_msg_fn_hdrpar, &kv);
    return kv.val;
}


void VESmail_imap_msg_free(VESmail_imap_msg *msg) {
    if (msg == &VESmail_imap_msg_PASS) return;
    if (msg) {
	if (msg->flags & VESMAIL_IMAP_MF_ROOT) {
	    VESmail_imap_result *rslt;
	    while ((rslt = msg->result)) {
		msg->result = rslt->mchain;
		VESmail_imap_result_free(rslt);
	    }
	    VESmail_clean(VESMAIL_IMAP_MAIL(msg));
	} else {
	    VESmail_imap_msg_free(msg->chain);
	}
	VESmail_imap_msg_free(msg->sections);
	free(msg->boundary);
	VESmail_header *h;
	while ((h = msg->cphdrs)) {
	    msg->cphdrs = h->chain;
	    VESmail_header_free(h);
	}
	int i;
	for (i = 0; i < sizeof(msg->headers) / sizeof(msg->headers[0]); i++) {
	    char *s = msg->headers[i];
	    if (s) VESmail_cleanse(s, strlen(s));
	    free(s);
	}
    }
    free(msg);
}

void VESmail_imap_msg_page_free(union VESmail_imap_msg_page *pg, int depth, int pagesize) {
    if (depth > 0) {
	int i;
	if (pg->page) for (i = 0; i < pagesize; i++) VESmail_imap_msg_page_free(pg->page + i, depth - 1, pagesize);
	free(pg->page);
    } else {
	VESmail_imap_msg_free(pg->msg);
    }
}
