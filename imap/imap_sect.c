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
 * (c) 2020-2026 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * Apache License, Version 2.0
 * You may use, copy, modify, merge, publish, distribute and/or sell copies
 * of the Software under the terms of the Apache License, Version 2.0, a copy
 * of which is provided in the COPYING file, or http://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
 *
 ***************************************************************************/

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/rand.h>
#include "../VESmail.h"
#include "../lib/optns.h"
#include "../srv/server.h"
#include "../lib/util.h"
#include "imap.h"
#include "imap_token.h"
#include "imap_msg.h"
#include "imap_fetch.h"
#include "imap_result.h"
#include "imap_sect.h"

int VESmail_imap_sect_learn_part(VESmail_imap_token *lst, VESmail_imap_msg *msg) {
    int rs = 0;
    if (!VESmail_imap_token_isList(lst) || lst->len < 2) return VESMAIL_E_PARAM;
    VESmail_imap_token *t0 = lst->list[0];
    VESmail_imap_token *t1 = lst->list[1];
    if (!VESmail_imap_token_isAString(t1)) return VESMAIL_E_PARAM;
    if (VESmail_imap_token_isLSet(t0)) {
	VESmail_imap_msg **ptr = &msg->sections;
	int i;
	VESmail_imap_msg *endp = NULL;
	for (i = 0; i < t0->len; i++) {
	    if (!*ptr) *ptr = VESmail_imap_msg_new_part(msg);
	    int r = VESmail_imap_sect_learn_part(t0->list[i], *ptr);
	    if (r < 0) {
		rs = r;
		break;
	    } else {
		rs += r;
		if (r) endp = *ptr;
	    }
	    ptr = &(*ptr)->chain;
	}
	if (endp) {
	    VESmail_imap_msg_free(endp->chain);
	    endp->chain = NULL;
	    if (endp == msg->sections && lst->len >= 3) {
		VESmail_imap_token *t2 = VESmail_imap_token_getlist(lst->list[2]);
		if (t2) {
		    char kbuf[12];
		    for (i = 0; i < t2->len - 1; i += 2) {
			VESmail_imap_token *kv = t2->list[i + 1];
			if (!VESmail_imap_token_isAString(kv)) continue;
			VESmail_imap_token *kk = t2->list[i];
			if (kk->len < sizeof(kbuf) && VESmail_imap_token_cp_lcstr(kk, kbuf) && !strcmp(kbuf, "boundary")) {
			    char **injb;
			    for (injb = msg->server->optns->injected; *injb; injb++) {
				int l = strlen(*injb);
				if (l < kv->len && !strncmp(*injb, VESmail_imap_token_data(kv), l)) {
				    VESmail_imap_msg_free(endp);
				    msg->sections = NULL;
				    msg->flags |= VESMAIL_IMAP_MF_INJ;
				    break;
				}
			    }
			}
			if (msg->flags & VESMAIL_IMAP_MF_INJ) {
			    return VESmail_imap_sect_learn_part(t0->list[0], msg);
			}
		    }
		}
	    }
	} else {
	    VESmail_imap_msg_free(*ptr);
	    *ptr = NULL;
	}
    } else {
	char *mime = malloc(t0->len + t1->len + 2);
	rs = VESMAIL_E_PARAM;
	if (VESmail_imap_token_cp_lcstr(t0, mime)) {
	    char *d = mime + strlen(mime);
	    *d++ = '/';
	    if (VESmail_imap_token_cp_lcstr(t1, d)) {
		if (!strcmp(mime, "message/rfc822")) {
		    msg->flags |= VESMAIL_IMAP_MF_RFC822;
		    if (!msg->rfc822) msg->rfc822 = VESmail_imap_msg_new_part(msg);
		    if (lst->len >= 9 && VESmail_imap_token_isLSet(lst->list[8])) {
			rs = VESmail_imap_sect_learn_part(lst->list[8]->list[0], msg->rfc822);
		    } else {
			rs = VESMAIL_E_PARAM;
		    }
		} else {
		    rs = 0;
		    char **mimes;
		    for (mimes = msg->server->optns->mime; *mimes; mimes++) if (!strcmp(*mimes, mime)) {
			msg->flags |= VESMAIL_IMAP_MF_VES;
			rs = 1;
			break;
		    }
		}
	    }
	}
	free(mime);
    }
    if (msg->flags & VESMAIL_IMAP_MF_ROOT) {
	if (!rs) {
	    msg->flags |= VESMAIL_IMAP_MF_PASS;
	} else if (rs > 0) {
	    msg->flags |= VESMAIL_IMAP_MF_ENCD;
	}
    }
    return rs;
}

VESmail_imap_fetch *VESmail_imap_sect_regqry(VESmail_imap_fetch *fetch, VESmail_imap_msg *msg) {
    if (!msg || (msg->flags & VESMAIL_IMAP_MF_STRUCT)) return NULL;
    VESmail_imap_fetch *fq = VESmail_imap_fetch_new_body(fetch->type, fetch->mode, fetch->stype, fetch->seclen, fetch->section);
    fq->qchain = msg->queries;
    msg->queries = fq;
    return fetch;
}

void VESmail_imap_sect_resqry(VESmail_imap_fetch *fq, VESmail_imap_msg *msg) {
    VESmail_imap_fetch *next;
    for (; fq; fq = next) {
	next = fq->qchain;
	fq->qchain = NULL;
	VESmail_imap_msg *sect = VESmail_imap_msg_section(msg, fq->seclen, fq->section);
	if (fq->stype == VESMAIL_IMAP_FS_HEADER && sect && (sect->flags & VESMAIL_IMAP_MF_RFC822)) sect = sect->rfc822;
	if (sect) sect->flags |= VESMAIL_IMAP_MF_QHDR;
	VESmail_imap_fetch_free(fq);
    }
}

int VESmail_imap_sect_learn(VESmail_imap_token *st, VESmail_imap_msg *msg) {
    if (!VESmail_imap_token_isLSet(st) || st->len != 1) return VESMAIL_E_PARAM;
    VESmail_imap_fetch *fq = msg->queries;
    msg->queries = NULL;
    int rs = VESmail_imap_sect_learn_part(st->list[0], msg);
    VESmail_imap_sect_resqry(fq, msg);
    return rs;
}

void VESmail_imap_sect_hdr_escape(VESmail_imap_fetch *fetch, VESmail_imap_token *token) {
    char **hdr;
    int r_id = !fetch->seclen;
    VESmail_imap_token *flds = token->list[1]->list[1]->list[0];
    VESmail_imap_token **fp = flds->list;
    for (hdr = fetch->fields; *hdr; hdr++, fp++) {
	if (r_id) {
	    if (!strcmp(*hdr, "message-id")) {
		switch (fetch->stype) {
		    case VESMAIL_IMAP_FS_HEADER_FIELDS:
			r_id = 0;
			break;
		    case VESMAIL_IMAP_FS_HEADER_FIELDS_NOT:
			*fp = VESmail_imap_token_memsplice(*fp, 0, 0, "X-VESMAIL_B_");
		    default:
			break;
		}
		continue;
	    }
	}
	if (!strncmp(*hdr, "x-vesmail", 9)) {
	    *fp = VESmail_imap_token_memsplice(*fp, 9, 0, "_E_");
	}
    }
    switch (fetch->stype) {
	case VESMAIL_IMAP_FS_HEADER_FIELDS:
	    VESmail_imap_token_splice(flds, -1, 0, 2,
		VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, "X-VESMAIL-HEADER"),
		VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, "X-VESMAIL-ID")
	    );
	    if (r_id) {
		VESmail_imap_token_splice(flds, -1, 0, 2,
		    VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, "MESSAGE-ID"),
		    VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, "X-VESMAIL_D_MESSAGE-ID")
		);
	    }
	default:
	    break;
    }
}

void VESmail_imap_sect_memsplice(char **hdr, VESmail_imap_token **fp, int offs, int del, const char *ins) {
    unsigned long int l = strlen(*hdr) + 1;
    *hdr = VESmail_memsplice(*hdr, 0, &l, offs, del, ins, (ins ? strlen(ins) : 0));
    *fp = VESmail_imap_token_memsplice(*fp, offs, del, ins);
}

int VESmail_imap_sect_hdr_unescape(VESmail_imap_fetch *fetch, VESmail_imap_token *token, VESmail_imap_fetch **rngptr) {
    int rs = 0;
    char **hdr;
    VESmail_imap_token *flds = token->list[1]->list[1]->list[0];
    VESmail_imap_token **fp = flds->list;
    for (hdr = fetch->fields; *hdr; hdr++, fp++) {
	char *h = *hdr;
	if (!strncmp(h, "x-vesmail", 9)) {
	    if (h[9] == '_' && h[10] && h[11] == '_') switch (h[10]) {
		case 'd': {
		    char **hdr2;
		    VESmail_imap_token **fp2 = flds->list;
		    for (hdr2 = fetch->fields; *hdr2; hdr2++, fp2++) {
			if (hdr2 == hdr || !strcmp(h + 12, *hdr2)) {
			    VESmail_imap_token_free(*fp2);
			    *fp2 = NULL;
			}
		    }
		    continue;
		}
		case 'e':
		    VESmail_imap_sect_memsplice(hdr, fp, 9, 3, NULL);
		    continue;
		case 'b':
		    VESmail_imap_sect_memsplice(hdr, fp, 0, 12, NULL);
		    continue;
		case 'm': {
		    unsigned int rng1, rng2;
		    int r = sscanf(h + 12, "range_%u_%u", &rng1, &rng2);
		    if (r > 0 && rngptr) {
			const char *rhash = strchr(h + 18, '-');
			VESmail_imap_fetch *rng = VESmail_imap_fetch_new_rhash((r > 1 ? VESMAIL_IMAP_FM_RANGE : VESMAIL_IMAP_FM_START), (rhash ? rhash + 1 : ""));
			rng->range[0] = rng1;
			if (r > 1) rng->range[1] = rng2;
			unsigned long seed;
			RAND_bytes((void *) &seed, sizeof(seed));
			VESmail_imap_fetch **rp;
			int ct = 0;
			for (rp = rngptr; *rp; rp = &((*rp)->qchain)) ct++;
			ct = seed % (ct + 1);
			for (rp = rngptr; ct > 0; rp = &((*rp)->qchain)) ct--;
			VESmail_imap_fetch_queue(rp, rng);
			break;
		    }
		    if (!strcmp(h + 12, "recon")) rs = 1;
		    break;
		}
		default:
		    break;
	    }
	    VESmail_imap_token_free(*fp);
	    *fp = NULL;
	}
    }
    char **hdrd;
    VESmail_imap_token **fpd = fp = flds->list;
    for (hdrd = hdr = fetch->fields; *hdr; hdr++, fp++) {
	if (!*fp) {
	    free(*hdr);
	    continue;
	}
	*hdrd++ = *hdr;
	*fpd++ = *fp;
    }
    *hdrd = NULL;
    flds->len = fpd - flds->list;
    return rs;
}

int VESmail_imap_sect_hdr_skip(VESmail_imap_fetch *fetch, const char *hdr) {
    if (!fetch || !hdr || !*hdr || fetch->mode == VESMAIL_IMAP_FM_NONE) return 0;
    switch (fetch->stype) {
	case VESMAIL_IMAP_FS_HEADER_FIELDS:
	case VESMAIL_IMAP_FS_HEADER_FIELDS_NOT: {
	    char **hp;
	    for (hp = fetch->fields; *hp; hp++) if (!strcmp(*hp, hdr)) return (fetch->stype == VESMAIL_IMAP_FS_HEADER_FIELDS_NOT);
	    return (fetch->stype == VESMAIL_IMAP_FS_HEADER_FIELDS);
	}
	default:
	    break;
    }
    return 0;
}

int VESmail_imap_sect_traverse_part(VESmail_imap_msg *msg, VESmail_imap_fetch *fetch, int (* callbk)(void *, VESmail_imap_msg *, VESmail_imap_fetch *), void *arg) {
    int rs = callbk(arg, msg, fetch);
    if (rs < 0) return rs;
    if (msg->flags & VESMAIL_IMAP_MF_RFC822) msg = msg->rfc822;
    if (!msg->sections) return rs;
    VESmail_imap_msg *m;
    int secl = fetch->seclen;
    VESmail_imap_fetch *f = VESmail_imap_fetch_new_body(fetch->type, fetch->mode, fetch->stype, secl + 1, NULL);
    memcpy(f->section, fetch->section, secl * sizeof(*f->section));
    f->section[secl] = 0;
    for (m = msg->sections; m; m = m->chain) {
	f->section[fetch->seclen]++;
	int r = VESmail_imap_sect_traverse_part(m, f, callbk, arg);
	if (r < 0) {
	    rs = r;
	    break;
	}
	rs += r;
    }
    VESmail_imap_fetch_free(f);
    return rs;
}

int VESmail_imap_sect_traverse(VESmail_imap_msg *msg, int (* callbk)(void *, VESmail_imap_msg *, VESmail_imap_fetch *), void *arg) {
    VESmail_imap_fetch fetch = {
	.type = VESMAIL_IMAP_FV_BODY,
	.mode = VESMAIL_IMAP_FM_SECTION,
	.stype = VESMAIL_IMAP_FS_HEADER,
	.seclen = 0
    };
    return VESmail_imap_sect_traverse_part(msg, &fetch, callbk, arg);
}

int VESmail_imap_sect_render_params(void *ctparams, const char *key, const char *val) {
    VESmail_imap_token_splice(ctparams, -1, 0, 2, VESmail_imap_token_nstring(key), VESmail_imap_token_nstring(val));
    return 0;
}

/***************************************************************************
* Size estimate for an encrypted part whose body has not been decrypted yet
* (no MF_BODY). The octet count the upstream server reports is the base64
* ciphertext of the encrypted part, which inflates the size the client
* eventually sees. For an identity Content-Transfer-Encoding the decrypted
* output equals the plaintext verbatim, and since the encrypted part is always
* base64 (VESmail forces dstenc = B64 on encrypt), plaintext <= cipher / 1.368.
* So cipher * 0.76 is a guaranteed upper bound with a small cushion over the
* 0.731 limit -- it de-inflates the estimate without ever under-promising the
* literal (which would silently truncate). base64 and quoted-printable parts
* keep the pass-through ciphertext size: base64 output ~= ciphertext anyway,
* and QP is unbounded upward, so lowering it is the unsafe direction. Exact
* sizes still come from MF_BODY / F_CALC when those kick in.
***************************************************************************/
#define VESMAIL_IMAP_EST_IDENT_NUM	76
#define VESMAIL_IMAP_EST_IDENT_DEN	100

static int VESmail_imap_sect_ctenc_identity(const char *ctenc) {
    static const char *const idents[] = { "7bit", "8bit", "binary", NULL };
    const char *const *ip;
    for (ip = idents; *ip; ip++) {
	const char *s = ctenc, *lc = *ip;
	while (*lc) {
	    char c = *s++;
	    if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
	    if (c != *lc++) break;
	}
	if (!*lc && !*s) return 1;
    }
    return 0;
}

int VESmail_imap_sect_apply_part(VESmail_imap_token *token, VESmail_imap_msg *msg, int flags) {
    if (!VESmail_imap_token_isList(token) || token->len < 2 || !msg || !(msg->flags & VESMAIL_IMAP_MF_HDR)) return VESMAIL_E_UNKNOWN;
    VESmail_imap_token **lst = token->list;
    VESmail_imap_token *t0 = lst[0];
    if (VESmail_imap_token_isLSet(t0)) {
	if ((msg->flags & VESMAIL_IMAP_MF_INJ) && !(flags & VESMAIL_IMAP_MF_INJ)) {
	    VESmail_imap_token *itoken = t0->list[0];
	    int ilen = itoken->len;
	    VESmail_imap_token **ilist = itoken->list;
	    itoken->len = 0;
	    itoken->list = NULL;
	    VESmail_imap_token_splice(token, 0, token->len, 0);
	    token->len = ilen;
	    free(token->list);
	    token->list = ilist;
	    return VESmail_imap_sect_apply_part(token, msg, flags | VESMAIL_IMAP_MF_INJ);
	} else {
	    int lidx = 0;
	    VESmail_imap_msg *part = msg->sections;
	    while (part) {
		if (lidx >= t0->len) return VESMAIL_E_UNKNOWN;
		VESmail_imap_sect_apply_part(t0->list[lidx++], part, (flags & ~VESMAIL_IMAP_MF_INJ));
		part = part->chain;
	    }
	    if (lidx < t0->len) VESmail_imap_token_splice(t0, lidx, t0->len - lidx, 0);
	}
    } else if (msg->flags & VESMAIL_IMAP_MF_RFC822) {
	if (token->len < 10 || !VESmail_imap_token_isLSet(lst[8])) return VESMAIL_E_UNKNOWN;
	VESmail_imap_msg *part = msg->rfc822;
	VESmail_imap_sect_apply_part(lst[8]->list[0], part, (flags & ~VESMAIL_IMAP_MF_INJ));
	if (msg->flags & VESMAIL_IMAP_MF_BODY) {
	    VESmail_imap_token_splice(token, 6, 1, 1, VESmail_imap_token_uint(msg->bbytes));
	    VESmail_imap_token_splice(token, 9, 1, 1, VESmail_imap_token_uint(msg->lines));
	}
    } else if (msg->flags & VESMAIL_IMAP_MF_VES) {
	if (token->len < 7) return VESMAIL_E_UNKNOWN;
	VESmail_imap_token *ctparams = VESmail_imap_token_list(0);
	const char *ctype = VESmail_imap_msg_header(msg, VESMAIL_IMAP_H_CONTENT_TYPE, &VESmail_imap_sect_render_params, ctparams);
	const char *ct2;
	int ctl, ftxt;
	if (ctype) {
	    ct2 = strchr(ctype, '/');
	    if (!ct2 || ct2 == ctype || !*++ct2 || strchr(ct2, '/')) ctype = NULL;
	}
	if (ctype) {
	    ctl = ct2 - ctype - 1;
	    ftxt = (ctl == 4 && !strncmp(ctype, "text", 4)) ? 1 : 0;
	} else {
	    ctype = "text";
	    ctl = 4;
	    ct2 = "plain";
	    ftxt = 1;
	}
	const char *ctenc = VESmail_imap_msg_header(msg, VESMAIL_IMAP_H_CONTENT_TRANSFER_ENCODING, NULL, NULL);
	if (!ctenc || !*ctenc) ctenc = "7bit";
	VESmail_imap_token_splice(token, 0, 6, 6,
	    VESmail_imap_token_vall(VESMAIL_IMAP_T_QUOTED, ctype, ctl),
	    VESmail_imap_token_val(VESMAIL_IMAP_T_QUOTED, ct2),
	    VESmail_imap_token_nlist(ctparams),
	    VESmail_imap_token_nstring(VESmail_imap_msg_header(msg, VESMAIL_IMAP_H_CONTENT_ID, NULL, NULL)),
	    VESmail_imap_token_nstring(VESmail_imap_msg_header(msg, VESMAIL_IMAP_H_CONTENT_DESCRIPTION, NULL, NULL)),
	    VESmail_imap_token_nstring(ctenc)
	);
	if (msg->flags & VESMAIL_IMAP_MF_BODY) {
	    VESmail_imap_token_splice(token, 6, 1, 1, VESmail_imap_token_uint(msg->bbytes));
	} else if (VESmail_imap_sect_ctenc_identity(ctenc)) {
	    unsigned int oct;
	    if (VESmail_imap_token_getuint(token->list[6], &oct) >= 0) {
		VESmail_imap_token_splice(token, 6, 1, 1, VESmail_imap_token_uint(
		    (unsigned int) ((unsigned long long) oct * VESMAIL_IMAP_EST_IDENT_NUM / VESMAIL_IMAP_EST_IDENT_DEN)
		));
	    }
	}
	if (ftxt) {
	    unsigned int lines;
	    if (msg->flags & VESMAIL_IMAP_MF_BODY) {
		lines = msg->lines;
	    } else if (VESmail_imap_token_getuint(token->list[6], &lines) >= 0) {
		lines = lines / 48 + 1;
	    } else {
		lines = 0;
	    }
	    VESmail_imap_token_splice(token, 7, 0, 1, VESmail_imap_token_uint(lines));
	}
	if (token->len > 7 + ftxt) {
	    if (!VESmail_imap_token_isAtom(token->list[7 + ftxt])) {
		VESmail_imap_token_splice(token, 7 + ftxt, 1, 1, VESmail_imap_token_nstring(NULL));
	    }
	    VESmail_imap_token *cdparams = VESmail_imap_token_list(0);
	    const char *cdisp = VESmail_imap_msg_header(msg, VESMAIL_IMAP_H_CONTENT_DISPOSITION, &VESmail_imap_sect_render_params, cdparams);
	    VESmail_imap_token *cdtoken = VESmail_imap_token_list(0);
	    if (cdisp && *cdisp) {
		VESmail_imap_token_splice(cdtoken, 0, 0, 2,
		    VESmail_imap_token_nstring(cdisp),
		    VESmail_imap_token_nlist(cdparams)
		);
	    } else {
		VESmail_imap_token_free(cdparams);
	    }
	    VESmail_imap_token_splice(token, 8 + ftxt, 1, 1, VESmail_imap_token_nlist(cdtoken));
	}
    }
    return 0;
}

int VESmail_imap_sect_apply(VESmail_imap_token *token, VESmail_imap_msg *msg) {
    return VESmail_imap_sect_apply_part(token->list[0], msg, 0);
}
