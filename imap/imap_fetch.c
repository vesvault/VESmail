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
#include "imap_token.h"
#include "imap.h"
#include "imap_fetch.h"


#define VESMAIL_VERB(verb)		#verb,
#define VESMAIL_VERB2(verb, sub)	#verb "." #sub,

const char *VESmail_imap_fetch_verbs[] = { VESMAIL_IMAP_FETCH_VERBS() NULL };

#undef VESMAIL_VERB
#undef VESMAIL_VERB2

const char *VESmail_imap_fetch_stypes[] = {
    "TEXT", "MIME", "HEADER", "HEADER.FIELDS", "HEADER.FIELDS.NOT", NULL
};

VESmail_imap_fetch *VESmail_imap_fetch_new(char type) {
    VESmail_imap_fetch *fetch = malloc(offsetof(VESmail_imap_fetch, fields));
    fetch->mode = VESMAIL_IMAP_FM_NONE;
    fetch->type = type;
    return fetch;
}

VESmail_imap_fetch *VESmail_imap_fetch_new_body(char type, char mode, char stype, int seclen, unsigned long int *sec) {
    VESmail_imap_fetch *fetch = malloc(sizeof(VESmail_imap_fetch) + seclen * sizeof(fetch->section[0]));
    fetch->mode = mode;
    fetch->type = type;
    fetch->stype = stype;
    fetch->fields = NULL;
    fetch->seclen = seclen;
    if (seclen && sec) memcpy(fetch->section, sec, seclen * sizeof(*sec));
    return fetch;
}

const char *VESmail_imap_fetch_parse_num(const char *src, const char *tail, int *ctr, unsigned long int *dst) {
    const char *s = src;
    long long int num;
    int ct = 0;
    while (1) {
	if (s == src) {
	    if (ct && dst) *dst++ = num;
	    num = 0;
	}
	if (s >= tail) {
	    if (ct) {
		if (s == src) return NULL;
		if (dst) *dst = num;
	    }
	    break;
	}
	char c = *s;
	if (c == '.') {
	    if (s == src) return NULL;
	    src = ++s;
	} else if (c >= '0' && c <= '9') {
	    num = num * 10 + (c - '0');
	    if (src == s++) ct++;
	} else {
	    if (s > src) return NULL;
	    break;
	}
    }
    if (ctr) *ctr = ct;
    return s;
}

VESmail_imap_fetch *VESmail_imap_fetch_parse(VESmail_imap_token *key) {
    if (!key) return NULL;
    VESmail_imap_token *k;
    VESmail_imap_token *kidx;
    switch (key->type) {
	case VESMAIL_IMAP_T_ATOM:
	    k = key;
	    kidx = NULL;
	    break;
	case VESMAIL_IMAP_T_LSET:
	    if (key->len >= 2 && VESmail_imap_token_isIndex(key->list[1])) {
		k = key->list[0];
		kidx = key->list[1];
		break;
	    }
	default:
	    return NULL;
    }
    int v = VESmail_imap_get_verb(k, VESmail_imap_fetch_verbs);
    if (v < 0) return NULL;
    VESmail_imap_fetch *fetch;
    if (kidx) {
	switch (v) {
	    case VESMAIL_IMAP_FV_BODY:
	    case VESMAIL_IMAP_FV_BODY_PEEK: {
		const char *rngstr, *rngtail;
		int rngct;
		int m;
		if (key->len > 2) {
		    VESmail_imap_token *rng = key->list[2];
		    if (key->len > 3 || !VESmail_imap_token_isAtom(rng) || rng->len < 2) return NULL;
		    rngstr = VESmail_imap_token_data(rng);
		    if (*rngstr++ != '<') return NULL;
		    rngtail = VESmail_imap_fetch_parse_num(rngstr, rngstr + rng->len - 2, &rngct, NULL);
		    if (!rngtail || rngtail - rngstr != rng->len - 2 || *rngtail != '>') return NULL;
		    switch (rngct) {
			case 1:
			    m = VESMAIL_IMAP_FM_START;
			    break;
			case 2:
			    m = VESMAIL_IMAP_FM_RANGE;
			    break;
			default:
			    return NULL;
		    }
		} else {
		    rngstr = NULL;
		    rngct = 0;
		    m = VESMAIL_IMAP_FM_SECTION;
		}
		int idxct;
		int stype = VESMAIL_IMAP_FS_NONE;
		const char *idxstr, *idxtail;
		if (kidx->len > 0) {
		    VESmail_imap_token *kidx0 = kidx->list[0];
		    if (!VESmail_imap_token_isAtom(kidx0)) return NULL;
		    idxstr = VESmail_imap_token_data(kidx0);
		    idxtail = VESmail_imap_fetch_parse_num(idxstr, idxstr + kidx0->len, &idxct, NULL);
		    if (!idxtail) return NULL;
		    struct {
			VESmail_imap_token t;
			char d[32];
		    } tt;
		    tt.t.len = kidx0->len - (idxtail - idxstr);
		    if (tt.t.len > 0) {
			if (tt.t.len > sizeof(tt.d)) return NULL;
			tt.t.type = VESMAIL_IMAP_T_ATOM;
			memcpy(tt.t.data, idxtail, tt.t.len);
			stype = VESmail_imap_get_verb(&tt.t, VESmail_imap_fetch_stypes);
			if (stype < 0) return NULL;
		    }
		} else {
		    idxstr = NULL;
		    idxct = 0;
		}
		char **flds;
		switch (stype) {
		    case VESMAIL_IMAP_FS_HEADER_FIELDS:
		    case VESMAIL_IMAP_FS_HEADER_FIELDS_NOT: {
			if (kidx->len != 2 || !VESmail_imap_token_isLSet(kidx->list[1]) || kidx->list[1]->len != 1) return NULL;
			VESmail_imap_token *lst = kidx->list[1]->list[0];
			if (!VESmail_imap_token_isList(lst) || lst->len > VESMAIL_IMAP_FETCH_FLD_SAFENUM) return NULL;
			int i;
			for (i = 0; i < lst->len; i++) if (!VESmail_imap_token_isAString(lst->list[i]) || lst->list[i]->len > VESMAIL_IMAP_FETCH_FLD_SAFELEN) return NULL;
			flds = malloc((lst->len + 1) * sizeof(*flds));
			for (i = 0; i < lst->len; i++) flds[i] = VESmail_imap_token_cp_lcstr(lst->list[i], NULL);
			flds[i] = NULL;
			break;
		    }
		    default: {
			if (kidx->len > 1) return NULL;
			flds = NULL;
			break;
		    }
		}
		fetch = VESmail_imap_fetch_new_body(v, m, stype, idxct, NULL);
		fetch->fields = flds;
		if (idxstr) VESmail_imap_fetch_parse_num(idxstr, idxtail, NULL, fetch->section);
		if (rngstr) VESmail_imap_fetch_parse_num(rngstr, rngtail, NULL, fetch->range);
		break;
	    }
	    default:
		return NULL;
	}
    } else {
	if (v == VESMAIL_IMAP_FV_BODY_PEEK) return NULL;
	fetch = VESmail_imap_fetch_new(v);
    }
    return fetch;
}

VESmail_imap_token *VESmail_imap_fetch_render_idx(VESmail_imap_fetch *fetch, int offs, int idx) {
    const char *s;
    int l;
    char buf[16];
    if (idx >= fetch->seclen) {
	s = VESmail_imap_fetch_stypes[fetch->stype];
    } else {
	sprintf(buf, "%lu", fetch->section[idx]);
	s = buf;
    }
    if (s) {
	l = strlen(s);
	if (offs > 0) offs++;
    } else {
	l = 0;
    }
    VESmail_imap_token *tk;
    if (s == buf) {
	tk = VESmail_imap_fetch_render_idx(fetch, offs + l, idx + 1);
    } else {
	tk = VESmail_imap_token_new(VESMAIL_IMAP_T_ATOM, offs + l);
	tk->len = offs + l;
    }
    char *d = VESmail_imap_token_data(tk) + offs;
    if (l) {
	if (offs > 1) d[-1] = '.';
	memcpy(d, s, l);
    }
    return tk;
}

VESmail_imap_token *VESmail_imap_fetch_render(VESmail_imap_fetch *fetch) {
    VESmail_imap_token *tk = VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, VESmail_imap_fetch_verbs[fetch->type]);
    const char *rg;
    switch (fetch->mode) {
	case VESMAIL_IMAP_FM_START:
	    rg = "<%lu>";
	    break;
	case VESMAIL_IMAP_FM_RANGE:
	    rg = "<%lu.%lu>";
	    break;
	case VESMAIL_IMAP_FM_SECTION:
	    rg = NULL;
	    break;
	default:
	    return tk;
    }
    VESmail_imap_token *lst = VESmail_imap_token_new(VESMAIL_IMAP_T_LSET, 0);
    VESmail_imap_token *idx = VESmail_imap_token_splice(VESmail_imap_token_new(VESMAIL_IMAP_T_INDEX, 0), 0, 0, 1, VESmail_imap_fetch_render_idx(fetch, 0, 0));
    switch (fetch->stype) {
	case VESMAIL_IMAP_FS_HEADER_FIELDS:
	case VESMAIL_IMAP_FS_HEADER_FIELDS_NOT: {
	    VESmail_imap_token *flds = VESmail_imap_token_new(VESMAIL_IMAP_T_LIST, 0);
	    char **f;
	    for (f = fetch->fields; *f; f++) VESmail_imap_token_splice(flds, -1, 0, 1, VESmail_imap_token_astring(*f));
	    VESmail_imap_token_splice(idx, 1, 0, 1, VESmail_imap_token_splice(VESmail_imap_token_new(VESMAIL_IMAP_T_LSET, 0), 0, 0, 1, flds));
	}
	default:
	    break;
    }
    VESmail_imap_token_splice(lst, 0, 0, 2, tk, idx);
    if (rg) {
	char rgstr[64];
	sprintf(rgstr, rg, fetch->range[0], fetch->range[1]);
	VESmail_imap_token_splice(lst, 2, 0, 1, VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, rgstr));
    }
    return lst;
}

// The following functions pertain to Range Hash operations
// Not a cryptographic hash, used to identify range tokens in a FETCH response
char *VESmail_imap_fetch_rhash(VESmail_imap_fetch *f, char *dst) {
    const unsigned long seed = 0x6b3b6549;
    unsigned long h = f->stype * seed;
    int i;
    for (i = 0; i < f->seclen; i++) h = (h ^ f->section[i]) * seed;
    sprintf(dst, "%08lX", h & 0xffffffff);
    return dst;
}

VESmail_imap_fetch *VESmail_imap_fetch_new_rhash(int mode, const char *rhash) {
    VESmail_imap_fetch *fetch = malloc(sizeof(VESmail_imap_fetch) + strlen(rhash) + 1);
    fetch->mode = mode;
    fetch->type = VESMAIL_IMAP_FV_BODY;
    fetch->stype = VESMAIL_IMAP_FS_NONE;
    fetch->qchain = NULL;
    fetch->seclen = 0;
    char c;
    char *d = fetch->rhash;
    while ((c = *rhash++)) {
	*d++ = (c >= 'a' && c <= 'f') ? c - 0x20 : c;
    }
    *d = 0;
    return fetch;
}

int VESmail_imap_fetch_check_rhash(VESmail_imap_fetch *fetch, const char *rhash) {
    char c;
    const char *s = fetch->rhash;
    while ((c = *s++)) {
	if (c != *rhash++) return 0;
    }
    return 1;
}

VESmail_imap_fetch **VESmail_imap_fetch_queue(VESmail_imap_fetch **queue, VESmail_imap_fetch *fetch) {
    while (*queue) queue = &(*queue)->qchain;
    *queue = fetch;
    return &fetch->qchain;
}

VESmail_imap_fetch *VESmail_imap_fetch_unqueue(VESmail_imap_fetch **queue) {
    VESmail_imap_fetch *fetch = *queue;
    *queue = fetch->qchain;
    fetch->qchain = NULL;
    return fetch;
}


void VESmail_imap_fetch_free(VESmail_imap_fetch *fetch) {
    if (fetch) {
	switch (fetch->mode) {
	    case VESMAIL_IMAP_FM_NONE:
		break;
	    default: {
		char **p = fetch->fields;
		if (p) {
		    while (*p) free(*p++);
		    free(fetch->fields);
		}
		break;
	    }
	}
	free(fetch);
    }
}
