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
#include <stdarg.h>
#include <stdio.h>
#include "../VESmail.h"
#include "../lib/xform.h"
#include "../lib/parse.h"
#include "../lib/util.h"
#include "imap_token.h"


VESmail_imap_token *VESmail_imap_token_new(int type, unsigned int len) {
    VESmail_imap_token *token;
    switch (type) {
	case VESMAIL_IMAP_T_ATOM:
	case VESMAIL_IMAP_T_QUOTED: {
	    token = malloc(offsetof(VESmail_imap_token, data) + len);
	    break;
	}
	case VESMAIL_IMAP_T_LITERAL: {
	    token = malloc(sizeof(VESmail_imap_token));
	    token->literal = NULL;
	    token->xform = NULL;
	    break;
	}
	default: {
	    token = malloc(sizeof(VESmail_imap_token));
	    token->list = NULL;
	    token->parent = NULL;
	}
    }
    token->type = type;
    token->state = VESMAIL_IMAP_P_INIT;
    token->flags = VESMAIL_IMAP_PF_INIT;
    token->len = 0;
    return token;
}

VESmail_imap_token *VESmail_imap_token_clone(VESmail_imap_token *orig) {
    if (!orig) return NULL;
    VESmail_imap_token *token;
    switch (orig->type) {
	case VESMAIL_IMAP_T_ATOM:
	case VESMAIL_IMAP_T_QUOTED: {
	    int l;
	    token = malloc((l = offsetof(VESmail_imap_token, data) + orig->len));
	    memcpy(token, orig, l);
	    break;
	}
	case VESMAIL_IMAP_T_LITERAL: {
	    token = malloc(sizeof(VESmail_imap_token));
	    memcpy(token, orig, offsetof(VESmail_imap_token, literal));
	    if (orig->literal) {
		memcpy((token->literal = malloc(orig->len)), orig->literal, orig->len);
	    } else {
		token->literal = NULL;
	    }
	    token->xform = NULL;
	    break;
	}
	default: {
	    token = malloc(sizeof(VESmail_imap_token));
	    memcpy(token, orig, offsetof(VESmail_imap_token, len));
	    token->len = 0;
	    token->list = NULL;
	    int i;
	    for (i = 0; i < orig->len; i++) VESmail_imap_token_push(token, VESmail_imap_token_clone(orig->list[i]));
	    token->hold = NULL;
	    break;
	}
    }
    return token;
}

VESmail_imap_token *VESmail_imap_token_putc(VESmail_imap_token *token, char c) {
    token->data[token->len++] = c;
    return token;
}

VESmail_imap_token *VESmail_imap_token_splice(VESmail_imap_token *list, int offs, int dlen, int ilen, ...) {
    int l = (list->len - dlen + ilen) & ~0x0f;
    if (!list->list || l > (list->len & ~0x0f)) list->list = realloc(list->list, (l + 16) * sizeof(*(list->list)));
    if (offs < 0) offs += list->len + 1;
    if (offs + dlen > list->len) dlen = list->len - offs;
    int i;
    for (i = 0; i < dlen; i++) VESmail_imap_token_free(list->list[offs + i]);
    int mvl = list->len - offs - dlen;
    int dl = ilen - dlen;
    if (mvl > 0 && dl != 0) memmove(list->list + offs + ilen, list->list + offs + dlen, mvl * sizeof(*(list->list)));
    list->len += dl;
    if (ilen > 0) {
	va_list va;
	va_start(va, ilen);
	for (i = 0; i < ilen; i++) {
	    VESmail_imap_token *t = list->list[offs + i] = va_arg(va, VESmail_imap_token *);
	    if (t && t->type < VESMAIL_IMAP_T_LITERAL) t->parent = list;
	}
	va_end(va);
    }
    return list;
}

struct VESmail_imap_token *VESmail_imap_token_push(struct VESmail_imap_token *list, struct VESmail_imap_token *token) {
    VESmail_imap_token_splice(list, -1, 0, 1, token);
    return token;
}

VESmail_imap_token *VESmail_imap_token_vall(int type, const char *str, int len) {
    VESmail_imap_token *token = VESmail_imap_token_new(type, len);
    memcpy((type == VESMAIL_IMAP_T_LITERAL ? (token->literal = malloc(len)) : token->data), str, (token->len = len));
    return token;
}

VESmail_imap_token *VESmail_imap_token_val(int type, const char *str) {
    return VESmail_imap_token_vall(type, str, strlen(str));
}

struct VESmail_imap_token *VESmail_imap_token_astringl(const char *str, int len) {
    int t = VESMAIL_IMAP_T_ATOM;
    int i;
    for (i = 0; i < len; i++) {
	unsigned char c = str[i];
	if (c < 0x20) {
	    t = VESMAIL_IMAP_T_LITERAL;
	    break;
	}
	if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == '-' || c == '.' || c == '@') continue;
	t = VESMAIL_IMAP_T_QUOTED;
    }
    return VESmail_imap_token_vall(t, str, len);
}

struct VESmail_imap_token *VESmail_imap_token_nstring(const char *str) {
    return str ? VESmail_imap_token_val(VESMAIL_IMAP_T_QUOTED, str) : VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, "NIL");
}

struct VESmail_imap_token *VESmail_imap_token_nlist(VESmail_imap_token *token) {
    if (token) switch (token->type) {
	case VESMAIL_IMAP_T_LSET:
	    if (token->len) return token;
	    break;
	case VESMAIL_IMAP_T_LIST:
	case VESMAIL_IMAP_T_INDEX:
	    if (token->len) return VESmail_imap_token_splice(VESmail_imap_token_new(VESMAIL_IMAP_T_LSET, 0), 0, 0, 1, token);
	default:
	    break;
    }
    VESmail_imap_token_free(token);
    return VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, "NIL");
}

VESmail_imap_token *VESmail_imap_token_uint(unsigned int val) {
    char str[16];
    sprintf(str, "%u", val);
    return VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, str);
}

char *VESmail_imap_token_data(VESmail_imap_token *token) {
    switch (token->type) {
	case VESMAIL_IMAP_T_LITERAL:
	    if (!token->literal) token->literal = malloc(token->len);
	    return token->literal;
	case VESMAIL_IMAP_T_ATOM:
	case VESMAIL_IMAP_T_QUOTED:
	    return token->data;
	default:
	    return NULL;
    }
}

int VESmail_imap_token_fn_pass(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return *srclen = 0;
    return VESmail_xform_process(xform->chain, 0, src, *srclen);
}

int VESmail_imap_token_render(VESmail_imap_token *token, VESmail_xform *xform, VESmail_imap_token **hold) {
    int rs = 0;
    const char *l1, *l2, *l3;
    switch (token->type) {
	case VESMAIL_IMAP_T_ATOM: {
	    if (hold && *hold) return rs;
	    if (token->len > 0) {
		int r = VESmail_xform_process(xform, 0, token->data, token->len);
		if (r < 0) return r;
		rs += r;
	    }
	    return rs;
	}
	case VESMAIL_IMAP_T_QUOTED: {
	    if (hold && *hold) return rs;
	    char buf[1024];
	    const char *s = token->data;
	    const char *tail = s + token->len;
	    char *d = buf;
	    *d++ = '"';
	    while (s < tail) {
		char c = *s++;
		switch (c) {
		    case '"': case '\\': *d++ = '\\';
		    default: break;
		}
		*d++ = c;
		if (d > buf + sizeof(buf) - 4) {
		    int r = VESmail_xform_process(xform, 0, buf, d - buf);
		    if (r < 0) return r;
		    rs += r;
		    d = buf;
		}
	    }
	    *d++ = '"';
	    int r = VESmail_xform_process(xform, 0, buf, d - buf);
	    if (r < 0) return r;
	    rs += r;
	    return rs;
	}
	case VESMAIL_IMAP_T_LITERAL: {
	    if (!hold || !*hold) {
		char buf[32];
		sprintf(buf, "{%lu}\r\n", token->len);
		int r = VESmail_xform_process(xform, 0, buf, strlen(buf));
		if (r < 0) return r;
		rs += r;
		if (hold) {
		    *hold = token;
		    if (!token->literal && !token->xform) token->xform = VESmail_xform_new(&VESmail_imap_token_fn_pass, xform, NULL);
		    return rs;
		}
	    }
	    if (!hold || *hold == token) {
		if (hold) *hold = NULL;
		if (token->literal) {
		    int r = VESmail_xform_process(xform, 0, token->literal, token->len);
		    if (r < 0) return r;
		    rs += r;
		}
	    }
	    return rs;
	}
	case VESMAIL_IMAP_T_LINE:
	    l1 = NULL;
	    l2 = " ";
	    l3 = "\r\n";
	    break;
	case VESMAIL_IMAP_T_LSET:
	    l1 = NULL;
	    l2 = NULL;
	    l3 = NULL;
	    break;
	case VESMAIL_IMAP_T_LIST:
	    l1 = "(";
	    l2 = " ";
	    l3 = ")";
	    break;
	case VESMAIL_IMAP_T_INDEX:
	    l1 = "[";
	    l2 = " ";
	    l3 = "]";
	    break;
	default:
	    return VESMAIL_E_PARAM;
    }
    int r;
    if (l1 && (!hold || !*hold)) {
	r = VESmail_xform_process(xform, 0, l1, strlen(l1));
	if (r < 0) return r;
	rs += r;
    }
    int i;
    for (i = 0; i < token->len; i++) {
	if (l2 && i > 0 && (!hold || !*hold)) {
	    r = VESmail_xform_process(xform, 0, l2, strlen(l2));
	    if (r < 0) return r;
	    rs += r;
	}
	r = VESmail_imap_token_render(token->list[i], xform, hold);
	if (r < 0) return r;
	rs += r;
    }
    if (l3 && (!hold || !*hold)) {
	r = VESmail_xform_process(xform, 0, l3, strlen(l3));
	if (r < 0) return r;
	rs += r;
    }
    return rs;
}

int VESmail_imap_token_getuint(VESmail_imap_token *token, unsigned int *rs) {
    if (!VESmail_imap_token_isAtom(token) || token->len < 1 || token->len > 10) return VESMAIL_E_PARAM;
    char fmt[8];
    sprintf(fmt, "%%%ldu", token->len);
    if (sscanf(VESmail_imap_token_data(token), fmt, rs) < 1) return VESMAIL_E_PARAM;
    return 0;
}

char *VESmail_imap_token_cp_lcstr(VESmail_imap_token *token, char *dst) {
    const char *s = VESmail_imap_token_data(token);
    if (!s) return NULL;
    if (!dst) dst = malloc(token->len + 1);
    char *d = dst;
    const char *tail = s + token->len;
    while (s < tail) {
	char c = *s++;
	*d++ = (c >= 'A' && c <= 'Z') ? c + 0x20 : c;
    }
    *d = 0;
    return dst;
}

VESmail_imap_token *VESmail_imap_token_getlist(VESmail_imap_token *token) {
    if (token) switch (token->type) {
	case VESMAIL_IMAP_T_LIST:
	    return token;
	case VESMAIL_IMAP_T_LSET:
	    if (token->len == 1 && VESmail_imap_token_isList(token->list[0])) return token->list[0];
	default:
	    break;
    }
    return NULL;
}

int VESmail_imap_token_xform_fn(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    if (xform->chain) {
	int l = *srclen;
	unsigned long rm = xform->imapToken->len;
	if (xform->offset < 0) {
	    if (xform->offset + l <= 0) {
		xform->offset += l;
		l = 0;
	    } else {
		l += xform->offset;
		src -= xform->offset;
		xform->offset = 0;
	    }
	} else {
	    rm -= xform->offset;
	}
	if (l > rm) l = rm;
	rm -= l;
	xform->offset += l;
	int rs = VESmail_xform_process(xform->chain, 0, src, l);
	if (rs < 0) return rs;
	if (final) while (rm) {
	    const char *pad = "                                                                              \r\n";
	    const int l0 = strlen(pad);
	    int l = l0;
	    if (l > rm) l = rm;
	    rm -= l;
	    int r = VESmail_xform_process(xform->chain, 0, pad + l0 - l, l);
	    if (r < 0) return r;
	    rs += r;
	}
	return rs;
    }
    if (final) {
	free(xform->imapToken->literal);
	int r;
	if (src == xform->buf) {
	    r = VESmail_xform_capture_buf(xform, &xform->imapToken->literal);
	    if (r < 0) return r;
	} else {
	    memcpy((xform->imapToken->literal = malloc(r = *srclen)), src, *srclen);
	}
	return xform->imapToken->len = r;
    } else {
	return *srclen = 0;
    }
}

VESmail_xform *VESmail_imap_token_xform_new(VESmail_imap_token *token) {
    if (!token) return NULL;
    VESmail_xform *xform = VESmail_xform_new(&VESmail_imap_token_xform_fn, NULL, NULL);
    xform->imapToken = token;
    return xform;
}

int VESmail_imap_token_xform_apply(VESmail_imap_token *token, VESmail_xform *xform) {
    if (token) switch (token->type) {
	case VESMAIL_IMAP_T_LITERAL: {
	    if (token->literal) {
		int r = VESmail_xform_process(xform, 1, token->literal, token->len);
		VESmail_xform_free(xform);
		return r;
	    } else if (!token->xform) {
		token->xform = xform;
		return 0;
	    }
	    break;
	}
	default:
	    break;
    }
    VESmail_xform_free(xform);
    return VESMAIL_E_PARAM;
}

int VESmail_imap_token_eq(VESmail_imap_token *a, VESmail_imap_token *b) {
    if (a == b) return 1;
    if (!a || !b) return 0;
    if (a->type != b->type || a->len != b->len) return 0;
    if (a->type >= VESMAIL_IMAP_T_LITERAL) return !memcmp(VESmail_imap_token_data(a), VESmail_imap_token_data(b), a->len);
    int i;
    for (i = 0; i < a->len; i++) {
	if (!VESmail_imap_token_eq(a->list[i], b->list[i])) return 0;
    }
    return 1;
}

VESmail_imap_token *VESmail_imap_token_memsplice(VESmail_imap_token *token, int offs, int del, const char *ins) {
    int insl = ins ? strlen(ins) : 0;
    if (token) switch (token->type) {
	case VESMAIL_IMAP_T_ATOM:
	case VESMAIL_IMAP_T_QUOTED:
	    token = (VESmail_imap_token *) VESmail_memsplice((char *) token, offsetof(VESmail_imap_token, data), &token->len, offs, del, ins, insl);
	    break;
	case VESMAIL_IMAP_T_LITERAL:
	    if (token->literal) token->literal = VESmail_memsplice(token->literal, 0, &token->len, offs, del, ins, insl);
	default:
	    break;
    }
    return token;
}

int VESmail_imap_token_error(VESmail_imap_token *token) {
    if (!token) return VESMAIL_E_PARAM;
    if (VESmail_imap_token_isLiteral(token) && token->xform) return token->xform->eof;
    else if (VESmail_imap_token_hasList(token)) {
	int i;
	for (i = 0; i < token->len; i++) {
	    int r = VESmail_imap_token_error(token->list[i]);
	    if (r < 0) return r;
	}
    }
    if (token->state == VESMAIL_IMAP_P_ERROR) return VESMAIL_E_UNKNOWN;
    return 0;
}

long long int VESmail_imap_token_chkbytes(VESmail_imap_token *token) {
    if (!token) return 0;
    long long int rs = 64;
    if (token->type < VESMAIL_IMAP_T_LITERAL) {
	int i;
	for (i = 0; i < token->len; i++) rs += VESmail_imap_token_chkbytes(token->list[i]);
    } else if (token->type > VESMAIL_IMAP_T_LITERAL || token->literal) {
	rs += token->len;
    }
    return rs;
}


void VESmail_imap_token_free(VESmail_imap_token *token) {
    if (token) {
	switch (token->type) {
	    case VESMAIL_IMAP_T_ATOM:
	    case VESMAIL_IMAP_T_QUOTED:
		VESmail_cleanse(token->data, token->len);
		break;
	    case VESMAIL_IMAP_T_LITERAL: {
		VESmail_cleanse(token->literal, token->len);
		free(token->literal);
		VESmail_xform_free(token->xform);
		break;
	    }
	    default: {
		int i;
		for (i = 0; i < token->len; i++) VESmail_imap_token_free(token->list[i]);
		free(token->list);
		break;
	    }
	}
    }
    free(token);
}
