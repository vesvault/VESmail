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
#include <libVES/Cipher.h>
#include "../VESmail.h"
#include "mail.h"
#include "parse.h"
#include "xform.h"
#include "util.h"
#include "banner.h"
#include "optns.h"
#include "header.h"


struct VESmail_header *VESmail_header_new(const char *key, int type, int len) {
    int l = strchr(key, ':') - key + 1;
    VESmail_header *hdr = malloc(sizeof(VESmail_header) + len + l + 4);
    hdr->type = type;
    hdr->key = hdr->data;
    memcpy(hdr->data, key, l);
    hdr->data[l] = ' ';
    hdr->len = l + 1;
    hdr->val = hdr->key + hdr->len;
    return hdr;
}

struct VESmail_header *VESmail_header_dup(struct VESmail_header *hdr, struct VESmail_header *chain) {
    VESmail_header *h = malloc(sizeof(VESmail_header) + hdr->len);
    memcpy((char *)(h->key = h->data), hdr->key, hdr->len);
    h->len = hdr->len;
    h->val = hdr->val ? hdr->val - hdr->key + h->key : NULL;
    h->chain = NULL;
    h->type = hdr->type;
    VESmail_header **hp;
    for (hp = &chain; *hp; hp = &(*hp)->chain);
    *hp = h;
    return chain;
}

char *VESmail_header_apply_msgid(VESmail_header *hdr, VESmail *mail) {
    const char *tail = hdr->key + hdr->len;
    const char *s = hdr->val;
    char *msgid = NULL;
    char *d = NULL;
    while (s < tail) {
	char c = *s++;
	switch (c) {
	    case '<':
		if (!msgid) msgid = malloc(tail - s);
		d = msgid;
		break;
	    case ' ': case 9:
		break;
	    case '>': {
		*d = 0;
		if (!(mail->flags & VESMAIL_F_PASS)) {
		    if (hdr->type == VESMAIL_H_VESID) {
			mail->flags |= VESMAIL_F_ENCD;
		    } else {
			const char *suff = mail->optns->idSuffix;
			char *s = msgid + strlen(msgid) - strlen(suff);
			if (s > msgid && !strcmp(s, suff)) {
			    mail->flags |= VESMAIL_F_ENCD;
			    *s = 0;
			}
		    }
		}
		free(mail->msgid);
		return mail->msgid = msgid;
	    }
	    default:
		if (d) *d++ = c;
		break;
	}
    }
    free(msgid);
    return NULL;
}

void VESmail_header_cb_boundary(void *parse, const char *key, const char *val) {
    if (!strcmp(key, "boundary")) VESmail_parse_set_boundary((VESmail_parse *) parse, val);
}

int VESmail_header_keys_values(const char *str, int len, void (* cb)(void *arg, const char *key, const char *val), void *arg) {
    const char *s = str;
    const char *tail = str + len;
    char *buf = malloc(len);
    char *d = buf;
    char *val = NULL;
    int ct = 0;
    char q = 0;
    while (s < tail) {
	char c = *s++;
	if (c == '\\') {
	    *d++ = c;
	    if (s >= tail) break;
	    c = *s++;
	}
	if (q) {
	    if (c == q) q = 0;
	    else *d++ = c;
	} else switch (c) {
	    case ' ': case 9: case 10: case 13:
		break;
	    case '\'': case '"':
		q = c;
		break;
	    case ';': case ',':
		if (d > buf) {
		    *d = 0;
		    if (cb) cb(arg, buf, val);
		    d = buf;
		    val = NULL;
		    ct++;
		}
		break;
	    case '=':
		*d++ = 0;
		val = d;
		break;
	    default:
		*d++ = (!val && c >= 'A' && c <= 'Z') ? c + 0x20 : c;
		break;
	}
    }
    if (d > buf) {
	*d = 0;
	if (cb) cb(arg, buf, val);
	ct++;
    }
    free(buf);
    return ct;
}

char *VESmail_header_get_val(const VESmail_header *hdr, char *val, const char **extra) {
    const char *s = hdr->val;
    const char *tail = hdr->key + hdr->len;
    if (!val) val = malloc(tail - s);
    char *d = val;
    while (s < tail) {
	char c = *s++;
	switch (c) {
	    case ' ': case 9: case 10: case 13:
		break;
	    case ';':
		if (extra) *extra = s;
		s = tail;
		break;
	    default:
		*d++ = (c >= 'A' && c <= 'Z') ? c + 0x20 : c;
		break;
	}
    }
    *d = 0;
    return val;
}

int VESmail_header_get_ctenc(const char *ctenc) {
    if (ctenc) {
	if (!strcmp(ctenc, "base64")) {
	    return VESMAIL_CTE_B64;
	} else if (!strcmp(ctenc, "quoted-printable")) {
	    return VESMAIL_CTE_QP;
	} else {
	    return VESMAIL_CTE_BIN;
	}
    }
    return VESMAIL_CTE_UNDEF;
}

int VESmail_header_get_ctype(const char *ctype, VESmail_parse *parse) {
    if (ctype) {
	if (!strncmp(ctype, "multipart/", 10)) {
	    if (!strcmp(ctype + 10, "alternative")) return VESMAIL_T_ALT;
	    else return VESMAIL_T_MULTI;
	} else if (!strcmp(ctype, "message/rfc822")) {
	    return VESMAIL_T_MSG;
	} else {
	    if (parse) {
		char **m;
		for (m = parse->mail->optns->mime; *m; m++) if (!strcmp(ctype, *m)) return VESMAIL_T_VES;
	    }
	    return VESMAIL_T_OTHER;
	}
    }
    return VESMAIL_T_UNDEF;
}

const char *VESmail_header_get_eol(const VESmail_header *hdr) {
    const char *eol = hdr->key + hdr->len;
    if (eol > hdr->key && eol[-1] == '\n') eol--;
    if (eol > hdr->key && eol[-1] == '\r') eol--;
    return eol;
}

VESmail_header *VESmail_header_add_val(VESmail_header *hdr, int len, const char *val) {
    memcpy(hdr->data + hdr->len, val, len);
    hdr->len += len;
    return hdr;
}

VESmail_header *VESmail_header_add_eol(VESmail_header *hdr, const VESmail_header *src) {
    if (src) {
	const char *eol = VESmail_header_get_eol(src);
	return VESmail_header_add_val(hdr, src->key - eol + src->len, eol);
    } else return VESmail_header_add_val(hdr, 2, "\r\n");
}

int VESmail_header_chkbytes(VESmail_header *hdr) {
    int rs = 0;
    for (; hdr; hdr = hdr->chain) rs += 64 + hdr->len;
    return rs;
}

int VESmail_header_push(VESmail_parse *parse, VESmail_header *hdr, int (* pushfn)(VESmail_parse *, VESmail_header *, int)) {
    int rs = 0;
    while (parse->hdrbuf) {
	int r = pushfn(parse, parse->hdrbuf, 1);
	if (r < 0) {
	    if (r == VESMAIL_E_HOLD) break;
	    return r;
	}
	rs += r;
	VESmail_header *next = parse->hdrbuf->chain;
	VESmail_header_free(parse->hdrbuf);
	parse->hdrbuf = next;
    }
    if (!parse->hdrbuf) {
	int r = pushfn(parse, hdr, 0);
	if (r >= 0) return rs + r;
	if (r != VESMAIL_E_HOLD) return r;
    }
    if (VESmail_header_chkbytes(parse->hdrbuf) + hdr->len > VESMAIL_HEADER_SAFEBYTES) return VESMAIL_E_BUF;
    parse->hdrbuf = VESmail_header_dup(hdr, parse->hdrbuf);
    return rs;
}

int VESmail_header_collect(struct VESmail_parse *parse, struct VESmail_header *hdr) {
    int t = hdr->type;
    switch (t) {
	case VESMAIL_H_MSGID:
	    if (parse->mail->msgid) break;
	case VESMAIL_H_VESID:
	    VESmail_header_apply_msgid(hdr, parse->mail);
	    break;
	case VESMAIL_H_CTYPE:
	    if (parse->ctype == VESMAIL_T_UNDEF) {
		const char *extra;
		char *ctype = VESmail_header_get_val(hdr, NULL, &extra);
		parse->ctype = VESmail_header_get_ctype(ctype, parse);
		switch (parse->ctype) {
		    case VESMAIL_T_UNDEF:
			parse->error |= VESMAIL_PE_HDR_INV;
			break;
		    case VESMAIL_T_ALT:
		    case VESMAIL_T_MULTI:
			VESmail_header_keys_values(extra, hdr->key - extra + hdr->len, &VESmail_header_cb_boundary, parse);
		    default:
			break;
		}
		free(ctype);
	    } else parse->error |= VESMAIL_PE_HDR_DUP;
	    break;
	case VESMAIL_H_CTENC:
	    if (parse->ctenc == VESMAIL_CTE_UNDEF) {
		char *ctenc = VESmail_header_get_val(hdr, NULL, NULL);
		parse->ctenc = VESmail_header_get_ctenc(ctenc);
		if (parse->ctenc == VESMAIL_CTE_UNDEF) parse->error |= VESMAIL_PE_HDR_INV;
		free(ctenc);
	    } else parse->error |= VESMAIL_PE_HDR_DUP;
	    break;
	case VESMAIL_H_BLANK:
	    if (parse->ctype == VESMAIL_T_UNDEF) parse->ctype = VESMAIL_T_OTHER;
	    if (parse->ctenc == VESMAIL_CTE_UNDEF) parse->ctenc = VESMAIL_CTE_BIN;
	    break;
	default:
	    break;
    }
    return 0;
}

int VESmail_header_output(VESmail_parse *parse, VESmail_header *hdr) {
    return VESmail_xform_process(parse->xform, 0, hdr->key, hdr->len);
}

int VESmail_header_commit(VESmail_parse *parse, VESmail_header *hdr) {
    return parse->outfn(parse, hdr);
}

int VESmail_header_divert(VESmail_parse *parse, VESmail_header *hdr) {
    if (VESmail_header_chkbytes(parse->divertbuf) + hdr->len > VESMAIL_HEADER_SAFEBYTES) return VESMAIL_E_BUF;
    parse->divertbuf = VESmail_header_dup(hdr, parse->divertbuf);
    return 0;
}

int VESmail_header_undivert(VESmail_parse *parse) {
    int rs = 0;
    while (parse->divertbuf) {
	int r = VESmail_header_commit(parse, parse->divertbuf);
	if (r < 0) return r;
	rs += r;
	VESmail_header *next = parse->divertbuf->chain;
	VESmail_header_free(parse->divertbuf);
	parse->divertbuf = next;
    }
    return rs;
}

int VESmail_header_commit_or_divert(VESmail_parse *parse, VESmail_header *hdr) {
    int inj = VESmail_check_inject(parse);
    if (inj < 0) return inj;
    return (inj ? &VESmail_header_divert : &VESmail_header_commit)(parse, hdr);
}
