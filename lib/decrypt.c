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
#include <libVES.h>
#include <libVES/Cipher.h>
#include <libVES/VaultKey.h>
#include <libVES/User.h>
#include <libVES/Ref.h>
#include <jVar.h>
#include "../VESmail.h"
#include "mail.h"
#include "parse.h"
#include "xform.h"
#include "util.h"
#include "header.h"
#include "ves.h"
#include "optns.h"
#include "decrypt.h"


VESmail_header *VESmail_header_decrypt(VESmail_parse *parse, VESmail_header *hdr) {
    libVES_Cipher *ci = VESmail_get_cipher(parse->mail);
    if (!ci || !hdr->val) return NULL;
    int srclen = hdr->key - hdr->val + hdr->len;
    char *buf = NULL;
    const char *e = NULL;
    int len = VESmail_b64decode(&buf, hdr->val, &srclen, &e);
    if (e) {
	parse->error |= VESMAIL_PE_HDR_VES;
	free(buf);
	libVES_Cipher_free(ci);
	return NULL;
    }
    VESmail_header *dec = malloc(sizeof(VESmail_header) + libVES_Cipher_decrypt(ci, 1, buf, len, NULL) + 4);
    char *decbuf = dec->data;
    dec->key = dec->data;
    dec->len = libVES_Cipher_decrypt(ci, 1, buf, len, &decbuf);
    free(buf);
    libVES_Cipher_free(ci);
    if (dec->len < 0) {
	parse->error |= VESMAIL_PE_HDR_VES;
	free(dec);
	return NULL;
    }
    char lckey[48];
    char *plckey = lckey;
    const char *s = decbuf;
    const char *tail = s + dec->len;
    while (s < tail) {
	char c = *s++;
	if (c == ':') {
	    while (s < tail) {
		switch (*s) {
		    case ' ': case '\t': case '\r': case '\n':
			s++;
			continue;
		    default:
			break;
		}
		break;
	    }
	    break;
	} else {
	    if (plckey < lckey + sizeof(lckey) - 1) *plckey++ = (c >= 'A' && c <= 'Z') ? c + 0x20 : c;
	}
    }
    dec->val = s;
    *plckey = 0;
    dec->type = VESmail_parse_header_type(parse, lckey);
    VESmail_header_add_eol(dec, hdr);
    return dec;
}

int VESmail_header_push_dec(VESmail_parse *parse, VESmail_header *hdr, int bufd) {
    int rs = 0;
    if ((parse->mail->flags & VESMAIL_F_PASS) || (parse->mail->msgid && !(parse->mail->flags & VESMAIL_F_ENCD))) {
	int r = VESmail_header_commit(parse, hdr);
	if (r < 0) return r;
	rs += r;
	return rs;
    }
    switch (parse->encap) {
	case VESMAIL_EN_ALT:
	case VESMAIL_EN_INJ:
	    switch (parse->vespart) {
		case VESMAIL_VP_UNDEF:
		    return VESMAIL_E_HOLD;
		case VESMAIL_VP_BANNER:
		    parse->xform = VESmail_parse_xform_null(parse);
		    return rs;
		default:
		    break;
	    }
	default:
	    break;
    }
    switch (hdr->type) {
	case VESMAIL_H_VES: {
	    if (!VESmail_cipher_ready(parse->mail)) return VESMAIL_E_HOLD;
	    VESmail_header *dec = VESmail_header_decrypt(parse, hdr);
	    if (!dec) return VESMAIL_E_VES;
	    parse->dechdrs |= 1 << dec->type;
	    switch (dec->type) {
		case VESMAIL_H_CTENC: {
		    if (parse->dstenc == VESMAIL_CTE_UNDEF) {
			char *ctenc = VESmail_header_get_val(dec, NULL, NULL);
			parse->dstenc = VESmail_header_get_ctenc(ctenc);
			if (parse->dstenc == VESMAIL_CTE_UNDEF) parse->error |= VESMAIL_PE_HDR_INV;
			free(ctenc);
		    } else parse->error |= VESMAIL_PE_HDR_DUP;
		    break;
		}
	    }
	    int r = VESmail_header_commit(parse, dec);
	    VESmail_header_free(dec);
	    return r;
	}
	case VESMAIL_H_PART:
	case VESMAIL_H_XCHG:
	case VESMAIL_H_VESID:
	case VESMAIL_H_VRFY:
	    return rs;
	case VESMAIL_H_CTYPE: case VESMAIL_H_CTENC: {
	    switch (parse->ctype) {
		case VESMAIL_T_VES:
		    return rs;
		case VESMAIL_T_UNDEF:
		    return VESMAIL_E_HOLD;
		case VESMAIL_T_ALT:
		    switch (parse->vespart) {
			case VESMAIL_VP_UNDEF:
			    return VESMAIL_E_HOLD;
			case VESMAIL_VP_INJ:
			    return rs;
			default:
			    break;
		    }
		    break;
		default:
		    break;
	    }
	    break;
	}
	case VESMAIL_H_SUBJ: case VESMAIL_H_CDISP: {
	    if (parse->dechdrs & (1 << hdr->type)) return 0;
	    if (!(parse->dechdrs & (1 << VESMAIL_H_BLANK))) return VESMAIL_E_HOLD;
	    break;
	}
	case VESMAIL_H_MSGID: {
	    if (!(parse->mail->flags & VESMAIL_F_ENCD)) break;
	    int l = strlen(parse->mail->msgid);
	    VESmail_header *h = VESmail_header_new(hdr->key, VESMAIL_H_MSGID, l + 4);
	    VESmail_header_add_val(h, 1, "<");
	    VESmail_header_add_val(h, l, parse->mail->msgid);
	    VESmail_header_add_val(h, 1, ">");
	    VESmail_header_add_eol(h, hdr);
	    int r = VESmail_header_commit(parse, h);
	    VESmail_header_free(h);
	    if (r < 0) return r;
	    rs += r;
	    return rs;
	}
	case VESMAIL_H_REFS:
	    if (parse->mail->flags & VESMAIL_O_HDR_REFS) {
		VESmail_header *hdr2 = VESmail_header_rebuild_references(hdr, parse->mail->optns->idSuffix, 0);
		int r = VESmail_header_commit(parse, hdr2);
		VESmail_header_free(hdr2);
		if (r < 0) return r;
		return rs + r;
	    }
	default:
	    break;
    }
    int r = VESmail_header_commit(parse, hdr);
    if (r < 0) return r;
    rs += r;
    return rs;
}

int VESmail_header_process_dec(struct VESmail_parse *parse, struct VESmail_header *hdr) {
    int rs = VESmail_header_collect(parse, hdr);
    if (rs < 0) return rs;
    switch (hdr->type) {
	case VESMAIL_H_PART: {
	    if (parse->vespart == VESMAIL_VP_UNDEF) {
		char *pt = VESmail_header_get_val(hdr, NULL, NULL);
		if (pt) {
		    if (!strcmp(pt, "body")) parse->vespart = VESMAIL_VP_BODY;
		    else if (!strcmp(pt, "banner")) {
			parse->vespart = VESMAIL_VP_BANNER;
			parse->xform = VESmail_parse_xform_null(parse);
		    } else if (!strcmp(pt, "injected")) parse->vespart = VESMAIL_VP_INJ;
		    else if (!strcmp(pt, "alternative")) parse->vespart = VESMAIL_VP_ALT;
		    else parse->error |= VESMAIL_PE_HDR_INV;
		} else parse->error |= VESMAIL_PE_HDR_INV;
		free(pt);
	    } else parse->error |= VESMAIL_PE_HDR_DUP;
	    break;
	}
	case VESMAIL_H_XCHG: {
	    if ((parse->mail->flags & VESMAIL_F_ENCD) && !VESmail_cipher_ready(parse->mail)) {
		jVar *xchg = jVar_parse(hdr->val, hdr->key + hdr->len - hdr->val);
		jVar *xc;
		int idx = 0;
		long long int uid = libVES_User_getId(libVES_me(parse->mail->ves));
		while ((xc = jVar_index(xchg, idx++))) {
		    if (uid == jVar_getInt(jVar_index(xc, 0))) {
			libVES_Ref *ref = libVES_Ref_new(jVar_getInt(jVar_index(xc, 1)));
			if (ref) {
			    jVar *jvk = jVar_index(xc, 2);
			    if (jVar_isString(jvk)) {
				libVES_VaultKey *vkey = libVES_VaultKey_get(ref, parse->mail->ves, NULL);
				if (vkey) {
				    libVES_veskey *vk = libVES_veskey_new(jvk->len, jvk->vString);
				    if (libVES_VaultKey_unlock(vkey, vk)) {
					if (libVES_VaultKey_apply(vkey)) {
					    vkey = NULL;
					}
					VESmail_unset_vaultItem(parse->mail);
				    }
				    libVES_veskey_free(vk);
				    libVES_VaultKey_free(vkey);
				}
			    }
			    libVES_Ref_free(ref);
			}
		    }
		}
		jVar_free(xchg);
	    }
	    break;
	}
	case VESMAIL_H_BLANK: {
	    parse->dechdrs |= 1 << VESMAIL_H_BLANK;
	    if (parse->vespart == VESMAIL_VP_UNDEF) parse->vespart = VESMAIL_VP_BODY;
	    if (!parse->mail->msgid) {
		parse->mail->msgid = strdup("");
	    }
	    if ((parse->mail->flags & VESMAIL_F_ENCD) && !VESmail_cipher_ready(parse->mail)) {
		return VESMAIL_E_VES;
	    }
	    break;
	}
	default:
	    break;
    }
    if (parse->encap != VESMAIL_EN_INJ) {
	int r = VESmail_header_push(parse, hdr, &VESmail_header_push_dec);
	if (r < 0) return r;
	rs += r;
    }
    if (parse->mail->flags & VESMAIL_F_ENCD) switch (hdr->type) {
	case VESMAIL_H_BLANK: {
	    if (parse->ctype == VESMAIL_T_VES) {
		int r = VESmail_parse_apply_encode(parse);
		if (r < 0) return r;
		rs += r;
		parse->xform = VESmail_xform_new_decrypt(parse);
	    }
	    int r = VESmail_parse_apply_nested(parse);
	    if (r < 0) return r;
	    rs += r;
	    r = VESmail_parse_apply_decode(parse);
	    if (r < 0) return r;
	    rs += r;
	    break;
	}
    }
    return rs;
}

int VESmail_xform_fn_decrypt(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return *srclen = 0;
    libVES_Cipher *ci = VESmail_xform_ves_cipher(xform);
    if (!ci) return VESMAIL_E_VES;
    char *dst = NULL;
    int ptlen = libVES_Cipher_decrypt(ci, final, src, *srclen, &dst);
    if (ptlen < 0) return VESMAIL_E_VES;
    int r = VESmail_xform_process(xform->chain, final, dst, ptlen);
    VESmail_cleanse(dst, ptlen);
    free(dst);
    return r;
}

VESmail_xform *VESmail_xform_new_decrypt(VESmail_parse *parse) {
    return VESmail_xform_new(&VESmail_xform_fn_decrypt, parse->xform, parse);
}

