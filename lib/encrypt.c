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
#include <stdio.h>
#include <libVES/Cipher.h>
#include <libVES/VaultItem.h>
#include <libVES/VaultKey.h>
#include <libVES/User.h>
#include <jVar.h>
#include "../VESmail.h"
#include "mail.h"
#include "parse.h"
#include "xform.h"
#include "banner.h"
#include "util.h"
#include "header.h"
#include "ves.h"
#include "optns.h"
#include "encrypt.h"



VESmail_header *VESmail_header_encrypt(VESmail_parse *parse, VESmail_header *hdr) {
    libVES_Cipher *ci = VESmail_get_cipher(parse->mail);
    if (!ci) return NULL;
    const char *eol = VESmail_header_get_eol(hdr);
    int len = eol - hdr->key;
    char *ctext = NULL;
    int ctlen = libVES_Cipher_encrypt(ci, 1, hdr->key, len, &ctext);
    if (ctlen < 0) return NULL;
    VESmail_header *enc = VESmail_header_new("X-VESmail-Header:", VESMAIL_H_VES, ctlen * 3 / 2);
    char *ctail = ctext + ctlen;
    char *c = ctext;
    int l = 45;
    while (c < ctail) {
	if (c > ctext) {
	    VESmail_header_add_val(enc, hdr->len - len, eol);
	    VESmail_header_add_val(enc, 1, "\t");
	}
	if (ctail - c < l) l = ctail - c;
	libVES_b64encode(c, l, enc->data + enc->len);
	c += l;
	enc->len += strlen(enc->data + enc->len);
	l = 51;
    }
    VESmail_header_add_val(enc, hdr->len - len, eol);
    free(ctext);
    libVES_Cipher_free(ci);
    return enc;
}

int VESmail_header_encrypt_push(VESmail_parse *parse, VESmail_header *hdr) {
    if (!VESmail_cipher_ready(parse->mail)) return VESMAIL_E_HOLD;
    VESmail_header *enc = VESmail_header_encrypt(parse, hdr);
    if (!enc) return VESMAIL_E_VES;
    int r = VESmail_header_commit(parse, enc);
    VESmail_header_free(enc);
    return r;
}

int VESmail_header_encd_msgid(VESmail_parse *parse, const char *key, VESmail_header *hdr) {
    int l1, l2;
    int rs = 0;
    VESmail_header *h = VESmail_header_new("X-VESmail-ID:", VESMAIL_H_VESID, (l1 = strlen(parse->mail->msgid)) + 16);
    VESmail_header_add_val(h, 1, "<");
    VESmail_header_add_val(h, l1, parse->mail->msgid);
    VESmail_header_add_val(h, 1, ">");
    VESmail_header_add_eol(h, hdr);
    int r = VESmail_header_commit(parse, h);
    VESmail_header_free(h);
    if (r < 0) return r;
    rs += r;
    h = VESmail_header_new(key, VESMAIL_H_MSGID, l1 + (l2 = strlen(parse->mail->optns->idSuffix)) + 16);
    VESmail_header_add_val(h, 1, "<");
    VESmail_header_add_val(h, l1, parse->mail->msgid);
    VESmail_header_add_val(h, l2, parse->mail->optns->idSuffix);
    VESmail_header_add_val(h, 1, ">");
    VESmail_header_add_eol(h, hdr);
    r = VESmail_header_commit(parse, h);
    VESmail_header_free(h);
    if (r < 0) return r;
    return rs + r;
}

int VESmail_header_send_xchg(VESmail_parse *parse) {
    libVES_VaultItem *vi = VESmail_get_vaultItem(parse->mail);
    if (!vi) return VESMAIL_E_VES;
    int maxl = 128 * vi->sharelen;
    VESmail_header *h = NULL;
    int i;
    for (i = 0; i < vi->sharelen; i++) {
	libVES_VaultKey *vk = vi->share[i];
	if (vk->type == LIBVES_VK_TEMP) {
	    long long int uid = libVES_User_getId(vk->user);
	    if (uid) {
		struct libVES_veskey *k = libVES_VaultKey_getVESkey(vk);
		if (k) {
		    if (h) {
			VESmail_header_add_val(h, 4, ",\r\n\t");
			maxl -= 4;
		    } else {
			h = VESmail_header_new("X-VESmail-Xchg:", VESMAIL_H_XCHG, maxl);
			VESmail_header_add_val(h, 1, "[");
			maxl--;
		    }
		    jVar *jv = jVar_array();
		    jVar_push(jv, jVar_int(uid));
		    jVar_push(jv, jVar_int(vk->id));
		    jVar_push(jv, jVar_stringl(k->veskey, k->keylen));
		    libVES_veskey_free(k);
		    char *json = jVar_toJSON(jv);
		    jVar_free(jv);
		    int l = strlen(json);
		    if (l + 16 > maxl) {
			free(json);
			VESmail_header_free(h);
			return VESMAIL_E_BUF;
		    }
		    maxl -= l;
		    VESmail_header_add_val(h, l, json);
		    free(json);
		}
	    }
	}
    }
    int rs;
    if (h) {
	VESmail_header_add_val(h, 3, "]\r\n");
	rs = VESmail_header_commit(parse, h);
	VESmail_header_free(h);
    } else rs = 0;
    return rs;
}


int VESmail_header_push_enc(VESmail_parse *parse, VESmail_header *hdr, int bufd) {
    if (parse->mail->flags & VESMAIL_F_PASS) return VESmail_header_commit(parse, hdr);
    int rs = 0;
    switch (hdr->type) {
	case VESMAIL_H_CTYPE: {
	    int inj = VESmail_check_inject(parse);
	    if (inj < 0) return inj;
	    int encf = parse->ctype == VESMAIL_T_OTHER || parse->ctype == VESMAIL_T_VES;
	    if (inj || encf) {
		int r = VESmail_header_encrypt_push(parse, hdr);
		if (r < 0) return r;
		rs += r;
		if (!encf) {
		    int r = VESmail_header_divert(parse, hdr);
		    if (rs < 0) return r;
		    rs += r;
		}
		return rs;
	    }
	    if (parse->ctype == VESMAIL_T_ALT) {
		switch (parse->encap) {
		    case VESMAIL_EN_ROOT:
		    case VESMAIL_EN_MULTI: {
			VESmail_header *h = VESmail_header_add_eol(
			    VESmail_header_add_val(
				VESmail_header_new("X-VESmail-Part:", VESMAIL_H_PART, 64),
				11, "alternative"
			    ), hdr);
			int r = VESmail_header_commit(parse, h);
			VESmail_header_free(h);
			if (r < 0) return r;
			rs += r;
			break;
		    }
		    default:
			break;
		}
	    }
	    break;
	}
	case VESMAIL_H_CTENC: {
	    switch (parse->ctype) {
		case VESMAIL_T_UNDEF:
		    return VESMAIL_E_HOLD;
		case VESMAIL_T_OTHER:
		    parse->dstenc = VESMAIL_CTE_B64;
		    int r = VESmail_header_encrypt_push(parse, hdr);
		    if (r < 0) return r;
		    rs += r;
		    return rs;
		default:
		    break;
	    }
	    break;
	}
	case VESMAIL_H_CDISP: {
	    const char *s = memchr(hdr->val, ';', hdr->val - hdr->key + hdr->len);
	    if (s) {
		int r = VESmail_header_encrypt_push(parse, hdr);
		if (r < 0) return r;
		rs += r;
		VESmail_header *h = VESmail_header_new(hdr->key, VESMAIL_H_CDISP, s - hdr->val);
		VESmail_header_add_eol(VESmail_header_add_val(h, s - hdr->val, hdr->val), hdr);
		r = VESmail_header_commit_or_divert(parse, h);
		VESmail_header_free(h);
		if (r < 0) return r;
		rs += r;
		return rs;
	    }
	    break;
	}
	case VESMAIL_H_SUBJ: {
	    int r = VESmail_header_encrypt_push(parse, hdr);
	    if (r < 0) return r;
	    rs += r;
	    if ((parse->encap == VESMAIL_EN_ROOT) && parse->mail->optns->subj) {
		int l;
		VESmail_header *h = VESmail_header_new(hdr->key, VESMAIL_H_SUBJ, l = strlen(parse->mail->optns->subj));
		VESmail_header_add_eol(VESmail_header_add_val(h, l, parse->mail->optns->subj), hdr);
		r = VESmail_header_commit(parse, h);
		VESmail_header_free(h);
		if (r < 0) return r;
		rs += r;
	    }
	    return rs;
	}
	case VESMAIL_H_MSGID: {
	    if (parse->mail->flags & VESMAIL_F_ENCD) break;
	    if (parse->mail->msgid) {
		int r = VESmail_header_encd_msgid(parse, hdr->key, hdr);
		if (r < 0) return r;
		rs += r;
	    }
	    return rs;
	}
	case VESMAIL_H_RCPT:
	case VESMAIL_H_NOENC:
	    break;
	case VESMAIL_H_BLANK: {
	    if (parse->encap == VESMAIL_EN_ROOT) {
		int r = VESmail_save_ves(parse->mail);
		if (r < 0) return r;
		rs += r;
		if (parse->mail->flags & VESMAIL_O_XCHG) {
		    r = VESmail_header_send_xchg(parse);
		    if (r < 0) return r;
		    rs += r;
		}
	    }
	    switch (parse->ctype) {
		case VESMAIL_T_OTHER:
		case VESMAIL_T_VES: {
		    VESmail_header *h;
		    if (parse->encap == VESMAIL_EN_ALT || VESmail_check_inject(parse)) {
			h = VESmail_header_add_eol(
			    VESmail_header_add_val(
				VESmail_header_new("X-VESmail-Part:", VESMAIL_H_PART, 64),
				4, "body"
			    ), hdr);
			int r = VESmail_header_commit_or_divert(parse, h);
			VESmail_header_free(h);
			if (r < 0) return r;
			rs += r;
		    }
		    h = VESmail_header_add_eol(
			VESmail_header_add_val(
			    VESmail_header_new("Content-Type:", VESMAIL_H_CTYPE, 64),
			    strlen(parse->mail->optns->mime[0]), parse->mail->optns->mime[0]
			), hdr);
		    int r = VESmail_header_commit_or_divert(parse, h);
		    VESmail_header_free(h);
		    if (r < 0) return r;
		    rs += r;
		    h = VESmail_header_add_eol(
			VESmail_header_add_val(
			    VESmail_header_new("Content-Transfer-Encoding:", VESMAIL_H_CTENC, 64),
			    6, "base64"
			), hdr);
		    r = VESmail_header_commit_or_divert(parse, h);
		    VESmail_header_free(h);
		    if (r < 0) return r;
		    rs += r;
		    parse->dstenc = VESMAIL_CTE_B64;
		    break;
		}
		default:
		    break;
	    }
	    if (VESmail_check_inject(parse) > 0) {
		char *d = parse->injboundary = malloc(strlen(parse->mail->optns->injected[0]) + 48);
		strcpy(d, parse->mail->optns->injected[0]);
		d += strlen(d);
		VESmail_randstr(40, d);
		d[40] = 0;
		VESmail_header *h = VESmail_header_new("X-VESmail-Part:",VESMAIL_H_PART, 32);
		VESmail_header_add_eol(VESmail_header_add_val(h, 8, "injected"), hdr);
		int r = VESmail_header_commit(parse, h);
		VESmail_header_free(h);
		if (r < 0) return r;
		rs += r;
		h = VESmail_header_new("Content-Type:",VESMAIL_H_CTYPE, 256);
		VESmail_header_add_eol(VESmail_header_add_val(h, 22, "multipart/alternative;"), hdr);
		d = h->data + h->len;
		sprintf(d, "\tboundary=\"%s\"", parse->injboundary);
		h->len += strlen(d);
		VESmail_header_add_eol(h, hdr);
		r = VESmail_header_commit(parse, h);
		VESmail_header_free(h);
		if (r < 0) return r;
		rs += r;
	    }
	    break;
	}
	default:
	    return VESmail_header_encrypt_push(parse, hdr);
    }
    switch (hdr->type) {
	case VESMAIL_H_CTENC:
	case VESMAIL_H_CDISP: {
	    int inj = VESmail_check_inject(parse);
	    if (inj < 0) return inj;
	    if (inj) {
		int r = VESmail_header_divert(parse, hdr);
		if (r < 0) return r;
		rs += r;
		return rs;
	    }
	    break;
	}
	default:
	    break;
    }
    int r = VESmail_header_commit(parse, hdr);
    if (r < 0) return r;
    rs += r;
    return rs;
}

int VESmail_header_process_enc(struct VESmail_parse *parse, struct VESmail_header *hdr) {
    int rs = VESmail_header_collect(parse, hdr);
    if (rs < 0) return rs;
    switch (hdr->type) {
	case VESMAIL_H_RCPT: {
	    char *rcpt = strndup(hdr->val, VESmail_header_get_eol(hdr) - hdr->val);
	    VESmail_add_rcpt(parse->mail, rcpt, !(parse->mail->flags & VESMAIL_O_HDR_RCPT));
	    free(rcpt);
	    break;
	}
	case VESMAIL_H_BLANK: {
	    if (!parse->mail->msgid && !(parse->mail->flags & VESMAIL_F_PASS)) {
		char *msgid = malloc(strlen(parse->mail->optns->idBase) + 48);
		VESmail_randstr(32, msgid);
		strcpy(msgid + 32, parse->mail->optns->idBase);
		parse->mail->msgid = msgid;
		int r = VESmail_header_encd_msgid(parse, "Message-ID:", hdr);
		if (r < 0) return r;
		rs += r;
	    }
	    break;
	}
    }
    int r = VESmail_header_push(parse, hdr, &VESmail_header_push_enc);
    if (r < 0) return r;
    rs += r;
    switch (hdr->type) {
	case VESMAIL_H_BLANK: {
	    if (parse->mail->flags & VESMAIL_F_PASS) break;
	    int inj = VESmail_check_inject(parse);
	    if (inj > 0) {
		char buf[128];
		sprintf(buf, "\r\n--%s\r\n", parse->injboundary);
		int r = VESmail_xform_process(parse->xform, 0, buf, strlen(buf));
		if (r < 0) return r;
		rs += r;
		r = VESmail_header_undivert(parse);
		if (r < 0) return r;
		rs += r;
	    }
	    if (inj > 0) {
		r = VESmail_header_commit(parse, hdr);
		if (r < 0) return r;
		rs += r;
		parse->xform = VESmail_xform_new_inject(parse, &VESmail_banner_alt_inject);
	    }
	    switch (parse->ctype) {
		case VESMAIL_T_OTHER:
		case VESMAIL_T_VES: {
		    r = VESmail_parse_apply_encode(parse);
		    if (r < 0) return r;
		    rs += r;
		    parse->xform = VESmail_xform_new_encrypt(parse);
		    break;
		}
		default:
		    break;
	    }
	    r = VESmail_parse_apply_nested(parse);
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

int VESmail_xform_fn_encrypt(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return *srclen = 0;
    libVES_Cipher *ci = VESmail_xform_ves_cipher(xform);
    if (!ci) return VESMAIL_E_VES;
    char *dst = NULL;
    int ctlen = libVES_Cipher_encrypt(ci, final, src, *srclen, &dst);
    if (ctlen < 0) return VESMAIL_E_VES;
    int r = VESmail_xform_process(xform->chain, final, dst, ctlen);
    free(dst);
    return r;
}

VESmail_xform *VESmail_xform_new_encrypt(VESmail_parse *parse) {
    return VESmail_xform_new(&VESmail_xform_fn_encrypt, parse->xform, parse);
}

