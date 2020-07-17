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
#include <libVES.h>
#include <libVES/Cipher.h>
#include <libVES/VaultItem.h>
#include <libVES/Ref.h>
#include <libVES/User.h>
#include <libVES/VaultKey.h>
#include <libVES/List.h>
#include "../VESmail.h"
#include "parse.h"
#include "header.h"
#include "xform.h"
#include "encrypt.h"
#include "decrypt.h"
#include "optns.h"
#include "mail.h"

#if LIBVES_VERSION_NUMBER < 0x00090500
#error libVES >= 0.95 is required - "https://github.com/vesvault/libVES.c"
#endif


int VESmail_xform_fn_out(VESmail_xform *xform, int final, const char *src, int *srclen) {
    return (src ? (xform->chain ? VESmail_xform_process(xform->chain, final, src, *srclen) : (*srclen = 0)) : 0);
}

VESmail *VESmail_init(VESmail *mail, libVES *ves, VESmail_optns *optns) {
    mail->ves = ves;
    mail->optns = optns ? optns : &VESmail_optns_default;
    mail->msgid = NULL;
    mail->vaultItem = NULL;
    mail->flags = VESMAIL_F_INIT | mail->optns->flags;
    return mail;
}

VESmail *VESmail_new(libVES *ves, VESmail_optns *optns, int (* headerfn)(struct VESmail_parse *parse, struct VESmail_header *hdr)) {
    VESmail *mail = VESmail_init(malloc(sizeof(VESmail)), ves, optns);
    mail->out = VESmail_xform_new(&VESmail_xform_fn_out, NULL, NULL);
    mail->root = VESmail_parse_new(mail, headerfn, mail->out, VESMAIL_EN_ROOT);
    mail->share = NULL;
    mail->nowUrl = NULL;
    return mail;
}

VESmail *VESmail_new_encrypt(libVES *ves, VESmail_optns *optns) {
    return VESmail_new(ves, optns, &VESmail_header_process_enc);
}

VESmail *VESmail_new_decrypt(libVES *ves, VESmail_optns *optns) {
    return VESmail_new(ves, optns, &VESmail_header_process_dec);
}

VESmail *VESmail_set_out(VESmail *mail, VESmail_xform *xform) {
    if (mail) {
	mail->out->chain = xform;
    }
    return mail;
}

libVES_VaultItem *VESmail_get_vaultItem(VESmail *mail) {
    if (!mail->vaultItem) {
	libVES_Ref *ref = libVES_External_new(mail->optns->vesDomain, mail->msgid);
	if (!ref) return NULL;
	if ((mail->vaultItem = libVES_VaultItem_get(ref, mail->ves))) {
	    libVES_Ref_free(ref);
	} else {
	    mail->vaultItem = libVES_VaultItem_create(ref);
	    libVES_Cipher *ci = libVES_Cipher_generate(mail->ves);
	    libVES_VaultItem_setCipher(mail->vaultItem, ci);
	    libVES_Cipher_free(ci);
	}
    }
    return mail->vaultItem;
}

void VESmail_unset_vaultItem(VESmail *mail) {
    libVES_VaultItem_free(mail->vaultItem);
    mail->vaultItem = NULL;
}

int VESmail_cipher_ready(VESmail *mail) {
    return mail->msgid && VESmail_get_vaultItem(mail) && mail->vaultItem->value;
}

libVES_Cipher *VESmail_get_cipher(VESmail *mail) {
    return libVES_VaultItem_getCipher(VESmail_get_vaultItem(mail), mail->ves);
}

void VESmail_logrcpt(VESmail *mail, libVES_VaultKey *vkey) {
    char pub[128];
    const char *p = vkey->publicKey;
    char *d = pub;
    if (p) p = strchr(p, '\n');
    while (p) {
	p++;
	const char *e = strchr(p, '\n');
	if (!e || !e[1]) break;
	if (d > pub + sizeof(pub) - 24) {
	    *d++ = '.';
	    *d++ = '.';
	    *d++ = '.';
	    break;
	}
	const char *e1 = e;
	if (e1 > p && e1[-1] == '\r') e1--;
	if (d > pub) *d++ = ',';
	if (e1 - p > 17) {
	    memcpy(d, p, 8);
	    d += 8;
	    *d++ = '~';
	    p = e1 - 8;
	}
	memcpy(d, p, e1 - p);
	d += e1 - p;
	p = e;
    }
    *d = 0;
    VESmail_arch_log("encrypt msgid=<%s> %s=ves:///%lld/ pub=%s", mail->msgid, (!vkey->ves->vaultKey || vkey->ves->vaultKey->id != vkey->id ? "rcpt" : "self"), vkey->id, pub);
}

int VESmail_save_ves(VESmail *mail) {
    libVES_VaultItem *vi = VESmail_get_vaultItem(mail);
    if (!vi) return VESMAIL_E_VES;
    if (mail->share) {
	int i;
	for (i = 0; i < mail->share->len; i++) {
	    libVES_VaultKey *vkey = mail->share->list[i];
	    if ((mail->optns->flags & VESMAIL_O_VES_NTFY) && libVES_VaultKey_isNew(vkey)) {
		libVES_VaultKey_setAppUrl(vkey, VESmail_nowUrl(mail));
	    }
	    VESmail_logrcpt(mail, vkey);
	}
	if (!libVES_VaultItem_entries(vi, mail->share, LIBVES_SH_ADD)) return VESMAIL_E_VES;
    }
    if ((mail->share || libVES_VaultItem_isNew(vi)) && !libVES_VaultItem_post(vi, mail->ves)) return VESMAIL_E_VES;
    VESmail_unset_vaultItem(mail);
    return 0;
}

int VESmail_add_rcpt(VESmail *mail, const char *rcpt, int update_only) {
    const char *r;
    int rs = 0;
    if (!rcpt) return 0;
    for (r = rcpt; *r; r++) {
	libVES_User *u = libVES_User_fromPath(&r);
	char email[256];
	if (!u) continue;
	if (strlen(u->email) < sizeof(email)) {
	    const char *e = u->email;
	    char *d = email;
	    char c;
	    while ((c = *e++)) *d++ = (c >= 'A' && c <= 'Z') ? c + 0x20 : c;
	    *d = 0;
	    libVES_Ref *ref = libVES_External_new(mail->optns->vesDomain, email);
	    if (ref) {
		rs++;
		if (update_only) {
		    if (mail->share) {
			int i;
			for (i = 0; i < mail->share->len; i++) {
			    libVES_VaultKey *vkey = mail->share->list[i];
			    if (vkey->external && vkey->user && !strcmp(vkey->external->externalId, ref->externalId)) {
				if (u->firstName && !vkey->user->firstName) vkey->user->firstName = strdup(u->firstName);
				if (u->lastName && !vkey->user->lastName) vkey->user->lastName = strdup(u->lastName);
			    }
			}
		    }
		} else {
		    libVES_VaultKey *vkey = libVES_VaultKey_get(ref, mail->ves, u);
		    if (vkey) {
			if (!mail->share) {
			    mail->share = libVES_List_new(&libVES_VaultKey_ListCtl);
			    libVES_List_push(mail->share, libVES_VaultKey_get(mail->ves->external, mail->ves, NULL));
			}
			if (vkey->user != u) libVES_User_free(u);
			if (vkey->external != ref) libVES_Ref_free(ref);
			libVES_List_push(mail->share, vkey);
			continue;
		    }
		}
		libVES_Ref_free(ref);
	    }
	}
	libVES_User_free(u);
    }
    return rs;
}

void VESmail_inject_header(VESmail *mail, VESmail_header *hdr) {
    if (mail && hdr) {
	hdr->chain = mail->root->hdrbuf;
	mail->root->hdrbuf = hdr;
    }
}

int VESmail_convert(struct VESmail *mail, char **dst, int final, const char *src, int srclen) {
    return VESmail_parse_convert(mail->root, dst, final, src, srclen);
}

const char *VESmail_nowUrl(VESmail *mail) {
    if (!mail) return NULL;
    if (!mail->nowUrl && mail->msgid && mail->optns->now.url) {
	int l = strlen(mail->optns->now.url);
	mail->nowUrl = malloc(l + 3 * strlen(mail->msgid) + 1);
	strcpy(mail->nowUrl, mail->optns->now.url);
	char *d = mail->nowUrl + l;
	const char *s = mail->msgid;
	unsigned char c;
	static const char hex[] = "0123456789ABCDEF";
	while ((c = *s++)) {
	    switch (c) {
		case '.': case '-': case '_': case '@':
		    break;
		default:
		    if (c >= '0' && c <= '9') break;
		    if (c >= 'A' && c <= 'Z') break;
		    if (c >= 'a' && c <= 'z') break;
		    *d++ = '%';
		    *d++ = hex[c >> 4];
		    *d++ = hex[c & 0x0f];
		    continue;
	    }
	    *d++ = c;
	}
	*d++ = 0;
	mail->nowUrl = realloc(mail->nowUrl, d - mail->nowUrl);
    }
    return mail->nowUrl;
}

void VESmail_clean(VESmail *mail) {
    libVES_VaultItem_free(mail->vaultItem);
    mail->vaultItem = NULL;
    free(mail->msgid);
    mail->msgid = NULL;
}

void VESmail_free(VESmail *mail) {
    if (mail) {
	VESmail_clean(mail);
	VESmail_parse_free(mail->root);
	VESmail_xform_free(mail->out);
	libVES_List_free(mail->share);
	free(mail->nowUrl);
    }
    free(mail);
}
