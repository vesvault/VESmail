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
#include <openssl/evp.h>
#include <libVES.h>
#include <libVES/User.h>
#include <libVES/VaultItem.h>
#include <libVES/File.h>
#include <libVES/Ref.h>
#include <jVar.h>
#include "../VESmail.h"
#include "../lib/mail.h"
#include "../lib/optns.h"
#include "../lib/xform.h"
#include "../lib/parse.h"
#include "../lib/header.h"
#include "../srv/arch.h"
#include "../srv/server.h"
#include "../srv/conf.h"
#include "../srv/tls.h"
#include "now.h"
#include "now_store.h"


int VESmail_now_store_xform_fn(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    VESmail *mail = xform->parse->mail;
    if (xform->fd == VESMAIL_E_HOLD) {
	if (mail->flags & VESMAIL_F_PASS) {
	    xform->fd = VESMAIL_E_PARAM;
	} else {
	    libVES_User *me = libVES_me(mail->ves);
	    char *fname = VESmail_now_filename(mail->msgid, libVES_User_getEmail(me), mail->optns);
	    if (fname) {
		int fd = VESmail_arch_creat(fname);
		xform->fd = fd < 0 ? VESMAIL_E_IO : fd;
		free(fname);
	    } else if (!final) {
		return *srclen = 0;
	    }
	}
    }
    if (xform->fd >= 0) {
	int l = *srclen;
	VESmail_conf *conf = mail->optns->ref;
	if (conf && conf->now.maxSize > 0 && conf->now.maxSize < xform->offset + l) {
	    l = conf->now.maxSize - xform->offset;
	}
	const char *s = src;
	while (l > 0) {
	    int w = VESmail_arch_write(xform->fd, s, l);
	    if (w < 0) {
		VESmail_arch_close(xform->fd);
		xform->fd = VESMAIL_E_IO;
		break;
	    }
	    s += w;
	    l -= w;
	    xform->offset += w;
	}
	if (final) {
	    if (VESmail_arch_close(xform->fd) < 0) xform->fd = VESMAIL_E_IO;
	}
    }
    if (xform->fd < 0) xform->parse->error |= VESMAIL_MERR_NOW;
    return VESmail_xform_process(xform->chain, final, src, *srclen);
}

char *VESmail_now_filename(const char *msgid, const char *email, VESmail_optns *optns) {
    if (!msgid || !email || !*email || !optns->now.dir) return NULL;
    int l = strlen(optns->now.dir);
    int l2 = strlen(email);
    char *fname = malloc(l + l2 + 40);
    strcpy(fname, optns->now.dir);
    unsigned char *d = (unsigned char *) fname + l;
    *d++ = '/';
    const char *e = email;
    char c;
    while ((c = *e)) {
	switch (c) {
	    case '.':
		if (e > email) break;
	    case '/':
	    case '\\':
		c = '_';
	    default:
		break;
	}
	e++;
	*d++ = c;
    }
    *d = 0;
    VESmail_arch_mkdir(fname, 0771);
    *d++ = '/';
    void *mdctx = EVP_MD_CTX_create();
    unsigned int shalen = 32;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) > 0
	&& EVP_DigestUpdate(mdctx, msgid, strlen(msgid)) > 0
	&& EVP_DigestFinal_ex(mdctx, d, &shalen) > 0) {
	while (shalen > 0) {
	    unsigned char v = *d % 36;
	    *d++ = (v >= 10 ? 'a' - 10 : '0') + v;
	    shalen--;
	}
	*d = 0;
    } else {
	free(fname);
	fname = NULL;
    }
    EVP_MD_CTX_destroy(mdctx);
    return fname;
}

void VESmail_now_store_inject(VESmail_parse *root, int fd) {
    root->xform = VESmail_xform_new(&VESmail_now_store_xform_fn, root->xform, root);
    root->xform->fd = fd;
}

VESmail *VESmail_now_store_apply(VESmail *mail) {
    if (!mail || !mail->optns->now.dir) return mail;
    VESmail_now_store_inject(mail->root, VESMAIL_E_HOLD);
    return mail;
}


#define VESmail_now_store_error(srv, code, err)	(VESmail_now_log(srv, "PUT", code, NULL), VESmail_now_error(srv, code, err))
#define VESmail_now_store_error_msg(srv, code, err, mail)	(VESmail_now_log(srv, "PUT", code, "msgid", (mail)->msgid, NULL), VESmail_now_error(srv, code, err))

int VESmail_now_store_hdrpush(VESmail_parse *parse, VESmail_header *hdr, int bufd) {
    VESmail *mail = parse->mail;
    VESmail_server *srv = parse->ref;
    if (!mail->msgid || !srv->ves) return VESMAIL_E_HOLD;
    if (!mail->ves) {
	mail->ves = srv->ves;
	libVES_VaultItem *vi = VESmail_get_vaultItem(mail);
	if (!vi || !vi->id) return VESmail_now_store_error(srv, 503, "Failed to retrieve Message-ID\r\n");
	libVES_File *fi = libVES_VaultItem_getFile(vi);
	libVES_User *u = libVES_File_getCreator(fi);
	char *fname = VESmail_now_filename(mail->msgid, libVES_User_getEmail(u), mail->optns);
	if (!fname) return VESmail_now_store_error_msg(srv, 401, "Failed to retrieve the creator info\r\n", mail);
	int fd = VESmail_arch_creat(fname);
	free(fname);
	if (fd < 0) return VESmail_now_store_error_msg(srv, 403, "Error opening the spool file\r\n", mail);
	VESmail_now_store_inject(mail->root, fd);
    }
    return VESmail_header_output(parse, hdr);
}

int VESmail_now_store_hdrproc(VESmail_parse *parse, VESmail_header *hdr) {
    int rs = VESmail_header_collect(parse, hdr);
    if (rs < 0) return rs;
    VESmail_server *srv = parse->ref;
    switch (hdr->type) {
	case VESMAIL_H_VRFY:
	    if (!srv->ves && hdr->val) {
		char vrfy[80];
		const char *s = hdr->val;
		const char *tail = hdr->key + hdr->len;
		char *d = vrfy;
		while (s < tail && d < vrfy + sizeof(vrfy) - 1) {
		    char c = *s++;
		    switch (c) {
			case ' ': case '\t': case '\r': case '\n':
			    if (d == vrfy) continue;
			case ';': case ',':
			    c = 0;
			default:
			    *d++ = c;
		    }
		    if (!c) break;
		}
		*d = 0;
		srv->ves = libVES_fromRef(NULL);
		VESmail_tls_initVES(srv->ves);
		libVES_setSessionToken(srv->ves, vrfy);
		if (srv->debug > VESMAIL_DEBUG_LIBVES) srv->ves->debug = srv->debug - VESMAIL_DEBUG_LIBVES;
	    }
	    return rs;
	case VESMAIL_H_BLANK:
	    if (!srv->ves) {
		int r = VESmail_now_store_error_msg(srv, 400, "Message-ID: and X-VESmail-Verify: are required\r\n", parse->mail);
		if (r < 0) return r;
		return rs + r;
	    }
	default:
	    break;
    }
    int r = VESmail_header_push(parse, hdr, &VESmail_now_store_hdrpush);
    if (r < 0) return r;
    rs += r;
    return rs;
}

int VESmail_now_store_put_xform_fn(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    VESmail_parse *parse = xform->parse;
    VESmail *mail = parse->mail;
    VESmail_server *srv = parse->ref;
    int rs = VESmail_parse_process(parse, final, src, srclen);
    if (rs < 0) return rs;
    if (parse->error & VESMAIL_MERR_NOW) {
	int r = VESmail_now_store_error(srv, 500, "Error writing the spool file\r\n");
	if (r < 0) return r;
	return rs + r;
    }
    if (final) {
	VESmail_now_log(srv, "PUT", 201, "msgid", mail->msgid, NULL);
	if (VESmail_now_send_status(srv, 201) >= 0) VESmail_now_send(srv, 1, "\r\n");
    }
    return rs;
}

void VESmail_now_store_put_free_fn(VESmail_xform *xform) {
    VESmail_free(xform->parse->mail);
}

VESmail_xform *VESmail_now_store_put(VESmail_server *srv) {
    VESmail *mail = VESmail_new(NULL, srv->optns, &VESmail_now_store_hdrproc);
    mail->root->ref = srv;
    VESmail_xform *out = VESmail_xform_new_null(mail->root);
    VESmail_set_out(mail, out);
    VESmail_xform *in = VESmail_xform_new(&VESmail_now_store_put_xform_fn, out, mail->root);
    in->freefn = &VESmail_now_store_put_free_fn;
    return in;
}

int VESmail_now_store_reqStack(VESmail_now_req *req) {
    if (strcmp(req->method, "PUT")) return VESMAIL_E_HOLD;
    if (!(req->xform->chain = VESmail_now_store_put(req->xform->server))) return VESMAIL_E_HOLD;
    VESmail_now_req_cont(req);
    return 0;
}

int VESmail_now_store_postStack(VESmail_server *srv, jVar *req) {
    int rs = 0;
    char *msgid = jVar_getStringP(jVar_get(req, "messageId"));
    char *token = jVar_getStringP(jVar_get(req, "token"));
    char *extid = jVar_getStringP(jVar_get(req, "externalId"));
    jVar *veskey = jVar_get(req, "VESkey");
    libVES_Ref *ref = extid ? libVES_External_new(srv->optns->vesDomain, extid) : NULL;
    libVES *ves = libVES_fromRef(ref);
    if (srv->debug > 1) ves->debug = srv->debug - 1;
    VESmail_tls_initVES(ves);
    if (token) libVES_setSessionToken(ves, token);
    if (veskey && (!jVar_isString(veskey) || !libVES_unlock(ves, veskey->len, veskey->vString))) {
	rs = VESmail_now_errorlog(srv, 401, "Unlock failed\r\n", "POST[store]", "msgid", msgid);
    } else if (msgid) {
	libVES_Ref *msgref = libVES_External_new(srv->optns->vesDomain, msgid);
	libVES_VaultItem *vi = libVES_VaultItem_get(msgref, ves);
	libVES_Ref_free(msgref);
	const char *email;
	if (vi) {
	    libVES_File *fi = libVES_VaultItem_getFile(vi);
	    libVES_User *u = libVES_File_getCreator(fi);
	    email = libVES_User_getEmail(u);
	} else {
	    email = NULL;
	}
	char *fname = VESmail_now_filename(msgid, email, srv->optns);
	int fd = VESmail_arch_openr(fname);
	if (fd >= 0) {
	    if (!VESmail_tls_server_allow_plain(srv)) {
		rs = VESmail_now_errorlog(srv, 426, "TLS required\r\n", "POST[store]", "msgid", msgid);
	    } else {
		VESmail *mail = VESmail_new_decrypt(ves, srv->optns);
		if (!veskey) mail->flags |= VESMAIL_F_PASS;
		char buf[16384];
		int r = VESmail_now_send_status(srv, 200);
		if (r >= 0) rs += r;
		else rs = r;
		if (rs >= 0) {
		    r = VESmail_now_send(srv, 0, "Content-Type: message/rfc822\r\n");
		    if (r >= 0) rs += r;
		    else rs = r;
		}
		if (rs >= 0) {
		    r = VESmail_now_sendhdrs(srv);
		    if (r >= 0) rs += r;
		    else rs = r;
		}
		VESmail_set_out(mail, (srv->req_in->chain ? srv->req_in->chain : srv->rsp_out));
		int rd;
		while (rs >= 0 && (rd = VESmail_arch_read(fd, buf, sizeof(buf))) > 0) {
		    r = VESmail_convert(mail, NULL, 0, buf, rd);
		    if (r >= 0) rs += r;
		    else rs = r;
		}
		if (rs >= 0 && rd >= 0) {
		    r = VESmail_convert(mail, NULL, 1, buf, 0);
		    if (r >= 0) rs += r;
		    else rs = r;
		}
		VESmail_set_out(mail, NULL);
		VESmail_free(mail);
		srv->flags |= VESMAIL_SRVF_SHUTDOWN;
		VESmail_now_log(srv, "POST[store]", 200, "msgid", msgid, NULL);
	    }
	    VESmail_arch_close(fd);
	} else if (!email) {
	    rs = VESmail_now_errorlog(srv, 403, "Invalid token or messageId\r\n", "POST[store]", "msgid", msgid);
	} else {
	    rs = VESmail_now_errorlog(srv, 404, "This message is not spooled here\r\n", "POST[store]", "msgid", msgid);
	}
	free(fname);
	libVES_VaultItem_free(vi);
    } else rs = VESMAIL_E_HOLD;
    libVES_free(ves);
    libVES_cleanseJVar(req);
    jVar_free(req);
    return rs;
}
