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
#include <jVar.h>
#include <libVES.h>
#include <libVES/Ref.h>
#include <libVES/VaultItem.h>
#include <libVES/File.h>
#include <libVES/User.h>
#include <stdarg.h>
#include "../VESmail.h"
#include "../srv/server.h"
#include "../lib/mail.h"
#include "../lib/optns.h"
#include "../lib/xform.h"
#include "../srv/arch.h"
#include "../srv/conf.h"
#include "../srv/tls.h"
#include "now_store.h"
#include "now_probe.h"
#include "now.h"

int (* VESmail_now_feedback_fn)(const char *fbk) = NULL;

int VESmail_now_send(VESmail_server *srv, int final, const char *str) {
    return VESmail_xform_process(srv->rsp_out, final, str, strlen(str));
}

void VESmail_now_log(VESmail_server *srv, const char *meth, int code, ...) {
    char *host = VESmail_server_sockname(srv, 0);
    char *peer = VESmail_server_sockname(srv, 1);
    char buf[256];
    char *d = buf;
    va_list va;
    va_start(va, code);
    while (1) {
	const char *k = va_arg(va, const char *);
	if (!k) break;
	const char *v = va_arg(va, const char *);
	sprintf(d, " %s=%.80s", k, v);
	d += strlen(d);
    }
    va_end(va);
    *d = 0;
    VESmail_server_log(srv, "now %s %d srv=%s peer=%s%s", meth, code, host, peer, buf);
    free(peer);
    free(host);
}

int VESmail_now_send_status(VESmail_server *srv, int code) {
    const char *m;
    switch (code) {
	case 200:
	    m = "Ok";
	    break;
	case 201:
	    m = "Created";
	    break;
	case 202:
	    m = "Accepted";
	    break;
	case 302:
	    m = "Found";
	    break;
	case 400:
	    m = "Bad Request";
	    break;
	case 401:
	    m = "Unauthorized";
	    break;
	case 403:
	    m = "Forbidden";
	    break;
	case 404:
	    m = "Not Found";
	    break;
	case 405:
	    m = "Method Not Supported";
	    break;
	case 408:
	    m = "Timeout";
	    break;
	case 413:
	    m = "Request Body Too Large";
	    break;
	case 426:
	    m = "Upgrade Required";
	    break;
	case 500:
	    m = "Internal Error";
	    break;
	case 502:
	    m = "Bad Gateway";
	    break;
	case 503:
	    m = "Service Unavailable";
	    break;
	default:
	    return VESMAIL_E_PARAM;
    }
    char buf[128];
    sprintf(buf, "HTTP/1.0 %d %s\r\n", code, m);
    return VESmail_now_send(srv, 0, buf);
}

int VESmail_now_sendcl(VESmail_server *srv, const char *body) {
    char buf[64];
    sprintf(buf, "Content-Length: %u\r\n", (body ? (unsigned int) strlen(body) : 0));
    return VESmail_now_send(srv, 0, buf);
}

int VESmail_now_sendhdrs(VESmail_server *srv) {
    VESmail_conf *conf = srv->optns->ref;
    char **h = conf ? conf->now.headers : NULL;
    int rs = 0;
    if (h) while (*h) {
	int r = VESmail_now_send(srv, 0, *h);
	if (r < 0) return r;
	rs += r;
	r = VESmail_now_send(srv, 0, "\r\n");
	if (r < 0) return r;
	rs += r;
	h++;
    }
    int r = VESmail_now_send(srv, 0, "\r\n");
    if (r < 0) return r;
    rs += r;
    return rs;
}

int VESmail_now_error(VESmail_server *srv, int code, const char *msg) {
    int rs = VESmail_now_send_status(srv, code);
    if (rs < 0) return rs;
    int r;
    if (msg) {
	r = VESmail_now_sendcl(srv, msg);
	if (r < 0) return r;
	rs += r;
	r = VESmail_now_send(srv, 0, "Content-Type: text/plain\r\n");
	if (r < 0) return r;
	rs += r;
    }
    r = VESmail_now_sendhdrs(srv);
    if (r < 0) return r;
    rs += r;
    if (msg) {
	r = VESmail_now_send(srv, 1, msg);
	if (r < 0) return r;
	rs += r;
    }
    srv->flags |= VESMAIL_SRVF_SHUTDOWN;
    return rs;
}

int VESmail_now_cont(VESmail_server *srv) {
    return VESmail_now_send(srv, 0, "HTTP/1.0 100 Continue\r\n\r\n");
}

int VESmail_now_xform_fn_post(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    VESmail_server *srv = xform->server;
    if (!xform->data) xform->data = jVarParser_new(NULL);
    xform->data = jVarParser_parse(xform->data, src, *srclen);
    xform->offset += *srclen;
    if (!jVarParser_isComplete((jVarParser *)(xform->data))) {
	if (final || jVarParser_isError((jVarParser *)(xform->data))) return VESmail_now_error(srv, 400, "JSON expected\r\n");
	if (xform->offset > VESMAIL_NOW_REQ_SAFEBYTES) return VESmail_now_error(srv, 413, "Too long");
	return 0;
    }
    jVar *req = jVarParser_done(xform->data);
    xform->data = NULL;
    int e = 400;
    const char *er = "";
    int rs = 0;
    jVar *conn = jVar_get(req, "probe");
    if (conn) {
	int r = VESmail_now_probe(xform->server, conn, jVar_getStringP(jVar_get(req, "token")));
	libVES_cleanseJVar(req);
	jVar_free(req);
	return r;
    }
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
	e = 401;
	er = "Unlock failed\r\n";
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
		e = 426;
		er = "TLS required\r\n";
	    } else {
		VESmail *mail = VESmail_new_decrypt(ves, srv->optns);
		if (!veskey) mail->flags |= VESMAIL_F_PASS;
		char buf[16384];
		int r = VESmail_now_send_status(srv, (e = 200));
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
		VESmail_set_out(mail, (xform->chain ? xform->chain : srv->rsp_out));
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
	    }
	    VESmail_arch_close(fd);
	} else if (!email) {
	    e = 403;
	    er = "Invalid token or messageId\r\n";
	} else {
	    e = 404;
	    er = "This message is not spooled here\r\n";
	}
	free(fname);
	libVES_VaultItem_free(vi);
    } else {
	if (VESmail_now_feedback_fn) {
	    jVar *fbk = jVar_get(req, "feedback");
	    if (fbk) {
		const char *fbks = jVar_getStringP(fbk);
		static void *mutex = NULL;
		VESmail_arch_mutex_lock(&mutex);
		rs = VESmail_now_feedback_fn ? VESmail_now_feedback_fn(fbks) : VESMAIL_E_PARAM;
		VESmail_arch_mutex_unlock(&mutex);
		e = rs >= 0 ? 202 : 502;
		VESmail_now_log(srv, "POST", e, "feedback", fbks, NULL);
		return VESmail_now_error(srv, e, (rs >= 0 ? NULL : "Feedback not accepted"));
	    }
	}
	er = "Required: messageId | probe\r\n";
    }
    libVES_free(ves);
    VESmail_now_log(srv, "POST", e, "msgid", msgid, NULL);
    libVES_cleanseJVar(req);
    jVar_free(req);
    return e == 200 ? rs : VESmail_now_error(srv, e, er);
}

void VESmail_now_xform_fn_post_free(VESmail_xform *xform) {
    if (xform->data) jVar_free(jVarParser_done(xform->data));
    VESmail_xform_free(xform->chain);
}

int VESmail_now_xform_fn_get(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    VESmail_server *srv = xform->server;
    const char *mft = srv->optns->ref ? ((VESmail_conf *) srv->optns->ref)->now.manifest : NULL;
    VESmail_now_log(srv, "GET", (mft ? 200 : 404), NULL);
    if (mft) {
	int rs = VESmail_now_send_status(srv, 200);
	if (rs < 0) return rs;
	int r = VESmail_now_sendcl(srv, mft);
	if (r < 0) return r;
	rs += r;
	r = VESmail_now_send(srv, 0, "Content-Type: application/json\r\n");
	if (r < 0) return r;
	rs += r;
	r = VESmail_now_sendhdrs(srv);
	if (r < 0) return r;
	rs += r;
	r = VESmail_now_send(srv, 1, mft);
	if (r < 0) return r;
	rs += r;
	srv->flags |= VESMAIL_SRVF_SHUTDOWN;
	return rs;
    } else {
	return VESmail_now_error(srv, 404, "Manifest is not supplied\r\n");
    }
}

int VESmail_now_process_chain(VESmail_xform *xform, int final, const char *src, int srclen) {
    if (xform->offset < 0) {
	xform->offset += srclen;
	if (xform->offset >= -1) {
	    xform->server->flags |= VESMAIL_SRVF_SHUTDOWN;
	    final = 1;
	}
    }
    return VESmail_xform_process(xform->chain, final, src, srclen);
}

int VESmail_now_xform_fn_req(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    if (final && !(xform->server->flags & VESMAIL_SRVF_SHUTDOWN)) {
	if (xform->server->flags & VESMAIL_SRVF_TMOUT) VESmail_now_send_status(xform->server, 408);
	xform->server->flags |= VESMAIL_SRVF_SHUTDOWN;
    }
    if (xform->chain) return VESmail_now_process_chain(xform, final, src, *srclen);
    const char *s = src;
    const char *tail = s + *srclen;
    const char *s2;
    char fcont = 0;
    int clen = -1;
    while (s < tail && (s2 = memchr(s, '\n', tail - s))) {
	if (s2 - s > VESMAIL_NOW_REQ_SAFEBYTES) return VESMAIL_E_BUF;
	switch (s2 - s) {
	    case 1:
		if (*s != '\r') break;
	    case 0: {
		char vbuf[12];
		char *d = vbuf;
		for (s = src; s < tail && d < vbuf + sizeof(vbuf) - 1; ) {
		    char c = *s++;
		    if (c >= 'a' && c <= 'z') *d++ = c - 0x20;
		    else if (c >= 'A' && c <= 'Z') *d++ = c;
		    else {
			if (c != ' ') vbuf[0] = 0;
			break;
		    }
		}
		*d = 0;
		const char *url = s;
		s = s2 + 1;
		if (!strcmp(vbuf, "POST")) {
		    if (fcont) VESmail_now_cont(xform->server);
		    xform->chain = VESmail_xform_new(&VESmail_now_xform_fn_post, NULL, xform->server);
		    xform->chain->freefn = &VESmail_now_xform_fn_post_free;
		    return VESmail_now_process_chain(xform, final, s, tail - s);
		} else if (!strcmp(vbuf, "GET")) {
		    const char *u = url;
		    const char *utail = memchr(url, ' ', tail - url);
		    if (utail) {
			while ((u = memchr(u, '/', utail - u))) {
			    if (u < utail - 5 && !memcmp(u + 1, "e2e/", 4)) {
				u += 4;
				char *q = memchr(u, '?', utail - u);
				int rs = VESmail_now_send_status(xform->server, 302);
				if (rs < 0) return rs;
				int r = VESmail_now_send(xform->server, 0, "Location: " VESMAIL_NOW_E2EURL);
				if (r < 0) return r;
				rs += r;
				if (q) {
				    r = VESmail_xform_process(xform->server->rsp_out, 0, u, q - u);
				    if (r < 0) return r;
				    rs += r;
				    r = VESmail_now_send(xform->server, 0, "#");
				    if (r < 0) return r;
				    rs += r;
				    u = q + 1;
				}
				r = VESmail_xform_process(xform->server->rsp_out, 0, u, utail - u);
				if (r < 0) return r;
				rs += r;
				r = VESmail_now_send(xform->server, 1, "\r\n\r\n");
				if (r < 0) return r;
				xform->server->flags |= VESMAIL_SRVF_SHUTDOWN;
				return rs + r;
			    }
			    u++;
			}
		    }
		    xform->chain = VESmail_xform_new(&VESmail_now_xform_fn_get, NULL, xform->server);
		    return VESmail_xform_process(xform->chain, 1, "", 0);
		} else if (!strcmp(vbuf, "PUT")) {
		    if ((xform->chain = VESmail_now_store_put(xform->server))) {
			if (fcont) VESmail_now_cont(xform->server);
			return VESmail_now_process_chain(xform, final, s, tail - s);
		    }
		} else if (!strcmp(vbuf, "OPTIONS")) {
		    VESmail_now_log(xform->server, "OPTIONS", 200, NULL);
		    int rs = VESmail_now_send_status(xform->server, 200);
		    if (rs < 0) return rs;
		    int r = VESmail_now_sendhdrs(xform->server);
		    if (r < 0) return r;
		    rs += r;
		    r = VESmail_now_send(xform->server, 1, "");
		    if (r < 0) return r;
		    xform->server->flags |= VESMAIL_SRVF_SHUTDOWN;
		    return rs + r;
		}
		VESmail_now_log(xform->server, (vbuf[0] ? vbuf : "-"), 405, NULL);
		return VESmail_now_error(xform->server, 405, "Not supported\r\n");
	    }
	    default: {
		char buf[80];
		if (s > src && s2 - s < sizeof(buf) - 1) {
		    char *d = buf;
		    const char *s1;
		    for (s1 = s; s1 < s2; s1++) {
			char c = *s1;
			switch (c) {
			    case ';':
			    case ',':
				c = 0;
			    case 0:
				break;
			    case ' ':
			    case '\t':
			    case '\r':
				break;
			    default:
				*d++ = (c >= 'A' && c <= 'Z') ? (c | 0x20) : c;
				break;
			}
			if (!c) break;
		    }
		    *d = 0;
		    if (!strcmp(buf, "expect:100-continue")) {
			fcont = 1;
		    } else if (sscanf(buf, "content-length:%d", &clen) == 1 && clen >= 0) {
			xform->offset = -1 - clen;
		    }
		}
		break;
	    }
	}
	s = s2 + 1;
    }
    return *srclen = 0;
}

int VESmail_now_idle(VESmail_server *srv, int tmout) {
    if ((srv->tmout = VESMAIL_NOW_TMOUT - tmout) <= 0) srv->flags |= VESMAIL_SRVF_TMOUT;
    return 0;
}

void VESmail_now_debug(VESmail_server *srv, const char *msg) {
    VESmail_now_send(srv, 0, "HTTP/1.0 199 Debug");
    VESmail_now_send(srv, 0, msg);
    VESmail_now_send(srv, 0, "\r\n\r\n");
}

void VESmail_now_fn_free(VESmail_server *srv) {
    VESmail_xform_free(srv->req_in->chain);
}

VESmail_server *VESmail_server_new_now(VESmail_optns *optns) {
    VESmail_server *srv = VESmail_server_init(malloc(sizeof(VESmail_server)), optns);
    srv->type = "now";
    srv->req_in = VESmail_xform_new(&VESmail_now_xform_fn_req, NULL, srv);
    srv->rsp_out = NULL;
    srv->debugfn = &VESmail_now_debug;
    srv->idlefn = &VESmail_now_idle;
    srv->freefn = &VESmail_now_fn_free;
    return srv;
}
