/***************************************************************************
 *  _____
 * |\    | >                   VESmail Project
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
#include "../VESmail.h"
#include "../srv/server.h"
#include "../lib/mail.h"
#include "../lib/optns.h"
#include "../lib/xform.h"
#include "../srv/arch.h"
#include "now_store.h"
#include "now.h"

int VESmail_now_send(VESmail_server *srv, int final, const char *str) {
    return VESmail_xform_process(srv->rsp_out, final, str, strlen(str));
}

int VESmail_now_send_status(VESmail_server *srv, int code) {
    const char *m;
    switch (code) {
	case 200:
	    m = "Ok";
	    break;
	case 400:
	    m = "Bad Request";
	    break;
	case 403:
	    m = "Forbidden";
	    break;
	case 404:
	    m = "Not Found";
	    break;
	case 408:
	    m = "Timeout";
	    break;
	case 500:
	    m = "Internal Error";
	    break;
	default:
	    return VESMAIL_E_PARAM;
    }
    char buf[128];
    sprintf(buf, "HTTP/1.0 %d %s\r\n", code, m);
    return VESmail_now_send(srv, 0, buf);
}

int VESmail_now_error(VESmail_server *srv, int code, const char *msg) {
    int rs = VESmail_now_send_status(srv, code);
    if (rs < 0) return rs;
    int r;
    if (msg) {
	r = VESmail_now_send(srv, 0, "Content-Type: text/plain\r\n\r\n");
	if (r < 0) return r;
	rs += r;
	r = VESmail_now_send(srv, 1, msg);
    } else {
	r = VESmail_now_send(srv, 1, "\r\n");
    }
    if (r < 0) return r;
    rs += r;
    srv->flags |= VESMAIL_SRVF_SHUTDOWN;
    return rs;
}

int VESmail_now_xform_fn_post(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    if (!xform->data) xform->data = jVarParser_new(NULL);
    xform->data = jVarParser_parse(xform->data, src, *srclen);
    if (!jVarParser_isComplete((jVarParser *)(xform->data))) {
	if (final || jVarParser_isError((jVarParser *)(xform->data))) return VESmail_now_error(xform->server, 400, "JSON expected\r\n");
	return 0;
    }
    jVar *req = jVarParser_done(xform->data);
    xform->data = NULL;
    int e = 400;
    const char *er = NULL;
    int rs = 0;
    char *msgid = jVar_getString(jVar_get(req, "messageId"));
    if (msgid) {
	char *fname = VESmail_now_filename(msgid, xform->server->optns);
	int fd = VESmail_arch_openr(fname);
	if (fd >= 0) {
	    char *extid = jVar_getString(jVar_get(req, "externalId"));
	    char *token = jVar_getString(jVar_get(req, "token"));
	    jVar *veskey = jVar_get(req, "VESkey");
	    libVES_Ref *ref = extid ? libVES_External_new(VESMAIL_VES_DOMAIN, extid) : NULL;
	    libVES *ves = libVES_fromRef(ref);
	    if (xform->server->debug > 1) ves->debug = xform->server->debug - 1;
	    if (token) libVES_setSessionToken(ves, token);
	    if (veskey && (!jVar_isString(veskey) || !libVES_unlock(ves, veskey->len, veskey->vString))) {
		e = 403;
		er = "Unlock failed\r\n";
	    } else {
		VESmail *mail = VESmail_new_decrypt(ves, xform->server->optns);
		char buf[16384];
		int r = VESmail_now_send_status(xform->server, 200);
		if (r < 0) return r;
		rs += r;
		r = VESmail_now_send(xform->server, 0, "Content-Type: message/rfc822\r\n\r\n");
		if (r < 0) return r;
		rs += r;
		VESmail_set_out(mail, xform->server->rsp_out);
		int rd;
		while ((rd = VESmail_arch_read(fd, buf, sizeof(buf))) > 0) {
		    r = VESmail_convert(mail, NULL, 0, buf, rd);
		    if (r < 0) return r;
		    rs += r;
		}
		if (rd >= 0) {
		    r = VESmail_convert(mail, NULL, 1, buf, 0);
		    if (r < 0) return r;
		    rs += r;
		}
		VESmail_free(mail);
		e = 200;
		xform->server->flags |= VESMAIL_SRVF_SHUTDOWN;
	    }
	    libVES_free(ves);
	    VESmail_arch_close(fd);
	    free(extid);
	    free(token);
	} else {
	    e = 404;
	}
	free(fname);
	free(msgid);
    } else {
	er = "Required: messageId\r\n";
    }
    jVar_free(req);
    return e == 200 ? rs : VESmail_now_error(xform->server, e, er);
}

void VESmail_now_xform_fn_post_free(VESmail_xform *xform) {
    if (xform->data) jVar_free(jVarParser_done(xform->data));
}

int VESmail_now_xform_fn_req(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    if (xform->chain) return VESmail_xform_process(xform->chain, final, src, *srclen);
    const char *s = src;
    const char *tail = s + *srclen;
    const char *s2;
    while (s < tail && (s2 = memchr(s, '\n', tail - s))) {
	switch (s2 - s) {
	    case 1:
		if (*s != '\r') break;
	    case 0: {
		char vbuf[8];
		char *d = vbuf;
		for (s = src; s < tail && d < vbuf + sizeof(vbuf) - 1; ) {
		    char c = *s++;
		    if (c >= 'a' && c <= 'z') *d++ = c - 0x20;
		    else if (c >= 'A' && c <= 'Z') *d++ = c;
		    else {
			if (c == ' ') *d = 0;
			else vbuf[0] = 0;
			break;
		    }
		}
		if (!strcmp(vbuf, "POST")) {
		    xform->chain = VESmail_xform_new(&VESmail_now_xform_fn_post, NULL, xform->server);
		    xform->chain->freefn = &VESmail_now_xform_fn_post_free;
		    return VESmail_xform_process(xform->chain, final, s2, tail - s2);
		}
		return VESmail_now_error(xform->server, 400, NULL);
	    }
	    default:
		break;
	}
	s = s2 + 1;
    }
    if (final && !(xform->server->flags & VESMAIL_SRVF_SHUTDOWN)) {
	if (xform->server->flags & VESMAIL_SRVF_TMOUT) VESmail_now_send_status(xform->server, 408);
	xform->server->flags |= VESMAIL_SRVF_SHUTDOWN;
    }
    return *srclen = 0;
}

int VESmail_now_idle(VESmail_server *srv, int tmout) {
    if (tmout < 20) return 0;
    srv->flags |= VESMAIL_SRVF_TMOUT;
    return 0;
}

void VESmail_now_debug(VESmail_server *srv, const char *msg) {
    VESmail_now_send(srv, 0, "HTTP/1.0 100 ");
    VESmail_now_send(srv, 0, msg);
    VESmail_now_send(srv, 0, "\r\n");
}

VESmail_server *VESmail_server_new_now(VESmail_optns *optns) {
    VESmail_server *srv = VESmail_server_init(malloc(sizeof(VESmail_server)), optns);
    srv->type = "now";
    srv->req_in = VESmail_xform_new(&VESmail_now_xform_fn_req, NULL, srv);
    srv->rsp_out = NULL;
    srv->debugfn = &VESmail_now_debug;
    srv->idlefn = &VESmail_now_idle;
    return srv;
}
