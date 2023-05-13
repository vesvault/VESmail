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
	case 101:
	    m = "Switching Protocols";
	    break;
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

int VESmail_now_req_cont(VESmail_now_req *req) {
    struct VESmail_now_hdr *h = NULL;
    while ((h = VESmail_now_req_header(req, h))) {
	if (!strcmp(h->key, "expect") && h->end > h->val + 4 && !memcmp(h->lcval, "100-", 4)) return VESmail_now_cont(req->xform->server);
    }
    return 0;
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

struct VESmail_now_hdr *VESmail_now_req_header(struct VESmail_now_req *req, struct VESmail_now_hdr *prev) {
    struct VESmail_now_hdr **ph = prev ? &prev->chain : &req->headers;
    if (*ph) return *ph;
    const char *s = prev ? prev->next : req->hdr.start;
    if (s >= req->hdr.end) return NULL;
    const char *lf = memchr(s, '\n', req->hdr.end - s);
    if (!lf) return NULL;
    const char *e = (lf > s && lf[-1] == '\r') ? lf - 1 : lf;
    struct VESmail_now_hdr *h = malloc(sizeof(struct VESmail_now_hdr) + e - s + 1);
    if (!h) return NULL;
    h->chain = NULL;
    h->end = h->val = e;
    h->next = lf + 1;
    h->lcval = NULL;
    char *d = h->key;
    enum { kst_init, kst_colon, kst_done } kst = kst_init;
    while (s < e) {
	char c = *s++;
	switch (c) {
	    case ' ': case '\t':
		continue;
	    case ':':
		if (kst == kst_init) {
		    kst = kst_colon;
		    c = 0;
		}
		break;
	    default:
		if (kst == kst_colon) {
		    kst = kst_done;
		    h->val = s - 1;
		    h->lcval = d;
		}
		if (c >= 'A' && c <= 'Z') c |= 0x20;
		break;
	}
	*d++ = c;
    }
    if (!h->lcval) h->lcval = d;
    *d++ = 0;
    return *ph = h;
}

void VESmail_now_req_cleanup(struct VESmail_now_req *req) {
    while (req->headers) {
	struct VESmail_now_hdr *h = req->headers->chain;
	free(req->headers);
	req->headers = h;
    }
}

int VESmail_now_xform_fn_req(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    if (final && !(xform->server->flags & VESMAIL_SRVF_SHUTDOWN)) {
	xform->server->flags |= VESMAIL_SRVF_SHUTDOWN;
	if (xform->server->flags & VESMAIL_SRVF_TMOUT) return VESmail_now_errorlog(xform->server, 408, "Timeout\r\n", "-", NULL);
    }
    if (xform->chain) return VESmail_now_process_chain(xform, final, src, *srclen);
    const char *s = src;
    const char *tail = s + *srclen;
    const char *s2;
    VESmail_now_req req;
    req.xform = xform;
    req.headers = NULL;
    req.hdr.start = req.hdr.end = NULL;
    const char *body;
    while (s < tail && (s2 = memchr(s, '\n', tail - s))) {
	if (s2 - s > VESMAIL_NOW_REQ_SAFEBYTES) return VESMAIL_E_BUF;
	switch (s2 - s) {
	    case 1:
		if (*s != '\r') break;
	    case 0:
		req.hdr.end = s;
		body = s2 + 1;
		break;
	}
	s = s2 + 1;
	if (req.hdr.end) break;
	if (!req.hdr.start) req.hdr.start = s;
    }
    if (!req.hdr.end) return final ? VESmail_now_errorlog(xform->server, 400, "Unexpected end of headers\r\n", "-", NULL) : (*srclen = 0);
    if (!req.hdr.start) return VESmail_now_errorlog(xform->server, 400, "Invalid HTTP request\r\n", "-", NULL);
    char *d = req.method;
    for (s = src; ;) {
	char c = *s++;
	if (d >= req.method + sizeof(req.method) - 1 || s >= req.hdr.start) return VESmail_now_errorlog(xform->server, 400, "Invalid request line\r\n", "-", NULL);
	if (c >= 'a' && c <= 'z') *d++ = c - 0x20;
	else if (c == ' ') break;
	else *d++ = c;
    }
    *d = 0;
    req.uri.start = s;
    req.uri.end = memchr(s, ' ', req.hdr.start - s);
    if (!req.uri.end) return VESmail_now_errorlog(xform->server, 400, "Invalid HTTP request\r\n", req.method, NULL);
    req.uri.hash = memchr(s, '#', req.uri.end - s);
    if (!req.uri.hash) req.uri.hash = req.uri.end;
    req.uri.search = memchr(s, '?', req.uri.hash - s);
    if (!req.uri.search) req.uri.search = req.uri.hash;
    req.uri.path = memchr(s, '/', req.uri.search - s);
    if (req.uri.path) {
	if (req.uri.path > s && req.uri.path[-1] == ':' && req.uri.path < req.uri.search - 2 && req.uri.path[1] == '/') {
	    req.uri.path = memchr(req.uri.path + 2, '/', req.uri.search - req.uri.path - 2);
	    if (req.uri.path) req.uri.path++;
	    else req.uri.path = req.uri.search;
	} else req.uri.path++;
    } else req.uri.path = s;
    int (** reqfn)(VESmail_now_req *) = VESmail_now_CONF(xform->server, now.reqStack);
    int rs = VESMAIL_E_HOLD;
    if (reqfn) while (*reqfn) {
	rs = (*reqfn)(&req);
	if (rs != VESMAIL_E_HOLD) break;
	reqfn++;
    }
    if (rs == VESMAIL_E_HOLD) rs = VESmail_now_errorlog(xform->server, 405, "Not supported\r\n", req.method, NULL);
    else if (rs >= 0 && xform->chain) {
	int r = VESmail_now_process_chain(xform, final, body, tail - body);
	if (r < 0) rs = r;
	else rs += r;
    }
    VESmail_now_req_cleanup(&req);
    return rs;
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

void VESmail_now_fn_free(VESmail_server *srv, int final) {
    if (!final) return;
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
