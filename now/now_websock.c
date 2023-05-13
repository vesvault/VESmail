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
#include <jVar.h>
#include "../VESmail.h"
#include "../srv/server.h"
#include "../lib/optns.h"
#include "../lib/xform.h"
#include "../lib/util.h"
#include "../srv/conf.h"
#include "../imap/imap.h"
#include "../smtp/smtp.h"
#include "now.h"
#include "now_websock.h"


int VESmail_now_xform_fn_websock_rx(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    const unsigned char *s = (const void *)src;
    const unsigned char *e = s + *srclen;
    *srclen = 0;
    int rs = 0;
    while (s < e) {
	if (e - s < 2) return rs;
	unsigned char hl = 2;
	unsigned char l = s[1] & 0x7f;
	unsigned char op = s[0] & 0x0f;
	if (s[1] & 0x80) hl += 4;
	unsigned char ll, li;
	unsigned long long len = 0;
	switch (l) {
	    case 0x7f:
		ll = 8;
		break;
	    case 0x7e:
		ll = 2;
		break;
	    default:
		len = l;
		ll = 0;
		break;
	}
	hl += ll;
	if (e - s < hl) break;
	for (li = 0; li < ll; li++) len = (len << 8) | s[li + 2];
	if (len > VESMAIL_WEBSOCK_MAX) {
	    rs = VESMAIL_E_BUF;
	    break;
	}
	if (e - s < len + hl) break;
	const unsigned char *msg = s + hl;
	unsigned char *mbuf = NULL;
	if (s[1] & 0x80) {
	    mbuf = malloc(len);
	    if (!mbuf) {
		rs = VESMAIL_E_INTERNAL;
		break;
	    }
	    int i;
	    const unsigned char *msk = msg - 4;
	    for (i = 0; i < len; i++) mbuf[i] = msg[i] ^ msk[i & 0x03];
	    msg = mbuf;
	}
	int r = (op <= 2 || op == 8) ? VESmail_xform_process(xform->chain, (op == 8), msg, len) : 0;
	free(mbuf);
	if (op == 8) final = 0;
	if (r < 0) {
	    rs = r;
	    break;
	}
	rs += r;
	*srclen += len + hl;
	s += l + hl;
    }
    if (final && rs >= 0) {
	int r = VESmail_xform_process(xform->chain, 1, "", 0);
	if (r < 0) rs = r;
	else rs += r;
    }
    return rs;
}

int VESmail_now_xform_fn_websock_tx(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    if (!final && *srclen < VESMAIL_WEBSOCK_OUT && (!*srclen || src[*srclen - 1] != '\n')) return *srclen = 0;
    const unsigned char *s = (const void *)src;
    const unsigned char *e = s + *srclen;
    unsigned char *sbuf = NULL;
    int rs = 0;
    while (s < e) {
	int len = e - s;
	if (len > VESMAIL_WEBSOCK_OUT) len = VESMAIL_WEBSOCK_OUT;
	if (!sbuf) sbuf = malloc(len + 4);
	if (!sbuf) return VESMAIL_E_BUF;
	sbuf[0] = ((s > (const unsigned char *)src) ? 0 : 2) | (e - s > len ? 0 : 0x80);
	unsigned char *msg = sbuf + 2;
	if (len >= 0x7e) {
	    sbuf[1] = 0x7e;
	    sbuf[2] = (len >> 8) & 0xff;
	    sbuf[3] = len & 0xff;
	    msg += 2;
	} else sbuf[1] = len;
	memcpy(msg, s, len);
	int r = VESmail_xform_process(xform->chain, 0, sbuf, msg - sbuf + len);
	if (r < 0) {
	    rs = r;
	    break;
	}
	rs += r;
	s += len;
    }
    free(sbuf);
    if (final && rs >= 0) {
	const char fin[2] = { 0x88, 0x00 };
	int r = VESmail_xform_process(xform->chain, 1, fin, sizeof(fin));
	if (r < 0) rs = r;
	else rs += r;
	xform->server->flags |= VESMAIL_SRVF_SHUTDOWN;
    }
    return rs;
}

const char *VESmail_now_websock_uuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

int VESmail_now_websock_reqStack(VESmail_now_req *req) {
    VESmail_server *now = req->xform->server;
    int tlen = req->uri.search - req->uri.path - 3;
    if (tlen < 1 || req->uri.path[0] != 'w' || req->uri.path[1] != 's' || req->uri.path[2] != '/') return VESMAIL_E_HOLD;
    const char *type = req->uri.path + 3;
    struct VESmail_now_hdr *h = NULL;
    char wskey[32];
    int ws = 0;
    wskey[0] = 0;
    while ((h = VESmail_now_req_header(req, h))) {
	if (!strcmp(h->key, "upgrade") && h->end - h->val >= 9 && !memcmp(h->val, "websocket", 9)) ws = 1;
	else if (!strcmp(h->key, "sec-websocket-key") && h->end - h->val < sizeof(wskey)) {
	    memcpy(wskey, h->val, h->end - h->val);
	    wskey[h->end - h->val] = 0;
	}
    }
    if (!ws) return VESmail_now_error(now, 426, "Missing websocket headers\n");
    char mdhdr[64];
    unsigned int shalen = 20;
    char *shabuf = mdhdr + sizeof(mdhdr) - shalen;
    void *mdctx = EVP_MD_CTX_create();
    if (wskey[0]
	&& EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL) > 0
	&& EVP_DigestUpdate(mdctx, wskey, strlen(wskey)) > 0
	&& EVP_DigestUpdate(mdctx, VESmail_now_websock_uuid, strlen(VESmail_now_websock_uuid)) > 0
	&& EVP_DigestFinal_ex(mdctx, shabuf, &shalen) > 0) {
	strcpy(mdhdr, "Sec-WebSocket-Accept: ");
	VESmail_b64encode(shabuf, shalen, mdhdr + strlen(mdhdr));
	strcat(mdhdr + 22, "\r\n");
    } else {
	mdhdr[0] = 0;
    }
    EVP_MD_CTX_destroy(mdctx);
    jVar *cf = jVar_getl(VESmail_now_CONF(now, now.websock), type, tlen);
    if (!cf) return VESmail_now_errorlog(req->xform->server, 404, "Invalid service\n", req->method, "websock", jVar_toJSON(VESmail_now_CONF(now, now.websock)), NULL);
    if (VESmail_server_connect(now, cf, NULL) < 0) return VESmail_now_errorlog(req->xform->server, 502, "Websock connection failed\n", req->method, NULL);
    req->xform->chain = VESmail_xform_new(&VESmail_now_xform_fn_websock_rx, now->req_out, now);
    now->rsp_in = VESmail_xform_new(&VESmail_now_xform_fn_websock_tx, now->rsp_out, now);
    now->idlefn = NULL;
    char *fwdaddr = VESmail_server_sockname(now, 3);
    char *clnaddr = VESmail_server_sockname(now, 2);
    VESmail_now_log(now, req->method, 101, "fwd", fwdaddr, "cln", clnaddr, NULL);
    free(clnaddr);
    free(fwdaddr);
    int rs = VESmail_now_send_status(now, 101);
    if (rs < 0) return rs;
    int r = VESmail_now_send(now, 0, "Upgrade: websocket\r\n" "Connection: Upgrade\r\n");
    if (r < 0) return r;
    rs += r;
    r = VESmail_now_send(now, 0, mdhdr);
    if (r < 0) return r;
    rs += r;
    r = VESmail_now_send(now, 0, "\r\n");
    if (r < 0) return r;
    rs += r;
    return rs;
}
