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
#include "../VESmail.h"
#include "../lib/xform.h"
#include "../srv/server.h"
#include "smtp.h"
#include "smtp_track.h"
#include "smtp_reply.h"

int VESmail_smtp_reply_sendl(VESmail_server *srv, int code, int dsn, int flags, const char *str, int len) {
    int rs = (flags & VESMAIL_SMTP_RF_NODEBUG) ? 0 : VESmail_smtp_debug_flush(srv, code, dsn);
    if (rs < 0) return rs;
    int r;
    if (code > 0 && !(flags & VESMAIL_SMTP_RF_NOCODE)) {
	char head[16];
	char f = (flags & VESMAIL_SMTP_RF_FINAL) ? ' ' : '-';
	sprintf(head, "%03d%c", code, f);
	if (dsn > 0) sprintf(head + 4, "%d.%d.%d ", dsn >> 12, (dsn >> 8) & 0x0f, dsn & 0xff);
	r = VESmail_xform_process(srv->rsp_out, 0, head, strlen(head));
	if (r < 0) return r;
	rs += r;
    }
    if (len > 0) {
	r = VESmail_xform_process(srv->rsp_out, 0, str, len);
	if (r < 0) return r;
	rs += r;
    }
    if (!(flags & VESMAIL_SMTP_RF_NOEOL)) {
	r = VESmail_xform_process(srv->rsp_out, 0, "\r\n", 2);
	if (r < 0) return r;
	rs += r;
    }
    return rs;
}

int VESmail_smtp_reply_sendml(VESmail_server *srv, int code, int dsn, int flags, const char *str, int len) {
    const char *s = str;
    const char *tail = s + len;
    int rs = 0;
    while (s <= tail) {
	const char *lf = s < tail ? memchr(s, '\n', tail - s) : NULL;
	int r;
	if (lf) {
	    lf++;
	    r = VESmail_smtp_reply_sendl(srv, code, dsn, (flags & ~VESMAIL_SMTP_RF_FINAL) | VESMAIL_SMTP_RF_NOEOL, s, lf - s);
	    s = lf;
	} else {
	    r = VESmail_smtp_reply_sendl(srv, code, dsn, flags, s, tail - s);
	    s = tail + 1;
	}
	if (r < 0) return r;
	rs += r;
    }
    return rs;
}


int VESmail_smtp_reply_xform_fn(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    VESmail_smtp_reply reply;
    VESmail_server *srv = xform->server;
    int rs = 0;
    const char *s = src;
    reply.head = s;
    const char *tail = src + *srclen;
    *srclen = 0;
    while (s < tail) {
	const char *lf = memchr(s, '\n', tail - s);
	const char *endl;
	if (lf) {
	    endl = lf + 1;
	} else {
	    if (!final) {
		if (tail - reply.head > VESMAIL_SMTP_REPLY_SAFEBYTES) return VESMAIL_E_BUF;
		break;
	    }
	    endl = tail;
	}
	if (endl - s > 3 && s[0] >= '0' && s[0] <= '9' && s[1] >= '0' && s[1] <= '9' && s[2] >= '0' && s[2] <= '9') switch (s[3]) {
	    case ' ': {
		reply.code = ((s[0] - '0') * 10 + s[1] - '0') * 10 + s[2] - '0';
		reply.dsn = 0;
		const char *s1 = s + 4;
		const char *sp = memchr(s1, ' ', (endl > s1 + 12 ? 12 : endl - s1));
		if (sp) {
		    char buf[16];
		    memcpy(buf, s1, sp - s1);
		    buf[sp - s1] = 0;
		    int d, s, n;
		    char _endc;
		    if (sscanf(buf, "%u.%u.%u%c", &d, &s, &n, &_endc) == 3 && d > 0 && d < 8 && s >= 0 && s < 16 && n >= 0 && n < 256) {
			reply.dsn = (((d << 4) | s) << 8) | n;
		    }
		}
		break;
	    }
	    case '-':
		if (!final) {
		    s = endl;
		    continue;
		}
	    default:
		reply.code = 0;
		break;
	} else {
	    reply.code = 0;
	}
	if (!reply.code) reply.dsn = 0;
	reply.len = endl - reply.head;
	int r = VESmail_smtp_track_reply(srv, &reply);
	if (r < 0) return r;
	if (!VESMAIL_SMTP(srv)->track) srv->flags &= ~VESMAIL_SRVF_OVER;
	rs += r;
	reply.head = s = endl;
	*srclen = s - src;
    }
    if (final) srv->flags |= VESMAIL_SRVF_SHUTDOWN;
    return rs;
}

const char *VESmail_smtp_reply_get_text(VESmail_smtp_reply *reply, const char *eol) {
    const char *txt;
    const char *tail = reply->head + reply->len;
    if (eol) {
	txt = eol;
	if (txt < tail && *txt == '\r') txt++;
	if (txt < tail && *txt == '\n') txt++;
    } else {
	txt = reply->head;
    }
    txt += 4;
    if (reply->dsn > 0) {
	while (txt < tail && *txt++ != ' ');
    }
    return txt > tail ? NULL : txt;
}

const char *VESmail_smtp_reply_get_eol(VESmail_smtp_reply *reply, const char *text) {
    const char *tail = reply->head + reply->len;
    const char *lf = text ? memchr(text, '\n', tail - text) : NULL;
    const char *eol;
    if (lf) {
	eol = lf;
    } else {
	eol = tail;
	if (eol > reply->head && eol[-1] == '\n') eol--;
    }
    if (eol > reply->head && eol[-1] == '\r') eol--;
    return eol >= text ? eol : NULL;
}


VESmail_xform *VESmail_xform_new_smtp_reply(VESmail_server *srv) {
    VESmail_xform *xform = VESmail_xform_new(&VESmail_smtp_reply_xform_fn, NULL, srv);
    return xform;
}
