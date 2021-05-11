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
#include <stdarg.h>
#include "../VESmail.h"
#include "../lib/xform.h"
#include "../lib/mail.h"
#include "../srv/server.h"
#include "smtp.h"
#include "smtp_start.h"
#include "smtp_proxy.h"
#include "smtp_reply.h"
#include "smtp_cmd.h"


int VESmail_smtp_cmd_match_verb(const char **cmd, const char *tail, const char **verbs) {
    char buf[32];
    const char *s;
    char *d = buf;
    char sp = 0;
    for (s = *cmd; s < tail; s++) {
	if (d >= buf + sizeof(buf)) return VESMAIL_E_UNKNOWN;
	char c = *s;
	switch (c) {
	    case ':':
		*d++ = c;
	    case ' ': case '\t': case '\r': case '\n':
		sp = 1;
		continue;
	    default:
		if (sp) break;
		*d++ = (c >= 'a' && c <= 'z' ? c - 0x20 : c);
		continue;
	}
	break;
    }
    *d = 0;
    const char **v;
    for (v = verbs; *v; v++) if (!strcmp(buf, *v)) {
	*cmd = s;
	return v - verbs;
    }
    return VESMAIL_E_UNKNOWN;
}

VESmail_smtp_cmd *VESmail_smtp_cmd_parse(VESmail_smtp_cmd *cmd) {
    static const char *subv_mail[] = {"FROM:", NULL};
    static const char *subv_rcpt[] = {"TO:", NULL};
    const char *s = cmd->head;
    const char *tail = s + cmd->len;
    int v = VESmail_smtp_cmd_match_verb(&s, tail, VESmail_smtp_verbs);
    const char **subv;
    switch (v) {
	case VESMAIL_SMTP_V_MAIL:
	    subv = subv_mail;
	    break;
	case VESMAIL_SMTP_V_RCPT:
	    subv = subv_rcpt;
	    break;
	default:
	    subv = NULL;
	    break;
    }
    if (subv && VESmail_smtp_cmd_match_verb(&s, tail, subv) < 0) v = VESMAIL_E_UNKNOWN;
    cmd->verb = v;
    cmd->arg = v >= 0 && s < tail ? s : NULL;
    return cmd;
}

const char *VESmail_smtp_cmd_get_eol(const VESmail_smtp_cmd *cmd) {
    if (!cmd) return NULL;
    const char *eol = cmd->head + cmd->len;
    if (eol > cmd->head && eol[-1] == '\n') eol--;
    if (eol > cmd->head && eol[-1] == '\r') eol--;
    return eol;
}

int VESmail_smtp_cmd_fwd(VESmail_server *srv, const char *cmd, int cmdlen) {
    return VESmail_xform_process(srv->req_out, 0, cmd, cmdlen);
}

int VESmail_smtp_cmd_fwda(VESmail_server *srv, const char *cmd, int argc, ...) {
    int rs = VESmail_smtp_cmd_fwd(srv, cmd, strlen(cmd));
    if (rs < 0) return rs;
    if (argc > 0) {
	va_list va;
	va_start(va, argc);
	int i, r;
	for (i = 0; i < argc; i++) {
	    const char *s = va_arg(va, const char *);
	    r = VESmail_smtp_cmd_fwd(srv, " ", 1);
	    if (r < 0) break;
	    rs += r;
	    r = VESmail_smtp_cmd_fwd(srv, s, strlen(s));
	    if (r < 0) break;
	    rs += r;
	}
	va_end(va);
	if (r < 0) return r;
    }
    int r = VESmail_smtp_cmd_fwd(srv, "\r\n", 2);
    if (r < 0) return r;
    return rs + r;
}

VESmail_smtp_cmd *VESmail_smtp_cmd_dup(const VESmail_smtp_cmd *cmd) {
    VESmail_smtp_cmd *cmd2 = malloc(sizeof(VESmail_smtp_cmd) + cmd->len);
    cmd2->head = cmd2->data;
    cmd2->len = cmd->len;
    cmd2->arg = cmd->arg ? cmd2->head + (cmd->arg - cmd->head) : NULL;
    cmd2->verb = cmd->verb;
    memcpy(cmd2->data, cmd->head, cmd->len);
    return cmd2;
}

int VESmail_smtp_data_xform_fn(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return *srclen = 0;
    const char *s = src;
    const char *s0 = s;
    const char *tail = s + *srclen;
    int rs = 0;
    int r;
    while (s < tail) {
	if (*s == '.' && !xform->offset) {
	    r = VESmail_xform_process(xform->chain, 0, s0, s - s0 + 1);
	    if (r < 0) return r;
	    rs += r;
	    s0 = s;
	}
	const char *lf = memchr(s, '\n', tail - s);
	if (lf) {
	    s = lf + 1;
	    xform->offset = 0;
	    if (s < tail) continue;
	} else {
	    xform->offset = 1;
	}
	r = VESmail_xform_process(xform->chain, 0, s0, tail - s0);
	if (r < 0) return r;
	rs += r;
	break;
    }
    if (final) {
	r = VESmail_xform_process(xform->chain, 0, "\r\n.\r\n", 5);
	if (r < 0) return r;
	rs += r;
    }
    return rs;
}

VESmail_xform *VESmail_xform_new_smtp_data(VESmail_server *srv) {
    VESmail_xform *xform = VESmail_xform_new(&VESmail_smtp_data_xform_fn, NULL, srv);
    xform->offset = 0;
    xform->chain = srv->req_out;
    return xform;
}

int VESmail_smtp_cmd_xform_fn(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    VESmail_server *srv = xform->server;
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    int rs = VESmail_smtp_start_ready(srv);
    if (rs < 0) return rs;
    const char *s = src;
    const char *s0 = s;
    const char *tail = src + *srclen;
    *srclen = 0;
    int (* cmdfn)(VESmail_server *, VESmail_smtp_cmd *);
    while (s < tail) {
	const char *lf = memchr(s, '\n', tail - s);
	int r;
	switch (smtp->state) {
	    case VESMAIL_SMTP_S_DATA: {
		if (lf) {
		    int endf;
		    if ((endf = (*s == '.'))) {
			const char *s1;
			for (s1 = s + 1; s1 < lf && endf; s1++) switch (*s1) {
			    case ' ': case '\t': case '\r':
				continue;
			    default:
				endf = 0;
				break;
			}
			if (endf) {
			    if (smtp->mail) {
				const char *eom = s;
				r = VESmail_convert(smtp->mail, NULL, 1, s0, eom - s0);
				if (r < 0) return r;
				rs += r;
				s0 = lf + 1;
			    }
			    VESmail_smtp_proxy_over(srv);
			} else if (smtp->mail && s[1] == '.') {
			    r = VESmail_convert(smtp->mail, NULL, 0, s0, s - s0 + 1);
			    if (r < 0) return r;
			    rs += r;
			    s0 = s + 2;
			}
		    }
		    s = lf + 1;
		    if (!endf && s < tail) continue;
		}
		if (s <= s0) {
		    cmdfn = NULL;
		    break;
		}
		r = (smtp->mail && smtp->state == VESMAIL_SMTP_S_DATA
		    ? VESmail_convert(smtp->mail, NULL, 0, s0, s - s0)
		    : VESmail_xform_process(srv->req_out, 0, s0, s - s0));
		if (r < 0) return r;
		rs += r;
		s0 = s;
		continue;
	    }
	    case VESMAIL_SMTP_S_INIT:
	    case VESMAIL_SMTP_S_START:
		cmdfn = &VESmail_smtp_start_cmd;
		break;
	    case VESMAIL_SMTP_S_PROXY:
		cmdfn = ((smtp->flags & VESMAIL_SMTP_F_PIPE) || !smtp->track) ? &VESmail_smtp_proxy_cmd : NULL;
		break;
	    case VESMAIL_SMTP_S_AUTH:
		if (lf) {
		    int r = VESmail_smtp_start_sasl(srv, s, lf - s - (lf > s && lf[-1] == '\r' ? 1 : 0));
		    if (r < 0) return r;
		    rs += r;
		    s = lf + 1;
		    continue;
		}
	    default:
		cmdfn = NULL;
		break;
	}
	if (!cmdfn) break;
	const char *endl;
	if (lf) {
	    endl = lf + 1;
	} else {
	    if (!final) {
		if (tail - s > VESMAIL_SMTP_CMD_SAFEBYTES) return VESMAIL_E_BUF;
		break;
	    }
	    endl = tail;
	}
	VESmail_smtp_cmd cmd = {
	    .head = s,
	    .len = endl - s
	};
	VESmail_smtp_cmd_parse(&cmd);
	r = cmdfn(srv, &cmd);
	s = endl;
	if (r < 0) return r;
	rs += r;
    }
    *srclen = s - src;
    if (final && !(srv->flags & VESMAIL_SRVF_SHUTDOWN)) {
	int r = (srv->flags & VESMAIL_SRVF_TMOUT)
	    ? VESmail_smtp_reply_sendln(srv, 420, 0, VESMAIL_SMTP_RF_FINAL, "Timeout")
	    : VESmail_smtp_reply_sendln(srv, 421, 0, VESMAIL_SMTP_RF_FINAL, "Closing the session");
	srv->flags |= VESMAIL_SRVF_SHUTDOWN;
	if (r < 0) return r;
	else rs += r;
    }
    return rs;
}

VESmail_xform *VESmail_xform_new_smtp_cmd(VESmail_server *srv) {
    VESmail_xform *xform = VESmail_xform_new(&VESmail_smtp_cmd_xform_fn, NULL, srv);
    return xform;
}

void VESmail_smtp_cmd_free(struct VESmail_smtp_cmd *cmd) {
    if (cmd && cmd->head == cmd->data) VESmail_cleanse(cmd->data, cmd->len);
    free(cmd);
}
