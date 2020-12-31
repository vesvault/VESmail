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
#include "../VESmail.h"
#include "../lib/util.h"
#include "../lib/xform.h"
#include "../srv/server.h"
#include "../srv/tls.h"
#include "../srv/sasl.h"
#include "smtp.h"
#include "smtp_cmd.h"
#include "smtp_reply.h"
#include "smtp_track.h"
#include "smtp_xves.h"
#include "smtp_start.h"


#define VESMAIL_SMTP_SENDLN(srv, code, dsn, flags, msg, rs)	{\
    int r = VESmail_smtp_reply_sendln(srv, code, dsn, flags, msg);\
    if (r < 0) return r;\
    rs += r;\
}

int VESmail_smtp_start_ready(VESmail_server *srv) {
    if (VESMAIL_SMTP(srv)->state != VESMAIL_SMTP_S_HELLO) return 0;
    VESMAIL_SMTP(srv)->state = VESMAIL_SMTP_S_INIT;
    int rs = 0;
    VESMAIL_SMTP_SENDLN(srv, 220, 0, VESMAIL_SMTP_RF_FINAL | VESMAIL_SMTP_RF_NOEOL, srv->host, rs)
    VESMAIL_SMTP_SENDLN(srv, 0, 0, 0, " ESMTP VESmail ready.", rs)
    return rs;
}

int VESmail_smtp_start_login_fail(VESmail_server *srv, const char *msg, VESmail_smtp_reply *relayed) {
    VESMAIL_SMTP(srv)->state = VESMAIL_SMTP_S_START;
    int rs = 0;
    if (msg) {
	VESMAIL_SMTP_SENDLN(srv, 454, 0x4700, (relayed ? 0 : VESMAIL_SMTP_RF_FINAL), msg, rs)
    }
    if (relayed) {
	VESMAIL_SMTP_SENDLN(srv, 454, 0x4700, 0, "Response from the remote server", rs);
	int r = VESmail_smtp_reply_sendml(srv, 454, 0x4700, VESMAIL_SMTP_RF_FINAL, relayed->head, relayed->len);
	if (r < 0) return r;
	rs += r;
    }
    VESmail_server_disconnect(srv);
    return rs;
}

int VESmail_smtp_fwd_ehlo(VESmail_server *srv);
int VESmail_smtp_fwd_starttls(VESmail_server *srv);
int VESmail_smtp_fwd_login(VESmail_server *srv);

int VESmail_smtp_start_fn_r_ehlo(VESmail_smtp_track *trk, VESmail_smtp_reply *reply) {
    VESmail_server *srv = trk->server;
    if (reply->code == 250) {
	const char *txt, *eol, *auth = NULL, *authtail;
	int ftls = 0;
	for (
	    eol = VESmail_smtp_reply_get_eol(reply, reply->head);
	    (txt = VESmail_smtp_reply_get_text(reply, eol));
	) {
	    eol = VESmail_smtp_reply_get_eol(reply, txt);
	    switch (VESmail_smtp_cmd_match_verb(&txt, eol, VESmail_smtp_verbs)) {
		case VESMAIL_SMTP_V_XVES:
		    return VESmail_smtp_start_login_fail(srv, "Forbidden remote capability XVES", NULL);
		case VESMAIL_SMTP_V_STARTTLS:
		    ftls = 1;
		    break;
		case VESMAIL_SMTP_V_PIPELINING:
		    VESMAIL_SMTP(srv)->flags |= VESMAIL_SMTP_F_PIPE;
		    break;
		case VESMAIL_SMTP_V_AUTH:
		    auth = txt;
		    authtail = eol;
		default:
		    break;
	    }
	}
	if (VESmail_tls_client_started(srv)) {
	    ftls = 0;
	} else if (VESmail_tls_client_require(srv)) {
	    ftls = 1;
	}
	if (ftls) {
	    return VESmail_smtp_fwd_starttls(srv);
	} else {
	    while (!srv->sasl && auth && auth < authtail) {
		int m = VESmail_smtp_cmd_match_verb(&auth, authtail, VESmail_sasl_mechs);
		if (m < 0) {
		    auth = memchr(auth, ' ', authtail - auth);
		    if (auth) auth++;
		    continue;
		}
		srv->sasl = VESmail_server_sasl_client(m, VESMAIL_SMTP(srv)->uconf);
	    }
	    return VESmail_smtp_fwd_login(srv);
	}
    }
    return VESmail_smtp_start_login_fail(srv, NULL, reply);
}

int VESmail_smtp_start_fn_r_conn(VESmail_smtp_track *trk, VESmail_smtp_reply *reply) {
    if (reply->code == 220) {
	return VESmail_smtp_fwd_ehlo(trk->server);
    }
    return VESmail_smtp_start_login_fail(trk->server, NULL, reply);
}

int VESmail_smtp_start_fn_r_starttls(VESmail_smtp_track *trk, VESmail_smtp_reply *reply) {
    if (reply->code == 220) {
	int rs = VESmail_tls_client_start(trk->server, 1);
	if (rs >= 0) {
	    int r = VESmail_smtp_fwd_ehlo(trk->server);
	    if (r < 0) return r;
	    rs += r;
	}
	return rs;
    }
    return VESmail_smtp_start_login_fail(trk->server, NULL, reply);
}

int VESmail_smtp_start_fn_r_auth(VESmail_smtp_track *trk, VESmail_smtp_reply *reply) {
    VESmail_server *srv = trk->server;
    switch (reply->code) {
	case 235:
	    VESMAIL_SMTP(srv)->state = VESMAIL_SMTP_S_PROXY;
	    VESmail_sasl_free(srv->sasl);
	    srv->sasl = NULL;
	    return VESmail_smtp_reply_send(srv, reply);
	case 334: {
	    const char *h = VESmail_smtp_reply_get_text(reply, NULL);
	    const char *t = VESmail_smtp_reply_get_eol(reply, NULL);
	    if (h && t) {
		char *tk = VESmail_sasl_process(srv->sasl, h, t - h);
		if (tk) {
		    VESmail_smtp_track_new(srv, &VESmail_smtp_start_fn_r_auth);
		    int rs = VESmail_smtp_cmd_fwda(srv, tk, 0);
		    free(tk);
		    return rs;
		}
	    }
	}
    }
    return VESmail_smtp_start_login_fail(trk->server, NULL, reply);
}

int VESmail_smtp_fwd_ehlo(VESmail_server *srv) {
    VESmail_smtp_track_new(srv, &VESmail_smtp_start_fn_r_ehlo);
    return VESmail_smtp_cmd_fwda(srv, "EHLO", 1, VESMAIL_SMTP(srv)->helo);
}

int VESmail_smtp_fwd_starttls(VESmail_server *srv) {
    VESmail_smtp_track_new(srv, &VESmail_smtp_start_fn_r_starttls);
    return VESmail_smtp_cmd_fwda(srv, "STARTTLS", 0);
}

int VESmail_smtp_fwd_login(VESmail_server *srv) {
    if (!srv->sasl) return VESmail_smtp_start_login_fail(srv, "SASL is not available on remote SMTP host", NULL);
    VESmail_smtp_track_new(srv, &VESmail_smtp_start_fn_r_auth);
    char *ir = VESmail_sasl_process(srv->sasl, NULL, 0);
    int rs = VESmail_smtp_cmd_fwda(srv, "AUTH", (ir ? 2 : 1), VESmail_sasl_get_name(srv->sasl), ir);
    free(ir);
    return rs;
}

int VESmail_smtp_auth(VESmail_server *srv, const char *user, const char *pwd, int pwlen) {
    int r = VESmail_server_auth(srv, user, pwd, pwlen);
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    if (r >= 0) r = VESmail_server_connect(srv, (smtp->uconf = jVar_get(srv->uconf, "smtp")), "smtp");
    if (r >= 0) {
	smtp->state = VESMAIL_SMTP_S_CONN;
	jVar *jmode = jVar_get(smtp->uconf, "mode");
	if (jmode) {
	    const char *s = jmode->vString;
	    int mode = VESmail_smtp_cmd_match_verb(&s, s + jmode->len, VESmail_smtp_modes);
	    VESMAIL_SRV_DEBUG(srv, 1, sprintf(debug, "[conf] SMTP mode = %d", mode))
	    if (mode >= 0) smtp->mode = mode;
	}
	VESmail_smtp_track_new(srv, &VESmail_smtp_start_fn_r_conn);
    }
    return r;
}

int VESmail_smtp_start_sasl(VESmail_server *srv, const char *auth, int authl) {
    VESmail_sasl *sasl = srv->sasl;
    if (!sasl) return VESMAIL_E_PARAM;
    char *chlg = VESmail_sasl_process(sasl, auth, authl);
    if (chlg) {
	VESMAIL_SMTP(srv)->state = VESMAIL_SMTP_S_AUTH;
	int rs = VESmail_smtp_reply_sendln(srv, 334, 0, VESMAIL_SMTP_RF_FINAL, chlg);
	free(chlg);
	return rs;
    }
    int rs = VESMAIL_E_SASL;
    if (VESmail_sasl_authd(sasl)) {
	rs = VESmail_smtp_auth(srv, sasl->user, sasl->passwd, sasl->pwlen);
    }
    if (rs < 0) {
	char *err = VESmail_server_errorStr(srv, rs);
	rs = VESmail_smtp_start_login_fail(srv, err, NULL);
	free(err);
    }
    return rs;
}

int VESmail_smtp_start_ehlo(VESmail_server *srv, VESmail_smtp_cmd *cmd) {
    if (!cmd->arg) return VESmail_smtp_reply_sendln(srv, 501, 0, VESMAIL_SMTP_RF_FINAL, "Hostname missing");
    const char *eol = VESmail_smtp_cmd_get_eol(cmd);
    int l = eol - cmd->arg;
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    smtp->lf = eol + 1 == cmd->head + cmd->len ? "\n" : "\r\n";
    free(smtp->helo);
    smtp->helo = malloc(l + 1);
    memcpy(smtp->helo, cmd->arg, l);
    smtp->helo[l] = 0;
    int ehlo = cmd->verb == VESMAIL_SMTP_V_EHLO;
    int rs = 0;
    VESMAIL_SMTP_SENDLN(srv, 250, 0, ((ehlo ? 0 : VESMAIL_SMTP_RF_FINAL) | VESMAIL_SMTP_RF_NOEOL), srv->host, rs)
    VESMAIL_SMTP_SENDLN(srv, 0, 0, VESMAIL_SMTP_RF_NOEOL, " VESmail hello ", rs)
    VESMAIL_SMTP_SENDLN(srv, 0, 0, 0, smtp->helo, rs)
    if (ehlo) {
	VESMAIL_SMTP_SENDLN(srv, 250, 0, 0, "8BITMIME", rs)
	VESMAIL_SMTP_SENDLN(srv, 250, 0, 0, "PIPELINING", rs)
	if (VESmail_tls_server_allow_starttls(srv)) VESMAIL_SMTP_SENDLN(srv, 250, 0, 0, "STARTTLS", rs)
	if (VESmail_tls_server_allow_plain(srv)) {
	    VESMAIL_SMTP_SENDLN(srv, 250, 0, VESMAIL_SMTP_RF_NOEOL, "AUTH", rs)
	    int i;
	    for (i = 0; i <= VESMAIL_SASL_SRV_LAST; i++) {
		VESMAIL_SMTP_SENDLN(srv, 0, 0, VESMAIL_SMTP_RF_NOEOL, " ", rs)
		VESMAIL_SMTP_SENDLN(srv, 0, 0, (i == VESMAIL_SASL_SRV_LAST ? 0 : VESMAIL_SMTP_RF_NOEOL), VESmail_sasl_mechs[i], rs)
	    }
	}
	VESMAIL_SMTP_SENDLN(srv, 250, 0, 0, "HELP", rs)
	VESMAIL_SMTP_SENDLN(srv, 250, 0, VESMAIL_SMTP_RF_FINAL, "XVES", rs)
    }
    return rs;
}

int VESmail_smtp_start_help(VESmail_server *srv, VESmail_smtp_cmd *cmd) {
    return VESmail_smtp_reply_sendln(srv, 214, 0, VESMAIL_SMTP_RF_FINAL, "https://mail.ves.world");
}

int VESmail_smtp_start_cmd(VESmail_server *srv, VESmail_smtp_cmd *cmd) {
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    switch (cmd->verb) {
	case VESMAIL_SMTP_V_EHLO:
	case VESMAIL_SMTP_V_HELO:
	    return VESmail_smtp_start_ehlo(srv, cmd);
	case VESMAIL_SMTP_V_MAIL:
	case VESMAIL_SMTP_V_RCPT:
	case VESMAIL_SMTP_V_DATA:
	    return VESmail_smtp_reply_sendln(srv, 503, 0, VESMAIL_SMTP_RF_FINAL, "Use EHLO and AUTH first");
	case VESMAIL_SMTP_V_AUTH: {
	    if (!smtp->helo) return VESmail_smtp_reply_sendln(srv, 503, 0, VESMAIL_SMTP_RF_FINAL, "Use EHLO first");
	    const char *auth = cmd->arg;
	    const char *tail = cmd->head + cmd->len;
	    VESmail_sasl_free(srv->sasl);
	    srv->sasl = NULL;
	    if (!auth || !(srv->sasl = VESmail_sasl_new_server(VESmail_smtp_cmd_match_verb(&auth, tail, VESmail_sasl_mechs)))) {
		return VESmail_smtp_reply_sendln(srv, 501, 0, VESMAIL_SMTP_RF_FINAL, "Unknown SASL mechanism");
	    }
	    int authl = auth ? VESmail_smtp_cmd_get_eol(cmd) - auth : 0;
	    return VESmail_smtp_start_sasl(srv, (authl > 0 ? auth : NULL), authl);
	}
	case VESMAIL_SMTP_V_HELP:
	    return VESmail_smtp_start_help(srv, cmd);
	case VESMAIL_SMTP_V_STARTTLS: {
	    if (!VESmail_tls_server_allow_starttls(srv)) {
		return VESmail_smtp_reply_sendln(srv, 503, 0, VESMAIL_SMTP_RF_FINAL, "Not allowed in this context");
	    }
	    int rs = VESmail_smtp_reply_sendln(srv, 220, 0, VESMAIL_SMTP_RF_FINAL, "Begin TLS negotiation");
	    if (rs < 0) return rs;
	    int r = VESmail_tls_server_start(srv, 1);
	    if (r < 0) return r;
	    return rs + r;
	}
	case VESMAIL_SMTP_V_RSET:
	case VESMAIL_SMTP_V_VRFY:
	case VESMAIL_SMTP_V_NOOP:
	    return VESmail_smtp_reply_sendln(srv, 250, 0, VESMAIL_SMTP_RF_FINAL, "Ok");
	case VESMAIL_SMTP_V_XVES:
	    return VESmail_smtp_xves(srv, cmd);
	case VESMAIL_SMTP_V_QUIT:
	    srv->flags |= VESMAIL_SRVF_SHUTDOWN;
	    return VESmail_smtp_reply_sendln(srv, 221, 0, VESMAIL_SMTP_RF_FINAL, "VESmail ESMTP session is over.");
	default:
	    break;
    }
    return VESmail_smtp_reply_sendln(srv, 500, 0, VESMAIL_SMTP_RF_FINAL, "Unsupported command");
}

