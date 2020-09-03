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
#include <libVES.h>
#include <libVES/User.h>
#include <libVES/List.h>
#include <libVES/VaultItem.h>
#include "../VESmail.h"
#include "../lib/mail.h"
#include "../lib/optns.h"
#include "../lib/util.h"
#include "../lib/xform.h"
#include "../lib/header.h"
#include "../srv/server.h"
#include "../srv/arch.h"
#include "../now/now_store.h"
#include "smtp.h"
#include "smtp_cmd.h"
#include "smtp_reply.h"
#include "smtp_track.h"
#include "smtp_start.h"
#include "smtp_proxy.h"


#define VESMAIL_SMTP_SENDLN(srv, code, dsn, flags, msg, rs)	{\
    int r = VESmail_smtp_reply_sendln(srv, code, dsn, flags, msg);\
    if (r < 0) return r;\
    rs += r;\
}

void VESmail_smtp_proxy_reset(VESmail_server *srv) {
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    VESmail_free(smtp->mail);
    smtp->mail = NULL;
    smtp->flags &= ~VESMAIL_SMTP_F_PLAIN;
}

void VESmail_smtp_proxy_plain(VESmail_server *srv) {
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    if (smtp->mail) {
	smtp->mail->flags |= VESMAIL_F_PASS;
    }
    smtp->flags |= VESMAIL_SMTP_F_PLAIN;
}

int VESmail_smtp_proxy_replyw(VESmail_server *srv, VESmail_smtp_reply *reply) {
    int rs = (reply->code < 400 && (VESMAIL_SMTP(srv)->flags & VESMAIL_SMTP_F_PLAIN) && !(VESMAIL_SMTP(srv)->flags & VESMAIL_SMTP_F_NOWARN))
	? VESmail_smtp_reply_sendln(srv, reply->code, reply->dsn, 0, "VESmail WARNING: This email will NOT be encypted")
	: 0;
    if (rs < 0) return rs;
    int r = VESmail_smtp_reply_send(srv, reply);
    if (r < 0) return r;
    return rs + r;
}

int VESmail_smtp_proxy_fn_r(VESmail_smtp_track *trk, VESmail_smtp_reply *reply) {
    if (reply->code == 221) trk->server->flags |= VESMAIL_SRVF_SHUTDOWN;
    return VESmail_smtp_reply_send(trk->server, reply);
}

int VESmail_smtp_proxy_fn_r_mail(VESmail_smtp_track *trk, VESmail_smtp_reply *reply) {
    VESmail_server *srv = trk->server;
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    if (reply->code == 250) {
	VESmail_free(smtp->mail);
	smtp->mail = VESmail_set_out(VESmail_now_store_apply(VESmail_new_encrypt(srv->ves, srv->optns)), VESmail_xform_new_smtp_data(srv));
	smtp->mail->logfn = &VESmail_arch_log;
	smtp->mail->flags &= ~(VESMAIL_O_XCHG | VESMAIL_O_HDR_RCPT);
	if (smtp->mode <= VESMAIL_SMTP_M_XCHG) smtp->mail->flags |= VESMAIL_O_XCHG;
	if (smtp->mode == VESMAIL_SMTP_M_PLAIN || (smtp->flags & VESMAIL_SMTP_F_PLAIN)) VESmail_smtp_proxy_plain(srv);
    }
    return VESmail_smtp_proxy_replyw(srv, reply);
}

int VESmail_smtp_proxy_fn_u_qreply(VESmail_smtp_track *trk) {
    const VESmail_smtp_reply *re = trk->ref;
    return VESmail_smtp_reply_sendml(trk->server, re->code, re->dsn, VESMAIL_SMTP_RF_FINAL, re->head, strlen(re->head));
}

int VESmail_smtp_proxy_qreply(VESmail_server *srv, const VESmail_smtp_reply *re) {
    VESmail_smtp_track *trk = VESmail_smtp_track_new(srv, NULL);
    trk->ref = (void *) re;
    trk->unqfn = &VESmail_smtp_proxy_fn_u_qreply;
    return VESmail_smtp_track_unqueue(trk);
}

int VESmail_smtp_proxy_fn_r_rcpt(VESmail_smtp_track *trk, VESmail_smtp_reply *reply) {
    VESmail_server *srv = trk->server;
    if (reply->code == 250 && VESMAIL_SMTP(srv)->mail) {
	libVES_User *u = trk->ref;
	if (u) {
	    int r = VESmail_add_rcpt(VESMAIL_SMTP(srv)->mail, u->email, 0);
	    VESMAIL_SRV_DEBUG(srv, 1, sprintf(debug, "add rcpt: %s r=%d", u->email, r))
	}
    }
    return VESmail_smtp_proxy_replyw(srv, reply);
}

void VESmail_smtp_proxy_fn_f_rcpt(VESmail_smtp_track *trk) {
    libVES_User_free(trk->ref);
}

int VESmail_smtp_proxy_fn_r_over(VESmail_smtp_track *trk, VESmail_smtp_reply *reply) {
    VESmail_server *srv = trk->server;
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    smtp->state = VESMAIL_SMTP_S_PROXY;
    int rs = 0;
    if (smtp->mail && !(smtp->mail->flags & VESMAIL_F_PASS)) {
	char *uri = libVES_VaultItem_toURI(VESmail_get_vaultItem(smtp->mail));
	rs = VESmail_smtp_reply_sendln(srv, reply->code, reply->dsn, 0, (uri ? uri : "ves:????"));
	free(uri);
	if (rs < 0) return rs;
    }
    VESmail_smtp_proxy_reset(srv);
    int r = VESmail_smtp_reply_send(srv, reply);
    if (r < 0) return r;
    return rs + r;
}

int VESmail_smtp_proxy_cmd_rcpt(VESmail_server *srv, VESmail_smtp_cmd *cmd) {
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    libVES_User *u;
    if (!(smtp->flags & VESMAIL_SMTP_F_PLAIN)) {
	const char *p = cmd->arg;
	if (!p) {
	    static const VESmail_smtp_reply re = {
		.code = 501,
		.dsn = 0,
		.head = "Recipient missing."
	    };
	    return VESmail_smtp_proxy_qreply(srv, &re);
	}
	u = libVES_User_fromPath(&p);
	if (!u) {
	    static const VESmail_smtp_reply re = {
		.code = 501,
		.dsn = 0,
		.head = "VESmail recipient is unparsable."
	    };
	    return VESmail_smtp_proxy_qreply(srv, &re);
	}
	switch (smtp->mode) {
	    case VESMAIL_SMTP_M_REJECT:
	    case VESMAIL_SMTP_M_FALLBACK: {
		libVES_List *l = libVES_User_activeVaultKeys(u, NULL, srv->ves);
		libVES_List_free(l);
		if (l) break;
		if (smtp->mode == VESMAIL_SMTP_M_REJECT) {
		    static const VESmail_smtp_reply re = {
			.code = 450,
			.dsn = 0x4100,
			.head = "VESmail user is not on VESvault yet, relaying denied."
		    };
		    return VESmail_smtp_proxy_qreply(srv, &re);
		} else {
		    VESmail_smtp_proxy_plain(srv);
		}
	    }
	    default:
		break;
	}
    } else {
	u = NULL;
    }
    VESmail_smtp_track *trk = VESmail_smtp_track_new(srv, &VESmail_smtp_proxy_fn_r_rcpt);
    trk->freefn = &VESmail_smtp_proxy_fn_f_rcpt;
    trk->ref = u;
    return VESmail_smtp_cmd_send(srv, cmd);
}

int VESmail_smtp_proxy_fn_r_data(VESmail_smtp_track *trk, VESmail_smtp_reply *reply) {
    VESmail_server *srv = trk->server;
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    if (reply->code == 354) {
	smtp->state = VESMAIL_SMTP_S_DATA;
	if (smtp->mail) {
	    VESmail_header *rcvd = VESmail_header_new("Received:", VESMAIL_H_RCVD, 512);
	    char *sock = VESmail_server_sockname(srv, 0);
	    char *peer = VESmail_server_sockname(srv, 1);
	    char *tstamp = VESmail_server_timestamp();
	    sprintf(rcvd->data + rcvd->len, "from %s (helo=%.80s)%s\tby %s (%s) with %s (encrypt=%s mode=%s);%s\t%s%s",
		peer,
		smtp->helo,
		smtp->lf,
		sock,
		srv->host,
		VESMAIL_SHORT_NAME " ESMTP Proxy " VESMAIL_VERSION,
		((smtp->flags & VESMAIL_SMTP_F_PLAIN) ? "FALSE" : "TRUE"),
		VESmail_smtp_modes[smtp->mode],
		smtp->lf,
		tstamp,
		smtp->lf
	    );
	    free(sock);
	    free(peer);
	    free(tstamp);
	    rcvd->len += strlen(rcvd->data + rcvd->len);
	    rcvd->chain = NULL;
	    VESmail_inject_header(smtp->mail, rcvd);
	}
    } else {
	VESMAIL_SMTP(srv)->state = VESMAIL_SMTP_S_PROXY;
    }
    return VESmail_smtp_reply_send(srv, reply);
}

int VESmail_smtp_proxy_fn_u_start(VESmail_smtp_track *trk) {
    return VESmail_smtp_start_cmd(trk->server, trk->ref);
}

void VESmail_smtp_proxy_fn_f_start(VESmail_smtp_track *trk) {
    VESmail_smtp_cmd_free(trk->ref);
}

int VESmail_smtp_proxy_scmd(VESmail_server *srv, VESmail_smtp_cmd *cmd) {
    VESmail_smtp_cmd *cmd2 = VESmail_smtp_cmd_dup(cmd);
    VESmail_smtp_track *trk = VESmail_smtp_track_new(srv, NULL);
    trk->ref = cmd2;
    trk->unqfn = VESmail_smtp_proxy_fn_u_start;
    trk->freefn = VESmail_smtp_proxy_fn_f_start;
    return VESmail_smtp_track_unqueue(trk);
}

int VESmail_smtp_proxy_cmd(VESmail_server *srv, VESmail_smtp_cmd *cmd) {
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    switch (cmd->verb) {
	case VESMAIL_SMTP_V_RSET:
	case VESMAIL_SMTP_V_QUIT:
	    VESmail_smtp_track_new(srv, &VESmail_smtp_proxy_fn_r);
	    break;
	case VESMAIL_SMTP_V_MAIL:
	    VESmail_smtp_track_new(srv, &VESmail_smtp_proxy_fn_r_mail);
	    break;
	case VESMAIL_SMTP_V_RCPT:
	    return VESmail_smtp_proxy_cmd_rcpt(srv, cmd);
	case VESMAIL_SMTP_V_DATA:
	    smtp->state = VESMAIL_SMTP_S_HOLD;
	    VESmail_smtp_track_new(srv, &VESmail_smtp_proxy_fn_r_data);
	    break;
	case VESMAIL_SMTP_V_AUTH:
	case VESMAIL_SMTP_V_STARTTLS: {
	    static const VESmail_smtp_reply re = {
		.code = 503,
		.dsn = 0,
		.head = "Not allowed in this context."
	    };
	    return VESmail_smtp_proxy_qreply(srv, &re);
	}
	default:
	    return VESmail_smtp_proxy_scmd(srv, cmd);
    }
    return VESmail_smtp_cmd_send(srv, cmd);
}

void VESmail_smtp_proxy_over(VESmail_server *srv) {
    VESMAIL_SMTP(srv)->state = VESMAIL_SMTP_S_HOLD;
    VESmail_smtp_track_new(srv, &VESmail_smtp_proxy_fn_r_over);
}
