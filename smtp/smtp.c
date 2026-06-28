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
 * (c) 2020-2026 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * Apache License, Version 2.0
 * You may use, copy, modify, merge, publish, distribute and/or sell copies
 * of the Software under the terms of the Apache License, Version 2.0, a copy
 * of which is provided in the COPYING file, or http://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
 *
 ***************************************************************************/

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <jVar.h>
#include "../VESmail.h"
#include "../lib/xform.h"
#include "../lib/mail.h"
#include "../lib/optns.h"
#include "../srv/server.h"
#include "../srv/tls.h"
#include "smtp_cmd.h"
#include "smtp_reply.h"
#include "smtp_track.h"
#include "smtp.h"


#define VESMAIL_VERB(verb)	#verb,
const char *VESmail_smtp_verbs[] = { VESMAIL_SMTP_VERBS() NULL };
const char *VESmail_smtp_modes[] = { VESMAIL_SMTP_MODES() NULL };
#undef VESMAIL_VERB

void VESmail_smtp_debug(VESmail_server *srv, const char *msg) {
    struct VESmail_smtp_debug *dbg = malloc(sizeof(*dbg) + strlen(msg));
    dbg->chain = NULL;
    sprintf(dbg->msg, "[DEBUG] %s", msg);
    struct VESmail_smtp_debug **ptr = &VESMAIL_SMTP(srv)->debug;
    while (*ptr) ptr = &(*ptr)->chain;
    *ptr = dbg;
    if (VESMAIL_SMTP(srv)->flags & VESMAIL_SMTP_F_DBG099) VESmail_smtp_debug_flush(srv, 99, 0);
}

int VESmail_smtp_debug_flush(VESmail_server *srv, int code, int dsn) {
    int rs = 0;
    struct VESmail_smtp_debug *dbg;
    while ((dbg = VESMAIL_SMTP(srv)->debug)) {
	if (code > 0) {
	    int r = VESmail_smtp_reply_sendln(srv, code, dsn, VESMAIL_SMTP_RF_NODEBUG, dbg->msg);
	    if (r < 0) return r;
	    rs += r;
	}
	VESMAIL_SMTP(srv)->debug = dbg->chain;
	free(dbg);
    }
    return rs;
}

int VESmail_smtp_idle(VESmail_server *srv, int tmout) {
    int t = srv->req_out ?
	(VESMAIL_SMTP(srv)->state >= VESMAIL_SMTP_S_DATA ? VESMAIL_SMTP_TMOUT_DATA : VESMAIL_SMTP_TMOUT_CMD)
	: VESMAIL_SMTP_TMOUT_LOGIN;
    if ((srv->tmout = t - tmout) <= 0) srv->flags |= VESMAIL_SRVF_TMOUT;
    return 0;
}


void VESmail_smtp_fn_free(VESmail_server *srv, int final) {
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    if (!final) {
	VESmail_free(smtp->mail);
	return;
    }
    free(smtp->helo);
    VESmail_smtp_track *trk, *next;
    for (trk = smtp->track; trk; trk = next) {
	next = trk->chain;
	VESmail_smtp_track_free(trk);
    }
    VESmail_smtp_debug_flush(srv, 0, 0);
}

VESmail_server *VESmail_server_new_smtp(VESmail_optns *optns) {
    VESmail_server *srv = VESmail_server_init(malloc(sizeof(VESmail_server) + sizeof(VESmail_smtp)), optns);
    srv->type = "smtp";
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    srv->debugfn = &VESmail_smtp_debug;
    srv->freefn = &VESmail_smtp_fn_free;
    srv->idlefn = &VESmail_smtp_idle;
    smtp->state = VESMAIL_SMTP_S_HELLO;
    smtp->mode = VESMAIL_SMTP_M_REJECT;
    smtp->flags = VESMAIL_SMTP_F_INIT;
    smtp->helo = NULL;
    smtp->mail = NULL;
    smtp->track = NULL;
    smtp->debug = NULL;
    smtp->lf = "\r\n";

    srv->req_in = VESmail_xform_new_smtp_cmd(srv);

    srv->rsp_in = VESmail_xform_new_smtp_reply(srv);

    srv->rsp_out = NULL;
    return srv;
}
