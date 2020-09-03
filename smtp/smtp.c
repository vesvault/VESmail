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

void VESmail_smtp_fn_free(VESmail_server *srv) {
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    free(smtp->helo);
    VESmail_smtp_track *trk, *next;
    for (trk = smtp->track; trk; trk = next) {
	next = trk->chain;
	VESmail_smtp_track_free(trk);
    }
    VESmail_free(smtp->mail);
    VESmail_smtp_debug_flush(srv, 0, 0);
}

VESmail_server *VESmail_server_new_smtp(VESmail_optns *optns) {
    VESmail_server *srv = VESmail_server_init(malloc(sizeof(VESmail_server) + sizeof(VESmail_smtp)), optns);
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    srv->debugfn = &VESmail_smtp_debug;
    srv->freefn = &VESmail_smtp_fn_free;
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
