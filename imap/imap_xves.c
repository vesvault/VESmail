/***************************************************************************
 *  _____
 * |\    | >                   VESmail Project
 * | \   | >  ___       ___    Email Encryption made Convenient and Reliable
 * |  \  | > /   \     /   \                              https://mail.ves.world
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
#include "../VESmail.h"
#include "../srv/server.h"
#include "imap.h"
#include "imap_token.h"
#include "imap_xves.h"


#define VESMAIL_VERB(verb)	#verb,
const char *VESmail_imap_xves_verbs[] = { VESMAIL_IMAP_XVES_VERBS() NULL };
#undef VESMAIL_VERB

int VESmail_imap_xves_bool(VESmail_server *srv, int xves, int flag, VESmail_imap_token *req) {
    VESmail_imap *imap = VESMAIL_IMAP(srv);
    VESmail_imap_token *val = req->len > 3 ? req->list[3] : NULL;
    unsigned int v;
    if (val) {
	int r = VESmail_imap_token_getuint(val, &v);
	if (r < 0) return r;
	if (v > 1) return VESMAIL_E_PARAM;
	imap->flags = v ? (imap->flags | flag) : (imap->flags & ~flag);
    }
    v = imap->flags & flag ? 1 : 0;
    VESmail_imap_token *rsp = VESmail_imap_rsp_new(NULL, "XVES");
    int rs = VESmail_imap_rsp_send(srv, VESmail_imap_token_splice(rsp, -1, 0, 2,
	VESmail_imap_token_atom(VESmail_imap_xves_verbs[xves]),
	VESmail_imap_token_uint(v)
    ));
    VESmail_imap_token_free(rsp);
    return rs;
}

int VESmail_imap_xves(VESmail_server *srv, VESmail_imap_token *req, VESmail_imap_token *tag) {
    if (!tag) tag = VESmail_imap_cp_tag(req);
    int rs;
    int xves;
    if (req->state != VESMAIL_IMAP_P_DONE || req->len < 3) {
	xves = VESMAIL_E_PARAM;
    } else {
	xves = VESmail_imap_get_verb(req->list[2], VESmail_imap_xves_verbs);
    }
    switch (xves) {
	case VESMAIL_IMAP_XV_ORDER:
	    rs = VESmail_imap_xves_bool(srv, VESMAIL_IMAP_XV_ORDER, VESMAIL_IMAP_F_ORDER, req);
	    break;
	case VESMAIL_IMAP_XV_CALC:
	    rs = VESmail_imap_xves_bool(srv, VESMAIL_IMAP_XV_CALC, VESMAIL_IMAP_F_CALC, req);
	    break;
	case VESMAIL_IMAP_XV_NOOP:
	    rs = 0;
	    break;
	default:
	    rs = VESMAIL_E_UNKNOWN;
	    break;
    }
    VESmail_imap_token *rsp;
    if (rs >= 0) {
	rsp = VESmail_imap_rsp_new(tag, "OK");
	VESmail_imap_token_splice(rsp, -1, 0, 3,
	    VESmail_imap_token_atom("XVES"),
	    VESmail_imap_token_atom(VESmail_imap_xves_verbs[xves]),
	    VESmail_imap_token_atom("completed")
	);
    } else {
	rsp = VESmail_imap_rsp_new(tag, "BAD");
	char *er = VESmail_server_errorStr(srv, rs);
	VESmail_imap_token_push(rsp, VESmail_imap_token_atom(er));
	free(er);
    }
    rs = VESmail_imap_rsp_send(srv, rsp);
    VESmail_imap_token_free(rsp);
    VESmail_imap_req_abort(srv);
    return rs;
}
