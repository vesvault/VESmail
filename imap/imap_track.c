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
#include "../VESmail.h"
#include "../srv/server.h"
#include "imap.h"
#include "imap_token.h"
#include "imap_track.h"


VESmail_imap_track *VESmail_imap_track_init(VESmail_imap_track *trk, VESmail_server *srv, VESmail_imap_token *req) {
    trk->tag = (req && req->type == VESMAIL_IMAP_T_LINE && req->len >= 1
	&& req->list[0]->type == VESMAIL_IMAP_T_ATOM && req->list[0]->len > 0 && req->list[0]->data[0] != '+')
	? VESmail_imap_token_clone(req->list[0])
	: NULL;
    trk->server = srv;
    trk->chain = NULL;
    trk->queue = NULL;
    trk->rspfn = NULL;
    trk->token = NULL;
    return trk;
}

VESmail_imap_track *VESmail_imap_track_link(VESmail_imap_track *trk) {
    trk->chain = VESMAIL_IMAP(trk->server)->track;
    return VESMAIL_IMAP(trk->server)->track = trk;
}

VESmail_imap_track *VESmail_imap_track_queue(VESmail_imap_track *trk, VESmail_imap_track **ptr) {
    while (*ptr) ptr = &(*ptr)->queue;
    return *ptr = trk;
}

VESmail_imap_track *VESmail_imap_track_new_fwd(VESmail_server *srv, VESmail_imap_token *req) {
    return VESmail_imap_track_link(VESmail_imap_track_init(malloc(sizeof(VESmail_imap_track)), srv, req));
}

VESmail_imap_track *VESmail_imap_track_new_queue(VESmail_server *srv, VESmail_imap_token *req) {
    VESmail_imap_track *trk = VESmail_imap_track_init(malloc(sizeof(VESmail_imap_track)), srv, req);
    trk->token = req;
    return VESmail_imap_track_queue(trk, &VESMAIL_IMAP(srv)->reqq);
}

int VESmail_imap_track_out(VESmail_imap_track **ptr) {
    if (*ptr) {
	VESmail_imap_track *trk = *ptr;
	*ptr = trk->queue;
	trk->queue = NULL;
	VESmail_imap_track_link(trk);
	return VESmail_imap_req_fwd(trk->server, trk->token, 0);
    } 
    return 0;
}

VESmail_imap_track **VESmail_imap_track_match(VESmail_imap_track **ptr, const char *tag, int taglen) {
    if (ptr) while (*ptr) {
	if (taglen) {
	    if ((*ptr)->tag && taglen == (*ptr)->tag->len && !memcmp(tag, (*ptr)->tag->data, taglen)) return ptr;
	} else if (!(*ptr)->tag) return ptr;
	ptr = &(*ptr)->chain;
    }
    return NULL;
}

int VESmail_imap_track_send_rsp(VESmail_imap_track *trk) {
    if (trk->token) {
	int rs = VESmail_imap_rsp_send(trk->server, trk->token);
	return rs;
    }
    return 0;
}

void VESmail_imap_track_free(VESmail_imap_track *trk) {
    if (trk) {
	VESmail_imap_token_free(trk->tag);
	VESmail_imap_token_free(trk->token);
    }
    free(trk);
}

VESmail_imap_track *VESmail_imap_track_unlink(VESmail_imap_track **ptr) {
    VESmail_imap_track *trk = *ptr;
    if (trk) {
	*ptr = trk->chain;
	trk->chain = NULL;
    }
    return trk;
}

void VESmail_imap_track_done(VESmail_imap_track **ptr) {
    VESmail_imap_track_free(VESmail_imap_track_unlink(ptr));
}

