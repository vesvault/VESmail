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
#include "../VESmail.h"
#include "../srv/server.h"
#include "smtp.h"
#include "smtp_reply.h"
#include "smtp_track.h"


VESmail_smtp_track *VESmail_smtp_track_new(VESmail_server *srv, int (* replyfn)(VESmail_smtp_track *, VESmail_smtp_reply *)) {
    VESmail_smtp_track *trk = malloc(sizeof(VESmail_smtp_track));
    trk->server = srv;
    trk->chain = NULL;
    trk->replyfn = replyfn;
    trk->unqfn = NULL;
    trk->freefn = NULL;
    if (replyfn) srv->flags |= VESMAIL_SRVF_OVER;
    VESmail_smtp_track **ptr;
    for (ptr = &VESMAIL_SMTP(srv)->track; *ptr; ptr = &(*ptr)->chain);
    return *ptr = trk;
}

int VESmail_smtp_track_reply(VESmail_server *srv, VESmail_smtp_reply *reply) {
    VESmail_smtp_track *trk = VESMAIL_SMTP(srv)->track;
    if (!trk) return VESMAIL_E_PARAM;
    VESMAIL_SMTP(srv)->track = trk->chain;
    int rs = trk->replyfn(trk, reply);
    int r = VESmail_smtp_track_unqueue(trk->chain);
    VESmail_smtp_track_free(trk);
    if (rs < 0) return rs;
    if (r < 0) return r;
    return rs + r;
}

int VESmail_smtp_track_unqueue(VESmail_smtp_track *trk) {
    int rs = 0;
    if (!trk) return 0;
    VESmail_smtp *smtp = VESMAIL_SMTP(trk->server);
    if (trk == smtp->track) while (trk && !trk->replyfn) {
	smtp->track = trk->chain;
	int r = trk->unqfn(trk);
	if (r < 0) return r;
	rs += r;
	VESmail_smtp_track_free(trk);
	trk = smtp->track;
    }
    return rs;
}

void VESmail_smtp_track_free(VESmail_smtp_track *trk) {
    if (trk && trk->freefn) trk->freefn(trk);
    free(trk);
}
