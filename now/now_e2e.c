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
#include "../lib/xform.h"
#include "now.h"
#include "now_e2e.h"


int VESmail_now_e2e_reqStack(VESmail_now_req *req) {
    if (strcmp(req->method, "GET") || req->uri.search - req->uri.path < 4 || memcmp(req->uri.path, "e2e/", 4)) return VESMAIL_E_HOLD;
    const char *u = req->uri.path + 3;
    VESmail_server *srv = req->xform->server;
    int rs = VESmail_now_send_status(srv, 302);
    if (rs < 0) return rs;
    int r = VESmail_now_send(srv, 0, "Location: " VESMAIL_NOW_E2EURL);
    if (r < 0) return r;
    rs += r;
    r = VESmail_xform_process(srv->rsp_out, 0, u, req->uri.search - u);
    if (r < 0) return r;
    rs += r;
    u = req->uri.search;
    if (req->uri.hash > u) {
	r = VESmail_now_send(srv, 0, "#");
	if (r < 0) return r;
	rs += r;
	u += 1;
    }
    r = VESmail_xform_process(srv->rsp_out, 0, u, req->uri.end - u);
    if (r < 0) return r;
    rs += r;
    r = VESmail_now_send(srv, 1, "\r\n\r\n");
    if (r < 0) return r;
    srv->flags |= VESMAIL_SRVF_SHUTDOWN;
    return rs + r;
}
