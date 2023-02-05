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
#include "../lib/optns.h"
#include "../lib/xform.h"
#include "../srv/conf.h"
#include "now.h"
#include "now_manifest.h"


int VESmail_now_xform_fn_manifest(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    VESmail_server *srv = xform->server;
    const char *mft = srv->optns->ref ? ((VESmail_conf *) srv->optns->ref)->now.manifest : NULL;
    VESmail_now_log(srv, "GET", (mft ? 200 : 404), NULL);
    if (mft) {
	int rs = VESmail_now_send_status(srv, 200);
	if (rs < 0) return rs;
	int r = VESmail_now_sendcl(srv, mft);
	if (r < 0) return r;
	rs += r;
	r = VESmail_now_send(srv, 0, "Content-Type: application/json\r\n");
	if (r < 0) return r;
	rs += r;
	r = VESmail_now_sendhdrs(srv);
	if (r < 0) return r;
	rs += r;
	r = VESmail_now_send(srv, 1, mft);
	if (r < 0) return r;
	rs += r;
	srv->flags |= VESMAIL_SRVF_SHUTDOWN;
	return rs;
    } else {
	return VESmail_now_error(srv, 404, "Manifest is not supplied\r\n");
    }
}

int VESmail_now_manifest_reqStack(VESmail_now_req *req) {
    if (strcmp(req->method, "GET")) return VESMAIL_E_HOLD;
    if (req->uri.search - req->uri.path != 8 || memcmp(req->uri.path, "ves.json", 8)) return VESMAIL_E_HOLD;
    req->xform->chain = VESmail_xform_new(&VESmail_now_xform_fn_manifest, NULL, req->xform->server);
    return VESmail_xform_process(req->xform->chain, 1, "", 0);
}

