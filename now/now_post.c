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
#include <jVar.h>
#include "../VESmail.h"
#include "../srv/server.h"
#include "../lib/mail.h"
#include "../lib/optns.h"
#include "../lib/xform.h"
#include "../srv/conf.h"
#include "now.h"
#include "now_post.h"


int VESmail_now_xform_fn_post(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    VESmail_server *srv = xform->server;
    if (!xform->data) xform->data = jVarParser_new(NULL);
    xform->data = jVarParser_parse(xform->data, src, *srclen);
    xform->offset += *srclen;
    if (!jVarParser_isComplete((jVarParser *)(xform->data))) {
	if (final || jVarParser_isError((jVarParser *)(xform->data))) return VESmail_now_error(srv, 400, "JSON expected\r\n");
	if (xform->offset > VESMAIL_NOW_REQ_SAFEBYTES) return VESmail_now_error(srv, 413, "Too long\r\n");
	return 0;
    }
    jVar *req = jVarParser_done(xform->data);
    xform->data = NULL;
    int (** postfn)(VESmail_server *, jVar*) = VESmail_now_CONF(srv, now.postStack);
    int rs = VESMAIL_E_HOLD;
    if (postfn) while (*postfn) {
	rs = (*postfn)(srv, req);
	if (rs != VESMAIL_E_HOLD) break;
	postfn++;
    }
    srv->flags |= VESMAIL_SRVF_SHUTDOWN;
    if (rs == VESMAIL_E_HOLD) return VESmail_now_error(srv, 400, "Unsupported request body\r\n");
    return rs;
}

void VESmail_now_xform_fn_post_free(VESmail_xform *xform) {
    if (xform->data) jVar_free(jVarParser_done(xform->data));
    VESmail_xform_free(xform->chain);
}


int VESmail_now_post_reqStack(VESmail_now_req *req) {
    if (strcmp(req->method, "POST")) return VESMAIL_E_HOLD;
    VESmail_now_req_cont(req);
    req->xform->chain = VESmail_xform_new(&VESmail_now_xform_fn_post, NULL, req->xform->server);
    req->xform->chain->freefn = &VESmail_now_xform_fn_post_free;
    return 0;
}
