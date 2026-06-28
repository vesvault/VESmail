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
#include "../VESmail.h"
#include "../lib/mail.h"
#include "../lib/optns.h"
#include "../lib/parse.h"
#include "../lib/xform.h"
#include "../srv/server.h"
#include "imap_token.h"
#include "imap.h"
#include "imap_append.h"


int VESmail_imap_append_xform_fn(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return *srclen = 0;
    return VESmail_convert(xform->parse->mail, NULL, final, src, *srclen);
}

void VESmail_imap_append_xform_freefn(VESmail_xform *xform) {
    VESmail_free(xform->parse->mail);
}

int VESmail_imap_append_encrypt(VESmail_server *srv, VESmail_imap_token *body, VESmail_xform *sync) {
    VESmail_xform *out = VESmail_imap_token_xform_new(body);
    if ((out->chain = sync)) body->state = VESMAIL_IMAP_P_SYNC;
    VESmail *mail = VESmail_set_out(VESmail_new_encrypt(srv->ves, srv->optns), out);
    mail->flags &= ~(VESMAIL_O_XCHG | VESMAIL_O_HDR_RCPT);
    VESmail_xform *in = VESmail_xform_new(&VESmail_imap_append_xform_fn, NULL, mail->root);
    in->freefn = &VESmail_imap_append_xform_freefn;
    return VESmail_imap_token_xform_apply(body, in);
}
