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


int VESmail_now_feedback_postStack(VESmail_server *srv, jVar *req) {
    int (* fbkfn)(const char *fbk) = VESmail_now_CONF(srv, now.feedbackFn);
    if (!fbkfn) return VESMAIL_E_HOLD;
    jVar *fbk = jVar_get(req, "feedback");
    if (!fbk) return VESMAIL_E_HOLD;
    const char *fbks = jVar_getStringP(fbk);
    void **pmutex = VESmail_now_PCONF(srv, mutex);
    VESmail_arch_mutex_lock(pmutex);
    int rs = fbkfn(fbks);
    VESmail_arch_mutex_unlock(pmutex);
    return VESmail_now_errorlog(srv, (rs >= 0 ? 202 : 502), (rs >= 0 ? NULL : "Feedback not accepted"), "POST[feedback]", "feedback", fbks, NULL);
}
