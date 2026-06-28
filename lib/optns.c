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
#include "banner.h"
#include "optns.h"

char *VESmail_optns_default_mime[] = {"application/vnd.ves.encrypted", "application/x-ves-encrypted", "application/ves-encrypted", NULL};
char *VESmail_optns_default_injected[] = {"--VESmail-injected-", NULL};

struct VESmail_optns VESmail_optns_default = {
    .flags = VESMAIL_O_HDR_RCPT | VESMAIL_O_XCHG | VESMAIL_O_VES_NTFY | VESMAIL_O_HDR_REFS | VESMAIL_O_DECRYPT_PASS,
    .maxbuf = VESMAIL_OPTNSMAXBUF,
    .vesDomain = VESMAIL_VES_DOMAIN,
    .idSuffix = ".m.ves.world",
    .idBase = "@msgid.mail.ves.world",
    .subj = "<VESmail encrypted message>",
    .mime = VESmail_optns_default_mime,
    .injected = VESmail_optns_default_injected,
    .getBanners = NULL,
    .getApp = NULL,
    .now = {
	.url = NULL,
	.dir = NULL
    },
    .acl = NULL,
    .unspecd = "[unspecified]",
    .audit = NULL,
    .bcc = NULL
};

VESmail_optns *VESmail_optns_new() {
    return VESmail_optns_clone(&VESmail_optns_default);
}

VESmail_optns *VESmail_optns_clone(VESmail_optns *op) {
    struct VESmail_optns *optns = malloc(sizeof(VESmail_optns));
    memcpy(optns, op, sizeof(*optns));
    return optns;
}
