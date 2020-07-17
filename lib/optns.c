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
#include "banner.h"
#include "optns.h"

char *VESmail_optns_default_mime[] = {"application/vnd.ves.encrypted", "application/x-ves-encrypted", "application/ves-encrypted", NULL};
char *VESmail_optns_default_injected[] = {"--VESmail-injected-", NULL};

struct VESmail_optns VESmail_optns_default = {
    .flags = VESMAIL_O_HDR_RCPT | VESMAIL_O_XCHG | VESMAIL_O_VES_NTFY,
    .vesDomain = VESMAIL_VES_DOMAIN,
    .idSuffix = ".m.ves.world",
    .idBase = "@msgid.mail.ves.world",
    .subj = "<VESmail encrypted message>",
    .mime = VESmail_optns_default_mime,
    .injected = VESmail_optns_default_injected,
    .getBanners = NULL,
    .now = {
	.url = NULL,
	.dir = NULL
    },
    .acl = NULL
};

struct VESmail_optns *VESmail_optns_new() {
    struct VESmail_optns *optns = malloc(sizeof(VESmail_optns));
    memcpy(optns, &VESmail_optns_default, sizeof(*optns));
    return optns;
}
