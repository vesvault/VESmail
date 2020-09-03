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
#include <stdarg.h>
#include "../VESmail.h"
#include "../lib/mail.h"
#include "../srv/server.h"
#include "smtp.h"
#include "smtp_cmd.h"
#include "smtp_reply.h"
#include "smtp_xves.h"

#define VESMAIL_VERB(verb)	#verb,
const char *VESmail_smtp_xves_verbs[] = { VESMAIL_SMTP_XVES_VERBS() NULL };
#undef VESMAIL_VERB

int VESmail_smtp_xves(VESmail_server *srv, VESmail_smtp_cmd *cmd) {
    const char *arg = cmd->arg;
    const char *tail = cmd->head + cmd->len;
    VESmail_smtp *smtp = VESMAIL_SMTP(srv);
    int xv = arg ? VESmail_smtp_cmd_match_verb(&arg, tail, VESmail_smtp_xves_verbs) : VESMAIL_E_UNKNOWN;
    switch (xv) {
	case VESMAIL_SMTP_XV_NOOP:
	    return VESmail_smtp_reply_sendln(srv, 250, 0, VESMAIL_SMTP_RF_FINAL, "XVES NOOP");
	case VESMAIL_SMTP_XV_MODE: {
	    if (arg < tail) {
		int m = VESmail_smtp_cmd_match_verb(&arg, tail, VESmail_smtp_modes);
		if (m < 0) return VESmail_smtp_reply_sendln(srv, 501, 0, VESMAIL_SMTP_RF_FINAL, "Unknown XVES MODE");
		if (arg < tail) return VESmail_smtp_reply_sendln(srv, 501, 0, VESMAIL_SMTP_RF_FINAL, "Too many arguments.");
		smtp->mode = m;
	    }
	    int rs = VESmail_smtp_reply_sendln(srv, 250, 0, VESMAIL_SMTP_RF_FINAL | VESMAIL_SMTP_RF_NOEOL, "XVES MODE ");
	    if (rs < 0) return rs;
	    int r = VESmail_smtp_reply_sendln(srv, 0, 0, 0, VESmail_smtp_modes[smtp->mode]);
	    if (r < 0) return r;
	    return rs + r;
	}
	default:
	    break;
    }
    return VESmail_smtp_reply_sendln(srv, 501, 0, VESMAIL_SMTP_RF_FINAL, "Unknown XVES subcommand.");
}

