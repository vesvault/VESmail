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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../VESmail.h"
#include "tty.h"
#include "../srv/arch.h"
#include "help.h"


const char *VESmail_cli_banner =
 "  \x1b[1;33m_____\x1b[0m\n"
 " \x1b[1;33m|\\    |\x1b[0m \x1b[2;31m>\x1b[0m                   \x1b[1;36mVESmail Project\x1b[0m " VESMAIL_VERSION "\n"
 " \x1b[1;33m| \\   |\x1b[0m \x1b[2;31m>\x1b[0m  \x1b[1;31m___\x1b[0m       ___    Email Encryption made Convenient and Reliable\n"
 " \x1b[1;33m|  \\  |\x1b[0m \x1b[2;31m>\x1b[0m \x1b[1;31m/   \\\x1b[0m     /   \\                              \x1b[1;34mhttps://mail.ves.world\x1b[0m\n"
 " \x1b[1;33m|  /  |\x1b[0m \x1b[2;31m>\x1b[0m \x1b[1;31m\\__ /\x1b[0m     \\ __/\n"
 " \x1b[1;33m| /   |\x1b[0m \x1b[2;31m>\x1b[0m    \x1b[1;31m\\\\\x1b[0m     //        \x1b[1;33m-\x1b[0m RFC5322 MIME Stream Encryption & Decryption\n"
 " \x1b[1;33m|/____|\x1b[0m \x1b[2;31m>\x1b[0m     \x1b[1;31m\\\\\x1b[0m   //         \x1b[1;33m-\x1b[0m IMAP4rev1 Transparent Proxy Server\n"
 "       ___      \x1b[1;31m\\\\\x1b[0m_//          \x1b[1;33m-\x1b[0m ESMTP Transparent Proxy Server\n"
 "      /   \\     /   \\          \x1b[1;33m-\x1b[0m VES Encryption Key Exchange & Recovery\n"
 "      \\__ /     \\ __/\n"
 "         \\\\     //    \x1b[1;33m_____\x1b[0m                     ______________by______________\n"
 "          \\\\   //  \x1b[2;31m>\x1b[0m \x1b[1;33m|\\    |\x1b[0m\n"
 "           \\\\_//   \x1b[2;31m>\x1b[0m \x1b[1;33m| \\   |\x1b[0m                    \x1b[1mVESvault\x1b[0m\n"
 "           /   \\   \x1b[2;31m>\x1b[0m \x1b[1;33m|  \\  |\x1b[0m                    Encrypt Everything\n"
 "           \\___/   \x1b[2;31m>\x1b[0m \x1b[1;33m|  /  |\x1b[0m                    without fear of losing the Key\n"
 "                   \x1b[2;31m>\x1b[0m \x1b[1;33m| /   |\x1b[0m                              \x1b[1;34mhttps://vesvault.com\x1b[0m\n"
 "                   \x1b[2;31m>\x1b[0m \x1b[1;33m|/____|\x1b[0m                                  \x1b[1;34mhttps://ves.host\x1b[0m\n"
 "\n"
 "\n"
 " \x1b[1mvesmail imap\x1b[0m [--cert <path> --pkey <path> --ca <path>] [--now_url <VESmail_now> --now-dir <spool_dir>]\n"
 " \x1b[1mvesmail smtp\x1b[0m [--cert <path> --pkey <path> --ca <path>] [--now_url <VESmail_now> --now-dir <spool_dir>]\n"
 " \x1b[1mvesmail encrypt\x1b[0m -a <VESmail_account> -u <VESkey> [--now_url <VESmail_now> --now-dir <spool_dir>]\n"
 " \x1b[1mvesmail decrypt\x1b[0m -a <VESmail_account> -u <VESkey>\n"
 " \x1b[1mvesmail now\x1b[0m --now-dir <spool_dir>\n"
 "\n";

void out_ansi_str(int fdi, const char *str) {
    if (tty_is_ansi(fdi)) {
	VESmail_arch_write(fdi, str, strlen(str));
	return;
    }
    const char *s = str;
    const char *s0 = s;
    char c;
    char esc = 0;
    do {
	c = *s++;
	if (esc) {
	    if (c == 'm') {
		esc = 0;
		s0 = s;
	    }
	} else {
	    if (c == 0x1b || c == 0) {
		esc = 1;
		int l = s - s0 - 1;
		if (l > 0) VESmail_arch_write(fdi, s0, l);
	    }
	}
    } while (c);
}

void VESmail_help() {
    out_ansi_str(1, VESmail_cli_banner);
}
