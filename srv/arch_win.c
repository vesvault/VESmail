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

#include <winsock2.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>


const char *VESmail_arch_NAME = "Win32";

void VESmail_arch_init() {
}

int VESmail_arch_set_nb(int fd, int nb) {
    u_long flags = nb ? 0 : 1;
    return NO_ERROR == ioctlsocket(fd, FIONBIO, &flags) ? 0 : -1;
}

int VESmail_arch_thread(VESmail_server *srv, void (* threadfn)(void *)) {
    return VESMAIL_E_PARAM;
}

int VESmail_arch_poll(int len, ...) {
    return VESMAIL_E_PARAM;
}

char *VESmail_arch_gethostname() {
    return NULL;
}

int VESmail_arch_read(int fd, char *buf, int len) {
    return read(fd, buf, len);
}

int VESmail_arch_write(int fd, const char *src, int len) {
    return write(fd, src, len);
}
