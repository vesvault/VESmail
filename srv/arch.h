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

struct VESmail_server;

extern const char *VESmail_arch_NAME;

void VESmail_arch_init();
int VESmail_arch_set_nb(int fd, int nb);
int VESmail_arch_thread(struct VESmail_server *srv, void (* threadfn)(void *));
int VESmail_arch_poll(int len, ...);
char *VESmail_arch_gethostname();
int VESmail_arch_creat(const char *path);
int VESmail_arch_openr(const char *path);
int VESmail_arch_read(int fd, char *buf, int len);
int VESmail_arch_write(int fd, const char *src, int len);
int VESmail_arch_close(int fd);
int VESmail_arch_log(const char *fmt, ...);

#ifdef _WIN32

#define VESMAIL_CONF_PATH	""

#else

#define VESMAIL_CONF_PATH	"/etc/vesmail/"

#endif
