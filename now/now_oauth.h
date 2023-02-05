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

struct VESmail_now_req;
struct VESmail_server;

#ifndef VESMAIL_NOW_OAUTH_KEYPASSWD
#define	VESMAIL_NOW_OAUTH_KEYPASSWD	"oauth"
#endif
#ifndef VESMAIL_NOW_OAUTH_KEYALGO
#define	VESMAIL_NOW_OAUTH_KEYALGO	"ECDH"
#endif

int VESmail_now_oauth_reqStack(struct VESmail_now_req *req);
struct VESmail_now_oauth *VESmail_now_oauth_new(const char *path, const char *passphrase, const char *algo);
int VESmail_now_oauth_decrypt(struct VESmail_now_oauth *oauth, char **ppass, const char *token, int len);
void VESmail_now_oauth_free(struct VESmail_now_oauth *oauth);
