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
