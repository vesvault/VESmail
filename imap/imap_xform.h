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

struct VESmail_imap_token;
struct VESmail_server;
struct VESmail_xform;

typedef struct VESmail_imap_xform {
    int (* procfn)(struct VESmail_server *srv, struct VESmail_imap_token *token);
    struct VESmail_imap_token *line;
    struct VESmail_imap_token *list;
    struct VESmail_xform *sync;
    unsigned int skip;
    enum {
	VESMAIL_IMAP_X_INIT,
	VESMAIL_IMAP_X_HOLD,
	VESMAIL_IMAP_X_ABORT,
	VESMAIL_IMAP_X_FFWD
    } state;
} VESmail_imap_xform;

struct VESmail_xform *VESmail_xform_new_imap(struct VESmail_server *srv, int (* procfn)(struct VESmail_server *, struct VESmail_imap_token *));
struct VESmail_imap_token *VESmail_imap_xform_detach(struct VESmail_xform *xform, struct VESmail_imap_token *token);
struct VESmail_xform *VESmail_imap_xform_sync(struct VESmail_xform *xform);
