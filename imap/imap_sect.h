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

struct VESmail_imap_msg;
struct VESmail_imap_token;
struct VESmail_imap_fetch;
struct VESmail_imap_result;

int VESmail_imap_sect_learn(struct VESmail_imap_token *st, struct VESmail_imap_msg *msg);
void VESmail_imap_sect_hdr_escape(struct VESmail_imap_fetch *fetch, struct VESmail_imap_token *token);
int VESmail_imap_sect_hdr_unescape(struct VESmail_imap_fetch *fetch, struct VESmail_imap_token *token, struct VESmail_imap_fetch **rngptr);
int VESmail_imap_sect_hdr_skip(struct VESmail_imap_fetch *fetch, const char *hdr);
struct VESmail_imap_fetch *VESmail_imap_sect_regqry(struct VESmail_imap_fetch *fetch, struct VESmail_imap_msg *msg);
int VESmail_imap_sect_apply(struct VESmail_imap_token *token, struct VESmail_imap_msg *msg);
int VESmail_imap_sect_traverse(struct VESmail_imap_msg *msg, int (* callbk)(void *, struct VESmail_imap_msg *, struct VESmail_imap_fetch *), void *arg);
