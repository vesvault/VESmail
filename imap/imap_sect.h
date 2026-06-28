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
