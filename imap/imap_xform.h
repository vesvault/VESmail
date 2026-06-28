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

struct VESmail_imap_token;
struct VESmail_server;
struct VESmail_xform;

#ifndef VESMAIL_ENUM
#define	VESMAIL_ENUM(_type)	unsigned char
#endif

enum VESmail_imap_xform_state {
    VESMAIL_IMAP_X_INIT,
    VESMAIL_IMAP_X_HOLD,
    VESMAIL_IMAP_X_ABORT,
    VESMAIL_IMAP_X_FFWD
};

typedef struct VESmail_imap_xform {
    int (* procfn)(struct VESmail_server *srv, struct VESmail_imap_token *token);
    struct VESmail_imap_token *line;
    struct VESmail_imap_token *list;
    struct VESmail_xform *sync;
    unsigned int skip;
    VESMAIL_ENUM(VESmail_imap_xform_state) state;
} VESmail_imap_xform;

struct VESmail_xform *VESmail_xform_new_imap(struct VESmail_server *srv, int (* procfn)(struct VESmail_server *, struct VESmail_imap_token *));
struct VESmail_imap_token *VESmail_imap_xform_detach(struct VESmail_xform *xform, struct VESmail_imap_token *token);
struct VESmail_xform *VESmail_imap_xform_sync(struct VESmail_xform *xform);
