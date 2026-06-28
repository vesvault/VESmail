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

struct VESmail_server;
struct VESmail_imap;
struct VESmail_imap_token;

typedef struct VESmail_imap_track {
    struct VESmail_server *server;
    struct VESmail_imap_token *tag;
    int (* rspfn)(int verb, struct VESmail_imap_token *, struct VESmail_imap_track *);
    struct VESmail_imap_track *chain;
    struct VESmail_imap_track *queue;
    struct VESmail_imap_token *token;
    void *ref;
} VESmail_imap_track;


struct VESmail_imap_track *VESmail_imap_track_new_fwd(struct VESmail_server *srv, struct VESmail_imap_token *req);
struct VESmail_imap_track *VESmail_imap_track_new_queue(struct VESmail_server *srv, struct VESmail_imap_token *req);
int VESmail_imap_track_out(struct VESmail_imap_track **ptr);
struct VESmail_imap_track **VESmail_imap_track_match(struct VESmail_imap_track **ptr, const char *tag, int taglen);
#define VESmail_imap_track_cp_tag(trk)	VESmail_imap_token_clone(trk->tag)
int VESmail_imap_track_send_rsp(struct VESmail_imap_track *trk);
struct VESmail_imap_track *VESmail_imap_track_unlink(struct VESmail_imap_track **ptr);
void VESmail_imap_track_done(struct VESmail_imap_track **ptr);
void VESmail_imap_track_free(struct VESmail_imap_track *trk);
