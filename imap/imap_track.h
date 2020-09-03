/***************************************************************************
 *  _____
 * |\    | >                   VESmail Project
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
