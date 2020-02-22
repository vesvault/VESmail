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
struct VESmail_smtp_reply;

typedef struct VESmail_smtp_track {
    struct VESmail_server *server;
    int (* replyfn)(struct VESmail_smtp_track *, struct VESmail_smtp_reply *);
    int (* unqfn)(struct VESmail_smtp_track *);
    void (* freefn)(struct VESmail_smtp_track *);
    struct VESmail_smtp_track *chain;
    void *ref;
} VESmail_smtp_track;

struct VESmail_smtp_track *VESmail_smtp_track_new(struct VESmail_server *srv, int (* replyfn)(struct VESmail_smtp_track *, struct VESmail_smtp_reply *));
int VESmail_smtp_track_reply(struct VESmail_server *srv, struct VESmail_smtp_reply *reply);
int VESmail_smtp_track_unqueue(struct VESmail_smtp_track *trk);
void VESmail_smtp_track_free(struct VESmail_smtp_track *trk);
