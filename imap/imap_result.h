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

typedef struct VESmail_imap_result {
    struct VESmail_server *server;
    struct VESmail_imap_result *schain;
    struct VESmail_imap_result **sprev;
    struct VESmail_imap_token *token;
    struct VESmail_imap_msg **msgptr;
    struct VESmail_imap_result *mchain;
    struct VESmail_imap_result_entry {
	struct VESmail_imap_result_entry *chain;
	struct VESmail_imap_fetch *fetch;
	enum VESmail_imap_result_state {
	    VESMAIL_IMAP_RE_UNDEF,
	    VESMAIL_IMAP_RE_OK,
	    VESMAIL_IMAP_RE_REQ,
	    VESMAIL_IMAP_RE_DROP,
	    VESMAIL_IMAP_RE_CDROP,
	    VESMAIL_IMAP_RE_BAD,
	    VESMAIL_IMAP_RE_SILENT,
	    VESMAIL_IMAP_RE_SYNC,
	    VESMAIL_IMAP_RE_SYNCD,
	    VESMAIL_IMAP_RE_RESYNC,
	    VESMAIL_IMAP_RE_RESYNCD,
	    VESMAIL_IMAP_RE_DROPD
	} state;
    } *entry;
    struct VESmail_imap_fetch *range;
    long long int qbytes;
    enum VESmail_imap_result_state state;
    char fdrop;
} VESmail_imap_result;


struct VESmail_imap_token;
struct VESmail_server;

struct VESmail_imap_result *VESmail_imap_result_new(struct VESmail_imap_token *rsp, struct VESmail_server *srv);
int VESmail_imap_result_update(struct VESmail_imap_result *rslt);
int VESmail_imap_result_commit(struct VESmail_imap_result *rslt);
int VESmail_imap_result_send(struct VESmail_imap_result *rslt);
int VESmail_imap_result_flush(struct VESmail_imap *imap);
void VESmail_imap_result_free(struct VESmail_imap_result *rslt);

int VESmail_imap_result_process(struct VESmail_imap_result *rslt, struct VESmail_imap_fetch *fetch, struct VESmail_imap_token *key, struct VESmail_imap_token *val, int final);
