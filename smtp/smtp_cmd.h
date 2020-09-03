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
struct VESmail_xform;

typedef struct VESmail_smtp_cmd {
    const char *head;
    const char *arg;
    int len;
    int verb;
    char data[0];
} VESmail_smtp_cmd;

struct VESmail_xform *VESmail_xform_new_smtp_cmd(struct VESmail_server *srv);
struct VESmail_xform *VESmail_xform_new_smtp_data(struct VESmail_server *srv);
const char *VESmail_smtp_cmd_get_eol(const struct VESmail_smtp_cmd *cmd);
int VESmail_smtp_cmd_match_verb(const char **cmd, const char *tail, const char **verbs);
int VESmail_smtp_cmd_fwd(VESmail_server *srv, const char *cmd, int cmdlen);
#define	VESmail_smtp_cmd_send(srv, cmd)	VESmail_smtp_cmd_fwd(srv, (cmd)->head, (cmd)->len)
int VESmail_smtp_cmd_fwda(VESmail_server *srv, const char *cmd, int argc, ...);
struct VESmail_smtp_cmd *VESmail_smtp_cmd_dup(const struct VESmail_smtp_cmd *cmd);
#define VESmail_smtp_cmd_free(cmd)	free(cmd)
