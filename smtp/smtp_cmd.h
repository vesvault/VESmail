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
struct VESmail_xform;

typedef struct VESmail_smtp_cmd {
    const char *head;
    const char *arg;
    int len;
    int verb;
    char data[0];
} VESmail_smtp_cmd;

#ifndef VESMAIL_SMTP_CMD_SAFEBYTES
#define	VESMAIL_SMTP_CMD_SAFEBYTES	16383
#endif

struct VESmail_xform *VESmail_xform_new_smtp_cmd(struct VESmail_server *srv);
struct VESmail_xform *VESmail_xform_new_smtp_data(struct VESmail_server *srv);
const char *VESmail_smtp_cmd_get_eol(const struct VESmail_smtp_cmd *cmd);
int VESmail_smtp_cmd_match_verb(const char **cmd, const char *tail, const char **verbs);
int VESmail_smtp_cmd_fwd(VESmail_server *srv, const char *cmd, int cmdlen);
#define	VESmail_smtp_cmd_send(srv, cmd)	VESmail_smtp_cmd_fwd(srv, (cmd)->head, (cmd)->len)
int VESmail_smtp_cmd_fwda(VESmail_server *srv, const char *cmd, int argc, ...);
struct VESmail_smtp_cmd *VESmail_smtp_cmd_dup(const struct VESmail_smtp_cmd *cmd);
void VESmail_smtp_cmd_free(struct VESmail_smtp_cmd *cmd);
