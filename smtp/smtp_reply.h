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
struct VESmail_xform;

typedef struct VESmail_smtp_reply {
    const char *head;
    int len;
    short int code;
    short int dsn;
    char data[0];
} VESmail_smtp_reply;

#define	VESMAIL_SMTP_RF_FINAL	0x01
#define	VESMAIL_SMTP_RF_NOEOL	0x02
#define	VESMAIL_SMTP_RF_NODEBUG	0x04
#define	VESMAIL_SMTP_RF_NOCODE	0x08

int VESmail_smtp_reply_sendl(struct VESmail_server *srv, int code, int dsn, int flags, const char *str, int len);
#define	VESmail_smtp_reply_sendln(srv, code, dsn, flags, str)	VESmail_smtp_reply_sendl(srv, code, dsn, flags, str, strlen(str))
int VESmail_smtp_reply_sendml(struct VESmail_server *srv, int code, int dsn, int flags, const char *str, int len);
#define	VESmail_smtp_reply_send(srv, reply)	VESmail_smtp_reply_sendml(srv, (reply)->code, (reply)->dsn, (VESMAIL_SMTP_RF_NOCODE | VESMAIL_SMTP_RF_NOEOL), (reply)->head, (reply)->len)
const char *VESmail_smtp_reply_get_text(struct VESmail_smtp_reply *reply, const char *eol);
const char *VESmail_smtp_reply_get_eol(struct VESmail_smtp_reply *reply, const char *text);
struct VESmail_xform *VESmail_xform_new_smtp_reply(struct VESmail_server *srv);
