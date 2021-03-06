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

struct VESmail_optns;

struct VESmail_server *VESmail_server_new_now(struct VESmail_optns *optns);
int VESmail_now_error(struct VESmail_server *srv, int code, const char *msg);
void VESmail_now_log(struct VESmail_server *srv, const char *meth, int code, ...);
int VESmail_now_send(struct VESmail_server *srv, int final, const char *str);
int VESmail_now_send_status(struct VESmail_server *srv, int code);
int VESmail_now_sendhdrs(struct VESmail_server *srv);


#define	VESMAIL_MERR_NOW	0x0100

#ifndef VESMAIL_NOW_REQ_SAFEBYTES
#define	VESMAIL_NOW_REQ_SAFEBYTES	32767
#endif
