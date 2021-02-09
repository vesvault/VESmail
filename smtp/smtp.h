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

struct VESmail_server;
struct VESmail_optns;
struct VESmail_smtp_reply;

#define VESMAIL_SMTP_VERBS() \
VESMAIL_VERB(HELO) \
VESMAIL_VERB(EHLO) \
VESMAIL_VERB(AUTH) \
VESMAIL_VERB(MAIL) \
VESMAIL_VERB(RCPT) \
VESMAIL_VERB(DATA) \
VESMAIL_VERB(RSET) \
VESMAIL_VERB(STARTTLS) \
VESMAIL_VERB(VRFY) \
VESMAIL_VERB(NOOP) \
VESMAIL_VERB(HELP) \
VESMAIL_VERB(QUIT) \
VESMAIL_VERB(PIPELINING) \
VESMAIL_VERB(XVES)

#define VESMAIL_SMTP_MODES() \
VESMAIL_VERB(PLAIN) \
VESMAIL_VERB(FALLBACK) \
VESMAIL_VERB(REJECT) \
VESMAIL_VERB(XCHG) \
VESMAIL_VERB(HIGH)

#ifndef VESMAIL_ENUM
#define	VESMAIL_ENUM(_type)	unsigned char
#endif

enum VESmail_smtp_state {
    VESMAIL_SMTP_S_INIT,
    VESMAIL_SMTP_S_HELLO,
    VESMAIL_SMTP_S_START,
    VESMAIL_SMTP_S_AUTH,
    VESMAIL_SMTP_S_CONN,
    VESMAIL_SMTP_S_PROXY,
    VESMAIL_SMTP_S_HOLD,
    VESMAIL_SMTP_S_DATA
};
#define VESMAIL_VERB(verb)	VESMAIL_SMTP_M_ ## verb,
enum VESmail_smtp_mode { VESMAIL_SMTP_MODES() VESMAIL_SMTP_M__END };
#undef VESMAIL_VERB

typedef struct VESmail_smtp {
    VESMAIL_ENUM(VESmail_smtp_state) state;
    VESMAIL_ENUM(VESmail_smtp_mode) mode;
    short int flags;
    struct jVar *uconf;
    char *helo;
    struct VESmail_smtp_track *track;
    struct VESmail *mail;
    struct VESmail_smtp_debug {
	struct VESmail_smtp_debug *chain;
	char msg[12];
    } *debug;
    const char *lf;
    char **pbcc;
} VESmail_smtp;

#define	VESMAIL_MERR_BCC	0x0200

#define VESMAIL_SMTP(server)	((VESmail_smtp *) &server->ctl)

#define	VESMAIL_SMTP_F_PIPE	0x0001
#define	VESMAIL_SMTP_F_PLAIN	0x0002
#define	VESMAIL_SMTP_F_NOWARN	0x0010
#define	VESMAIL_SMTP_F_INIT	0

#define VESMAIL_VERB(verb)	VESMAIL_SMTP_V_ ## verb,
enum VESmail_smtp_verb { VESMAIL_SMTP_VERBS() VESMAIL_SMTP_V__END };
#undef VESMAIL_VERB

extern const char *VESmail_smtp_verbs[];
extern const char *VESmail_smtp_modes[];

struct VESmail_server *VESmail_server_new_smtp(struct VESmail_optns *optns);
int VESmail_smtp_debug_flush(struct VESmail_server *srv, int code, int dsn);
#define VESmail_smtp_get_bcc(srv)	(((VESmail_conf *)(srv->optns->ref))->bcc)
