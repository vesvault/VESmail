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

struct VESmail_imap_token;
struct VESmail_imap_xform;
struct VESmail_server;
struct VESmail_optns;

typedef struct VESmail_imap {
    enum {
	VESMAIL_IMAP_S_HELLO,
	VESMAIL_IMAP_S_START,
	VESMAIL_IMAP_S_CONN,
	VESMAIL_IMAP_S_LOGIN,
	VESMAIL_IMAP_S_PROXY,
	VESMAIL_IMAP_S_SHUTDOWN
    } state;
    char _algn;
    short int flags;
    struct jVar *uconf;
    struct VESmail_imap_track *track;
    struct VESmail_imap_track *reqq;
    struct VESmail_imap_token *cont;
    int (* untaggedfn)(int, struct VESmail_imap_token *, struct VESmail_server *);
    struct {
	union VESmail_imap_msg_page {
	    union VESmail_imap_msg_page *page;
	    struct VESmail_imap_msg *msg;
	    void *ptr;
	} page;
	unsigned short int depth;
	unsigned short int pagesize;
    } msgs;
    struct {
	struct VESmail_imap_result *queue;
	struct VESmail_imap_result **tail;
	struct VESmail_imap_result *curr;
	struct VESmail_imap_track *track;
	struct VESmail_imap_fetch *filter;
	struct VESmail_imap_msg *pass;
	struct VESmail_imap_token *query;
    } results;
    int ctBad;
    int ctOOR;
} VESmail_imap;

#define VESMAIL_IMAP(server)	((VESmail_imap *) &server->ctl)

#define	VESMAIL_IMAP_F_BYE	0x0001
#define	VESMAIL_IMAP_F_CDATA	0x0002
#define	VESMAIL_IMAP_F_RSP	0x0004

#define	VESMAIL_IMAP_F_MIMEBUG	0x0010
#define	VESMAIL_IMAP_F_MIMEOK	0x0020

#define VESMAIL_IMAP_F_CALC	0x0100
#define VESMAIL_IMAP_F_ORDER	0x0200

#define	VESMAIL_IMAP_F_INIT	0

#define VESMAIL_IMAP_OOR_SENSE	16

struct VESmail_parse;

#define VESMAIL_IMAP_VERBS() \
VESMAIL_VERB(OK) \
VESMAIL_VERB(NO) \
VESMAIL_VERB(BAD) \
VESMAIL_VERB(NOOP) \
VESMAIL_VERB(CAPABILITY) \
VESMAIL_VERB(ID) \
VESMAIL_VERB(STARTTLS) \
VESMAIL_VERB(LOGIN) \
VESMAIL_VERB(AUTHENTICATE) \
VESMAIL_VERB(UID) \
VESMAIL_VERB(FLAGS) \
VESMAIL_VERB(FETCH) \
VESMAIL_VERB(APPEND) \
VESMAIL_VERB(EXPUNGE) \
VESMAIL_VERB(LOGOUT) \
VESMAIL_VERB(PREAUTH) \
VESMAIL_VERB(BYE) \
VESMAIL_VERB(COMPRESS) \
VESMAIL_VERB(XVES)

#define VESMAIL_VERB(verb)	VESMAIL_IMAP_V_ ## verb,
enum { VESMAIL_IMAP_VERBS() VESMAIL_IMAP_V__END };
#undef VESMAIL_VERB

extern const char *VESmail_imap_verbs[];

struct VESmail_server *VESmail_server_new_imap(struct VESmail_optns *optns);
int VESmail_imap_get_verb(struct VESmail_imap_token *token, const char **verbs);
struct VESmail_imap_token *VESmail_imap_cp_tag(struct VESmail_imap_token *cmd);
int VESmail_imap_rsp_send(struct VESmail_server *srv, struct VESmail_imap_token *rsp);
int VESmail_imap_req_fwd(struct VESmail_server *srv, struct VESmail_imap_token *req);
int VESmail_imap_req_abort(struct VESmail_server *srv);
#define VESmail_imap_req_ready(srv)	(!VESMAIL_IMAP(srv)->cont)
int VESmail_imap_rsp_send_bad(struct VESmail_server *srv, struct VESmail_imap_token *tag, const char *msg);
int VESmail_imap_rsp_send_error(struct VESmail_server *srv, struct VESmail_imap_token *tag, int err);
struct VESmail_imap_token *VESmail_imap_req_detach(struct VESmail_server *srv, struct VESmail_imap_token *token);
struct VESmail_imap_token *VESmail_imap_rsp_detach(struct VESmail_server *srv, struct VESmail_imap_token *token);
void VESmail_imap_debug_token(struct VESmail_server *srv, int lvl, const char *label, struct VESmail_imap_token *token);
int VESmail_imap_cont(struct VESmail_server *srv, const char *msg);

struct VESmail_imap_token *VESmail_imap_req_new(struct VESmail_imap_token *tag, const char *verb);
struct VESmail_imap_token *VESmail_imap_rsp_new(struct VESmail_imap_token *tag, const char *verb);

struct VESmail_imap_token *VESmail_imap_caps(struct VESmail_server *srv, struct VESmail_imap_token *token, int start);

#define VESmail_imap_ARG_CHK(err, srv, token, idx, type)	if (err >= 0) {\
    if (token->len > idx) {\
	if (token->len == idx + 1 && token->state == VESMAIL_IMAP_P_CONT) {\
	    err = VESmail_imap_cont(srv, "OK");\
	    if (err >= 0) return err;\
	}\
    } else if (token->state == VESMAIL_IMAP_P_DONE) {\
	err = VESMAIL_E_PARAM;\
    } else {\
	err = VESmail_imap_cont(srv, "OK");\
	if (err >= 0) return err;\
    }\
}

void VESmail_imap_reset(struct VESmail_server *srv);
