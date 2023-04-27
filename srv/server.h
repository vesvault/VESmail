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

struct VESmail_xform;
struct bio_st;

typedef struct VESmail_server {
    const char *type;
    struct bio_st *req_bio;
    struct bio_st *rsp_bio;
    struct VESmail_xform *req_in;
    struct VESmail_xform *req_out;
    struct VESmail_xform *rsp_in;
    struct VESmail_xform *rsp_out;
    int (*idlefn)(struct VESmail_server *, int);
    void (* debugfn)(struct VESmail_server *, const char *);
    void (* freefn)(struct VESmail_server *, int final);
    struct libVES *ves;
    struct VESmail_optns *optns;
    struct jVar *uconf;
    struct {
	struct VESmail_tls_server *server;
	struct VESmail_tls_client *client;
    } tls;
    struct VESmail_sasl *sasl;
    struct VESmail_override *override;
    const char *host;
    char *login;
    void (* logfn)(void *logref, const char *fmt, ...);
    int (* abusefn)(void *ref, void *key, int keylen, int val);
    struct VESmail_override * (* ovrdfn)(void *ref);
    union {
	struct VESmail_proc *proc;
	void *logref;
	void *abuseref;
	void *ovrdref;
	void *ref;
    };
    long tmout;
    short int flags;
    short int stat;
    char debug;
    unsigned char subcode;
    short int authcode;
    int dumpfd;
    long cycles;
    long long int lastwrite;
    long long int reqbytes;
    long long int rspbytes;
    char ctl[0];
} VESmail_server;

#define	VESMAIL_E_SRV_STARTTLS	-80

#define	VESMAIL_SRV_MAXLOGIN	79

#define	VESMAIL_SRVR_NOREQ	0x0001
#define	VESMAIL_SRVR_NORSP	0x0002
#define	VESMAIL_SRVR_NOTHR	0x0004
#define	VESMAIL_SRVR_NOLOOP	0x0008
#define	VESMAIL_SRVR_NOLOG	0x1000
#define	VESMAIL_SRVR_NOPOLL	0x2000

#define	VESMAIL_SRVF_OVER	0x0010
#define	VESMAIL_SRVF_SHUTDOWN	0x0020
#define	VESMAIL_SRVF_TMOUT	0x0040
#define	VESMAIL_SRVF_KILL	0x0080

#define	VESMAIL_SRVF_TLSS	0x0100
#define	VESMAIL_SRVF_TLSC	0x0200

#define	VESMAIL_SRVF_QUIET	0x0800

#define	VESMAIL_SRVF_DONE	0x8000

#define VESMAIL_SRV_DEBUG(srv, level, code)	if ((srv)->debug >= (level)) {\
    char debug[4096] = "[??]";\
    { code; }\
    (srv)->debugfn(srv, debug);\
}

#ifndef	VESMAIL_SRV_TMOUT
#define	VESMAIL_SRV_TMOUT	30
#endif

struct VESmail_server *VESmail_server_init(struct VESmail_server *srv, struct VESmail_optns *optns);
void VESmail_server_unset_fd(struct VESmail_server *srv);
int VESmail_server_set_bio(struct VESmail_server *srv, void *bio_in, void *bio_out);
int VESmail_server_set_fd(struct VESmail_server *srv, int in, int out);
int VESmail_server_set_sock(struct VESmail_server *srv, int sock);
void VESmail_server_set_keepalive(struct VESmail_server *srv);
int VESmail_server_run(struct VESmail_server *srv, int flags);
#define VESmail_server_set_tls(srv, _tls)	(srv->tls.server = _tls)
int VESmail_server_connectsk(struct VESmail_server *srv, const char *host, const char *port);
int VESmail_server_connect(struct VESmail_server *srv, struct jVar *conf, const char *dport);
int VESmail_server_disconnect(struct VESmail_server *srv);
#define VESmail_server_connected(srv)	((srv)->rsp_bio)
int VESmail_server_auth(struct VESmail_server *srv, const char *user, const char *pwd, int pwlen);
struct VESmail_sasl *VESmail_server_sasl_client(int mech, struct jVar *uconf);
char *VESmail_server_errorStr(struct VESmail_server *srv, int err);
char *VESmail_server_sockname(struct VESmail_server *srv, int peer);
void VESmail_server_bytes(struct VESmail_server *srv, int done, int st);
char *VESmail_server_timestamp();
#define VESmail_server_log(srv, ...)	((srv)->logfn && ((srv)->logfn((srv)->logref, __VA_ARGS__), 0))
int VESmail_server_logauth(struct VESmail_server *srv, int er, long usec);
#define VESmail_server_ERRCODE2(er)	"XVES" #er
#define VESmail_server_ERRCODE(er)	VESmail_server_ERRCODE2(er)
int VESmail_server_abuse_peer(struct VESmail_server *srv, int val);
int VESmail_server_abuse_user(struct VESmail_server *srv, int val);
void VESmail_server_shutdown(struct VESmail_server *srv);
void VESmail_server_free(struct VESmail_server *srv);
