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

#ifndef VESMAIL_X509STORE
extern char *VESmail_tls_caBundle;
#endif

#ifndef VESMAIL_ENUM
#define	VESMAIL_ENUM(_type)	unsigned char
#endif

#define VESMAIL_TLS_LEVELS() \
    VESMAIL_VERB(NONE, "none") \
    VESMAIL_VERB(OPTIONAL, "optional") \
    VESMAIL_VERB(UNSECURE, "unsecure") \
    VESMAIL_VERB(MEDIUM, "medium") \
    VESMAIL_VERB(HIGH, "high")

#define VESMAIL_VERB(verb, str)	VESMAIL_TLS_ ## verb,
enum VESmail_tls_level { VESMAIL_TLS_LEVELS() VESMAIL_TLS__END };
#undef VESMAIL_VERB

typedef struct VESmail_tls_client {
    char *peer;
    VESMAIL_ENUM(VESmail_tls_level) level;
    char persist;
} VESmail_tls_client;

typedef struct VESmail_tls_server {
    void *ctx;
    char *cert;
    char *key;
    int (* snifn)(struct VESmail_server *srv, const char *sni);
    VESMAIL_ENUM(VESmail_tls_level) level;
    char persist;
} VESmail_tls_server;

struct VESmail_server;

extern const char *VESmail_tls_levels[];

int VESmail_tls_init();
void VESmail_tls_applyCA(void *ctx);
struct VESmail_tls_client *VESmail_tls_client_new(struct jVar *conf, char *host);
int VESmail_tls_client_start(struct VESmail_server *srv, int starttls);
#define VESmail_tls_client_require(srv)	((srv)->tls.client->level > VESMAIL_TLS_OPTIONAL)
#define VESmail_tls_client_none(srv)	((srv)->tls.client->level == VESMAIL_TLS_NONE)
#define VESmail_tls_client_started(srv)	((srv)->flags & VESMAIL_SRVF_TLSC)
void VESmail_tls_client_done(struct VESmail_server *srv);

struct VESmail_tls_server *VESmail_tls_server_new();
struct VESmail_tls_server *VESmail_tls_server_clone(struct VESmail_tls_server *tls);
int VESmail_tls_server_start(struct VESmail_server *srv, int starttls);
#define VESmail_tls_server_allow_starttls(srv)	((srv)->tls.server && (srv)->tls.server->cert && (srv)->tls.server->key && (srv)->tls.server->level > VESMAIL_TLS_NONE && !((srv)->flags & VESMAIL_SRVF_TLSS))
#define VESmail_tls_server_allow_plain(srv)	(VESmail_tls_server_started(srv) || (srv)->tls.server->level <= VESMAIL_TLS_OPTIONAL)
#define VESmail_tls_server_started(srv)	((srv)->flags & VESMAIL_SRVF_TLSS)
void VESmail_tls_server_ctxinit(struct VESmail_server *srv);
void VESmail_tls_server_ctxreset(struct VESmail_tls_server *tls);
void VESmail_tls_server_done(struct VESmail_server *srv);
void VESmail_tls_server_free(struct VESmail_tls_server *tls);

struct libVES *VESmail_tls_initVES(struct libVES *ves);
