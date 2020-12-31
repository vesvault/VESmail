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

typedef struct VESmail_tls_client {
    char *peer;
    enum {
	VESMAIL_TLS_NONE,
	VESMAIL_TLS_OPTIONAL,
	VESMAIL_TLS_UNSECURE,
	VESMAIL_TLS_MEDIUM,
	VESMAIL_TLS_HIGH
    } level;
    char persist;
} VESmail_tls_client;

typedef struct VESmail_tls_server {
    void *ctx;
    char *cert;
    char *key;
    int (* snifn)(struct VESmail_server *srv, const char *sni);
    char persist;
    char sni_only;
} VESmail_tls_server;

struct VESmail_server;

int VESmail_tls_init();
struct VESmail_tls_client *VESmail_tls_client_new(struct jVar *conf, char *host);
int VESmail_tls_client_start(struct VESmail_server *srv, int starttls);
#define VESmail_tls_client_require(srv)	((srv)->tls.client->level > VESMAIL_TLS_OPTIONAL)
#define VESmail_tls_client_none(srv)	((srv)->tls.client->level == VESMAIL_TLS_NONE)
#define VESmail_tls_client_started(srv)	((srv)->flags & VESMAIL_SRVF_TLSC)
void VESmail_tls_client_done(struct VESmail_server *srv);

struct VESmail_tls_server *VESmail_tls_server_new();
struct VESmail_tls_server *VESmail_tls_server_clone(struct VESmail_tls_server *tls);
int VESmail_tls_server_start(struct VESmail_server *srv, int starttls);
#define VESmail_tls_server_allow_starttls(srv)	((srv)->tls.server && !((srv)->flags & VESMAIL_SRVF_TLSS))
#define VESmail_tls_server_allow_plain(srv)	(!(srv)->tls.server->sni_only)
void VESmail_tls_server_ctxinit(struct VESmail_server *srv);
void VESmail_tls_server_ctxreset(struct VESmail_tls_server *tls);
void VESmail_tls_server_done(struct VESmail_server *srv);
void VESmail_tls_server_free(struct VESmail_tls_server *tls);
