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

struct jVar;
struct VESmail_optns;
struct VESmail_tls_server;
struct VESmail_tls_client;
struct VESmail_server;

typedef struct VESmail_conf {
    struct VESmail_optns *optns;
    struct VESmail_tls_server *tls;
    const char *hostname;
    const char *progpath;
    const char *progname;
    const char **banner;
    char **bannerPath;
    char *manifest;
    struct jVar *app;
    void *mutex;
    struct {
	char *prefix;
	char *suffix;
	int require;
    } sni;
    struct {
	char *filename;
	void *fh;
    } log;
    char guard;
} VESmail_conf;

struct jVar *VESmail_conf_read(const char *path, void (* errfn)(const char *, ...));
char *VESmail_conf_get_content(const char *path);
void VESmail_conf_apply(struct VESmail_conf *conf, struct jVar *jconf);
void VESmail_conf_applyroot(struct VESmail_conf *conf, struct jVar *jconf, int (* snifn)(struct VESmail_server *, const char *));
struct jVar *VESmail_conf_sni_read(struct VESmail_conf *conf, const char *sni, void (* errfn)(const char *, ...));
void VESmail_conf_setstr(char **val, struct jVar *conf);
struct VESmail_conf *VESmail_conf_clone(struct VESmail_conf *conf);
void VESmail_conf_vlog(struct VESmail_conf *conf, const char *fmt, void *va);
void VESmail_conf_closelog(struct VESmail_conf *conf);
void VESmail_conf_free(struct VESmail_conf *conf);
