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
	void (* wakefn)(struct VESmail_conf *);
    } log;
    struct {
	char *manifest;
	char **headers;
	void *reqStack;
	void *postStack;
	int (* feedbackFn)(const char *fbk);
	struct jVar *websock;
	long long int maxSize;
    } now;
    struct VESmail_now_oauth *oauth;
    int abuseSense;
    int dumpfd;
    char overrides;
    char guard;
    char allocd;
} VESmail_conf;

struct VESmail_conf_daemon {
    const char *type;
    char *host;
    char *port;
    struct VESmail_conf *conf;
    char debug;
    char tag;
};

struct jVar *VESmail_conf_read(const char *path, void (* errfn)(const char *, ...));
char *VESmail_conf_get_content(const char *path);
void VESmail_conf_apply(struct VESmail_conf *conf, struct jVar *jconf);
void VESmail_conf_applyroot(struct VESmail_conf *conf, struct jVar *jconf, int (* snifn)(struct VESmail_server *, const char *));
struct jVar *VESmail_conf_sni_read(struct VESmail_conf *conf, const char *sni, void (* errfn)(const char *, ...), unsigned long *mtime);
void VESmail_conf_setstr(char **val, struct jVar *conf);
struct VESmail_conf *VESmail_conf_clone(struct VESmail_conf *conf);
#ifdef va_arg
void VESmail_conf_vlog(struct VESmail_conf *conf, const char *fmt, va_list va);
#endif
void VESmail_conf_log(struct VESmail_conf *conf, const char *fmt, ...);
void VESmail_conf_closelog(struct VESmail_conf *conf);
void VESmail_conf_free(struct VESmail_conf *conf);

void VESmail_conf_setstr(char **val, struct jVar *conf);
int VESmail_conf_setpstr(char ***d, struct jVar *b, int f);

struct VESmail_conf_daemon *VESmail_conf_daemon_build(struct VESmail_conf *conf, struct jVar *jconf);
void VESmail_conf_daemon_free(struct VESmail_conf_daemon *cfd);

void VESmail_conf_addwebsock(struct VESmail_conf *conf, struct VESmail_conf_daemon *cd);
