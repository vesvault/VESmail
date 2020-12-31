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

typedef struct VESmail_daemon {
    const char *type;
    struct VESmail_conf *conf;
    struct jVar *jconf;
    struct VESmail_server *(* srvfn)(struct VESmail_optns *);
    void *thread;
    struct VESmail_proc *procs;
    struct {
	void *mutex;
	struct jTree *jtree;
    } sni;
    int sock;
    short int flags;
    char debug;
} VESmail_daemon;


// SIGHUP, SIGINT
#define VESMAIL_DAEMON_SIG_DOWN		1
#define VESMAIL_DAEMON_SIG_DOWN2	2

// SIGTERM
#define VESMAIL_DAEMON_SIG_TERM		15


#define VESMAIL_DAEMON_DEBUG(daemon, level, code)	if ((daemon)->debug >= (level)) { code; }

extern char VESmail_daemon_SIG;

struct VESmail_daemon *VESmail_daemon_new(struct VESmail_conf *conf, struct jVar *jconf, const char *type);
int VESmail_daemon_listen(struct VESmail_daemon *daemon);
int VESmail_daemon_watch(struct VESmail_daemon *daemon, void (* watchfn)(struct VESmail_proc *proc, void *arg), void *arg);
void VESmail_daemon_shutdown(struct VESmail_daemon *daemon);

struct VESmail_daemon **VESmail_daemon_execute(struct VESmail_conf *conf, struct jVar *jconf);
int VESmail_daemon_launchall(struct VESmail_daemon **daemons);
int VESmail_daemon_watchall(struct VESmail_daemon **daemons, void (* watchfn)(struct VESmail_proc *proc, void *arg), void *arg);
void VESmail_daemon_freeall(struct VESmail_daemon **daemons);
