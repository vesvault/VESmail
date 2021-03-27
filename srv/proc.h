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

typedef struct VESmail_proc {
    struct VESmail_daemon *daemon;
    struct VESmail_conf *conf;
    struct VESmail_proc *chain;
    void *thread;
    struct VESmail_server *server;
    struct VESmail_proc_ctx {
	struct VESmail_conf *conf;
	struct jVar *jconf;
	int refct;
    } *ctx;
    void *ref;
    int fdesc;
    short int tid;
    char flags;
    char exitcode;
} VESmail_proc;

#define	VESMAIL_PRF_SHUTDOWN	0x01
#define	VESMAIL_PRF_DONE	0x02

struct VESmail_proc *VESmail_proc_new(struct VESmail_daemon *daemon, int fd);
int VESmail_proc_launch(struct VESmail_proc *proc);
int VESmail_proc_watch(struct VESmail_proc *proc, void (* watchfn)(struct VESmail_proc *, void *), void *arg);
int VESmail_proc_shutdown(struct VESmail_proc *proc, int e);
void VESmail_proc_kill(struct VESmail_proc *proc);
void VESmail_proc_done(struct VESmail_proc *proc);
void VESmail_proc_free(struct VESmail_proc *proc);

struct VESmail_proc_ctx *VESmail_proc_ctx_new(struct VESmail_proc *proc, struct jVar *jconf);
void VESmail_proc_ctx_apply(struct VESmail_proc_ctx *ctx, struct VESmail_proc *proc);
void VESmail_proc_ctx_free(struct VESmail_proc_ctx *ctx);
void VESmail_proc_cleanup();
