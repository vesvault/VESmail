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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include "../VESmail.h"
#include "arch.h"
#include "conf.h"
#include "server.h"
#include "tls.h"
#include "daemon.h"
#include "proc.h"


void VESmail_proc_logfn(void *logref, const char *fmt, ...) {
    VESmail_proc *proc = logref;
    char fbuf[256];
    sprintf(fbuf, "[t%04d]: %s", proc->tid, fmt);
    va_list va;
    va_start(va, fmt);
    VESmail_conf_vlog(proc->conf, fbuf, va);
    va_end(va);
}

VESmail_proc *VESmail_proc_new(VESmail_daemon *daemon, int fd) {
    static void *tid_mutex = NULL;
    static short int tid = 1;
    VESmail_proc *proc = malloc(sizeof(VESmail_proc));
    proc->daemon = daemon;
    proc->conf = daemon->conf;
    proc->thread = NULL;
    proc->ref = NULL;
    proc->fdesc = fd;
    proc->flags = 0;
    VESmail_arch_mutex_lock(&tid_mutex);
    proc->tid = tid;
    if (++tid >= 10000) tid = 1;
    VESmail_arch_mutex_unlock(&tid_mutex);
    VESmail_server *srv = daemon->srvfn ? daemon->srvfn(daemon->conf->optns) : NULL;
    if ((proc->server = srv)) {
	srv->proc = proc;
	srv->debug = daemon->debug;
	srv->logfn = &VESmail_proc_logfn;
	srv->host = daemon->conf->hostname;
	VESmail_server_set_tls(srv, daemon->conf->tls);
	int r = VESmail_server_set_sock(srv, fd);
	if (r < 0) VESmail_proc_shutdown(proc, r);
    } else {
	VESmail_proc_free(proc);
	return NULL;
    }
    return proc;
}

int VESmail_proc_run(VESmail_proc *proc) {
    return VESmail_proc_shutdown(proc, VESmail_server_run(proc->server, VESMAIL_SRVR_NOTHR));
}

void *VESmail_proc_run_fn(void *ref) {
    VESmail_proc_run(ref);
    return NULL;
}

int VESmail_proc_launch(VESmail_proc *proc) {
    if (proc->thread) return 0;
    return VESmail_arch_thread(proc, &VESmail_proc_run_fn, &proc->thread);
}

int VESmail_proc_watch(VESmail_proc *proc, void (* watchfn)(struct VESmail_proc *, void *), void *arg) {
    if (proc->flags & VESMAIL_PRF_DONE) return 0;
    if (watchfn) watchfn(proc, arg);
    if (proc->flags & VESMAIL_PRF_SHUTDOWN) VESmail_proc_done(proc);
    return 1;
}

void VESmail_proc_kill(VESmail_proc *proc) {
    if (proc->server) proc->server->flags |= VESMAIL_SRVF_KILL;
}

int VESmail_proc_shutdown(VESmail_proc *proc, int e) {
    proc->exitcode = e;
    proc->flags |= VESMAIL_PRF_SHUTDOWN;
    return e;
}

void VESmail_proc_done(VESmail_proc *proc) {
    if (proc->server) {
	VESmail_server_free(proc->server);
	proc->server = NULL;
    }
    proc->flags |= VESMAIL_PRF_DONE;
}

void VESmail_proc_free(VESmail_proc *proc) {
    if (proc) {
	VESmail_arch_thread_done(proc->thread);
	VESmail_proc_done(proc);
    }
    free(proc);
}
