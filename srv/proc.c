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
#include <jVar.h>
#include <time.h>
#include "../VESmail.h"
#include "../util/jTree.h"
#include "arch.h"
#include "conf.h"
#include "server.h"
#include "tls.h"
#include "daemon.h"
#include "override.h"
#include "proc.h"

#ifndef VESMAIL_LOCAL

#define	VESMAIL_PROC_ABUSE_GRACE	3600

jTree *VESmail_proc_abuse_jtree = NULL;
void *VESmail_proc_abuse_mutex = NULL;

struct VESmail_proc_abuse {
    unsigned long int tstamp;
    struct VESmail_proc_abuse_key {
	int len;
	char data[0];
    } key;
};

int VESmail_proc_abuse_cmpfn(void *a, void *b, void *arg) {
    struct VESmail_proc_abuse *aa = a;
    struct VESmail_proc_abuse *ab = b;
    if (aa->key.len > ab->key.len) {
	return 1;
    }
    if (aa->key.len < ab->key.len) {
	return -1;
    }
    return memcmp(aa->key.data, ab->key.data, aa->key.len);
}

int VESmail_proc_abusefn(void *ref, void *key, int keylen, int val) {
    struct VESmail_proc_abuse *ab = malloc(sizeof(struct VESmail_proc_abuse) + keylen);
    ab->key.len = keylen;
    memcpy(ab->key.data, key, keylen);
    time_t t = time(NULL);
    unsigned char depth = 0;
    VESmail_arch_mutex_lock(&VESmail_proc_abuse_mutex);
    void **ap = jTree_seek(&VESmail_proc_abuse_jtree, ab, NULL, &VESmail_proc_abuse_cmpfn, &depth);
    if (*ap) {
	free(ab);
	ab = *ap;
    } else {
	ab->tstamp = t - VESMAIL_PROC_ABUSE_GRACE;
	*ap = ab;
    }
    int dt = t - ab->tstamp;
    if (dt > VESMAIL_PROC_ABUSE_GRACE) {
	ab->tstamp = t - VESMAIL_PROC_ABUSE_GRACE;
    }
    if (val > 0) {
	ab->tstamp += val * ((VESmail_proc *) ref)->conf->abuseSense;
    }
    VESmail_arch_mutex_unlock(&VESmail_proc_abuse_mutex);
    return t - ab->tstamp;
}

#endif

void VESmail_proc_logfn(void *logref, const char *fmt, ...) {
    VESmail_proc *proc = logref;
    char fbuf[256];
    sprintf(fbuf, "[t%04d]: %s", proc->tid, fmt);
    va_list va;
    va_start(va, fmt);
    VESmail_conf_vlog(proc->conf, fbuf, va);
    va_end(va);
}

VESmail_override *VESmail_proc_ovrdfn(void *ovrdref) {
    return VESmail_override_new(VESmail_override_mode(((VESmail_proc *) ovrdref)->conf));
}

static void *VESmail_proc_tid_mutex = NULL;

VESmail_proc *VESmail_proc_init(VESmail_proc *proc, VESmail_daemon *daemon, int fd) {
    static short int tid = 1;
    if (!proc) proc = malloc(sizeof(VESmail_proc));
    proc->daemon = daemon;
    proc->conf = daemon->conf;
    proc->thread = NULL;
    proc->ctx = NULL;
    proc->ref = NULL;
    proc->collectfn = NULL;
    proc->freefn = NULL;
    proc->fdesc = fd;
    proc->flags = 0;
    VESmail_arch_mutex_lock(&VESmail_proc_tid_mutex);
    proc->tid = tid;
    if (++tid >= 10000) tid = 1;
    VESmail_arch_mutex_unlock(&VESmail_proc_tid_mutex);
    VESmail_server *srv = daemon->srvfn ? daemon->srvfn(daemon->conf->optns) : NULL;
    if ((proc->server = srv)) {
	srv->proc = proc;
	srv->debug = daemon->debug;
	srv->logfn = &VESmail_proc_logfn;
	srv->host = daemon->conf->hostname;
	srv->ovrdfn = &VESmail_proc_ovrdfn;
	srv->dumpfd = daemon->conf->dumpfd;
	VESmail_server_set_tls(srv, daemon->conf->tls);
#ifndef VESMAIL_LOCAL
	if (daemon->conf->abuseSense > 0) srv->abusefn = &VESmail_proc_abusefn;
#endif
	if (fd >= 0) {
	    int r = VESmail_server_set_sock(srv, fd);
	    if (r < 0) VESmail_proc_shutdown(proc, r);
	}
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
    int shtdn = proc->flags & VESMAIL_PRF_SHUTDOWN;
    if (watchfn) watchfn(proc, arg);
    if (shtdn) VESmail_proc_done(proc);
    return 1;
}

void VESmail_proc_kill(VESmail_proc *proc) {
    if (proc->server) proc->server->flags |= VESMAIL_SRVF_KILL;
}

int VESmail_proc_shutdown(VESmail_proc *proc, int e) {
    proc->exitcode = e;
    if (proc->server) {
	if (proc->collectfn) proc->collectfn(proc);
	VESmail_server_shutdown(proc->server);
    }
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
#ifndef VESMAIL_LOCAL
	VESmail_proc_ctx_free(proc->ctx);
#endif
	if (proc->freefn) proc->freefn(proc);
    }
    free(proc);
}

#ifndef VESMAIL_LOCAL

struct VESmail_proc_ctx *VESmail_proc_ctx_new(struct VESmail_proc *proc, jVar *jconf) {
    if (!jconf) return NULL;
    struct VESmail_proc_ctx *ctx = malloc(sizeof(struct VESmail_proc_ctx));
    ctx->jconf = jconf;
    ctx->conf = VESmail_conf_clone(proc->daemon->conf);
    VESmail_conf_apply(ctx->conf, jVar_get(jconf, "*"));
    VESmail_conf_apply(ctx->conf, jVar_get(jconf, proc->server->type));
    ctx->refct = 1;
    return ctx;
}

void VESmail_proc_ctx_apply(struct VESmail_proc_ctx *ctx, VESmail_proc *proc) {
    if (!ctx) return;
    VESmail_proc_ctx_free(proc->ctx);
    proc->ctx = ctx;
    proc->conf = ctx->conf;
    proc->server->optns = ctx->conf->optns;
    proc->server->tls.server = ctx->conf->tls;
    ctx->refct++;
}

void VESmail_proc_ctx_free(struct VESmail_proc_ctx *ctx) {
    if (ctx && --ctx->refct <= 0) {
	VESmail_conf_free(ctx->conf);
	jVar_free(ctx->jconf);
	free(ctx);
    }
}

void VESmail_proc_cleanup() {
    void **pobj;
    for (pobj = jTree_first(VESmail_proc_abuse_jtree); pobj; pobj = jTree_next(pobj)) {
	free(*pobj);
	*pobj = NULL;
    }
    jTree_collapse(&VESmail_proc_abuse_jtree);
    VESmail_arch_mutex_done(VESmail_proc_abuse_mutex);
#else

void VESmail_proc_cleanup() {
#endif
    VESmail_arch_mutex_done(VESmail_proc_tid_mutex);
}
