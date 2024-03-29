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
#include <jVar.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include "../VESmail.h"
#include "../imap/imap.h"
#include "../smtp/smtp.h"
#include "../now/now.h"
#include "../util/jTree.h"
#include "arch.h"
#include "conf.h"
#include "server.h"
#include "tls.h"
#include "proc.h"
#include "daemon.h"


VESmail_daemon *VESmail_daemon_new(struct VESmail_conf_daemon *cd) {
    struct addrinfo hint = {
	.ai_family = VESMAIL_DAEMON_AF,
	.ai_socktype = SOCK_STREAM,
	.ai_protocol = 0,
	.ai_flags = AI_ADDRCONFIG | AI_PASSIVE,
	.ai_addrlen = 0,
	.ai_addr = NULL,
	.ai_canonname = NULL,
	.ai_next = NULL
    };
    struct addrinfo *ai = NULL;
    int r = getaddrinfo(cd->host, cd->port, &hint, &ai);
    if (r) return NULL;
    VESmail_daemon *daemon = malloc(sizeof(VESmail_daemon));
    daemon->type = cd->type;
    VESmail_conf_log(cd->conf, "start daemon=%s host=%s port=%s", cd->type, (cd->host ? cd->host : ""), (cd->port ? cd->port : ""));
    if (!strcmp(cd->type, "imap")) {
	daemon->srvfn = &VESmail_server_new_imap;
    } else if (!strcmp(cd->type, "smtp")) {
	daemon->srvfn = &VESmail_server_new_smtp;
    } else if (!strcmp(cd->type, "now")) {
	daemon->srvfn = &VESmail_server_new_now;
    } else {
	daemon->srvfn = NULL;
    }
    daemon->conf = cd->conf;
    daemon->debug = cd->debug;
    daemon->tag = cd->tag;
    daemon->sni.mutex = NULL;
    daemon->sni.jtree = NULL;
    struct VESmail_daemon_sock **psk = &daemon->sock;
    struct VESmail_daemon_sock *sk;
    struct addrinfo *a;
    for (a = ai; a; a = a->ai_next) {
	*psk = sk = malloc(sizeof(**psk));
	sk->daemon = daemon;
	sk->ainfo = a;
	sk->procs = NULL;
	sk->thread = NULL;
	sk->sock = VESMAIL_DMSK_NONE;
	psk = &sk->chain;
    }
    *psk = NULL;
    daemon->flags = 0;
    daemon->ref = NULL;
    return daemon;
}

int VESmail_daemon_sock_error(struct VESmail_daemon_sock *sk) {
    if (sk->sock >= 0) {
	VESmail_arch_shutdown(sk->sock);
	sk->sock = VESMAIL_DMSK_NONE;
    }
    return VESMAIL_E_CONN;
}

int VESmail_daemon_sock_listen(struct VESmail_daemon_sock *sk) {
    if (sk->sock >= 0) return 0;
    int fd = socket(sk->ainfo->ai_family, sk->ainfo->ai_socktype, sk->ainfo->ai_protocol);
    if (fd < 0) return VESMAIL_E_CONN;
    int flg = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &flg, sizeof(flg));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (void *) &flg, sizeof(flg));
#endif
    sk->sock = fd;
    VESMAIL_DAEMON_DEBUG(sk->daemon, 1, {
	char abuf[64];
	char pbuf[16];
	getnameinfo(sk->ainfo->ai_addr, sk->ainfo->ai_addrlen, abuf, sizeof(abuf), pbuf, sizeof(pbuf), NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "Binding to [%s]:%s ...\n", abuf, pbuf);
    })
    int connr;
    if ((connr = bind(sk->sock, sk->ainfo->ai_addr, sk->ainfo->ai_addrlen)) < 0) {
	VESMAIL_DAEMON_DEBUG(sk->daemon, 1, fprintf(stderr, "... bind failed (%d)\n", connr));
	return VESmail_daemon_sock_error(sk);
    }
    if ((connr = listen(sk->sock, 16)) < 0) {
	VESMAIL_DAEMON_DEBUG(sk->daemon, 1, fprintf(stderr, "... listen failed (%d)\n", connr));
	return VESmail_daemon_sock_error(sk);
    }
    if ((sk->daemon->flags & VESMAIL_DMF_NB) && (connr = VESmail_arch_set_nb(sk->sock, 1)) < 0) {
	VESMAIL_DAEMON_DEBUG(sk->daemon, 1, fprintf(stderr, "... set_nb failed (%d)\n", connr));
	return VESmail_daemon_sock_error(sk);
    }
    VESMAIL_DAEMON_DEBUG(sk->daemon, 1, fprintf(stderr, "... success\n"));
    return 0;
}

int VESmail_daemon_listen(VESmail_daemon *daemon) {
    struct VESmail_daemon_sock *sk;
    for (sk = daemon->sock; sk; sk = sk->chain) {
	int r = sk->ainfo ? VESmail_daemon_sock_listen(sk) : 0;
	if (r < 0) return r;
    }
    return 0;
}

int VESmail_daemon_sock_run(struct VESmail_daemon_sock *sk) {
    if (sk->sock < 0) while (VESmail_daemon_sock_listen(sk)) {
	if (sk->daemon->flags & VESMAIL_DMF_NB) return VESMAIL_E_CONN;
	VESmail_arch_usleep(15000000);
    }
    int fd;
    while (sk->sock != VESMAIL_DMSK_DOWN) {
	fd = accept(sk->sock, NULL, NULL);
	if (fd >= 0) {
	    VESmail_proc *p = VESmail_proc_new(sk->daemon, fd);
	    if (p) {
		p->chain = sk->procs;
		sk->procs = p;
		if (p->flags & VESMAIL_PRF_SHUTDOWN) {
		    VESmail_arch_shutdown(fd);
		} else {
		    VESmail_proc_launch(p);
		}
	    }
	} else {
	    int er = errno;
	    if (!(sk->daemon->flags & VESMAIL_DMF_NB) && !(er == EINTR || er == EAGAIN || er == EWOULDBLOCK)) {
		VESmail_arch_usleep(1000000);
	    }
	    if ((sk->daemon->flags & VESMAIL_DMF_RECONNECT) && er == EBADF) {
		VESmail_daemon_sock_error(sk);
		VESmail_arch_log("reconnect daemon=%s", sk->daemon->type);
		if (sk->daemon->flags & VESMAIL_DMF_NB) return VESMAIL_E_IO;
		while (VESmail_daemon_sock_listen(sk)) {
		    VESmail_arch_usleep(5000000);
		};
	    }
	}
	if (sk->daemon->flags & VESMAIL_DMF_NB) break;
    }
    return 0;
}

void *VESmail_daemon_sock_run_fn(void *ptr) {
    VESmail_daemon_sock_run(ptr);
    return NULL;
}

int VESmail_daemon_launch(VESmail_daemon *daemon) {
    VESMAIL_DAEMON_DEBUG(daemon, 2, fprintf(stderr, "Launching %s...\n", daemon->type))
    struct VESmail_daemon_sock *sk;
    for (sk = daemon->sock; sk; sk = sk->chain) if (!sk->thread) {
	int r = VESmail_arch_thread(sk, &VESmail_daemon_sock_run_fn, &sk->thread);
	if (r < 0) return r;
    }
    return 0;
}

#ifndef VESMAIL_LOCAL

struct VESmail_daemon_snirec {
    struct VESmail_proc_ctx *ctx;
    unsigned long mtime;
    char sni[0];
};

int VESmail_daemon_snicmpfn(void *data, void *term, void *arg) {
    return strcmp(((struct VESmail_daemon_snirec *) data)->sni, (const char *) term);
}

void VESmail_daemon_snierrfn(const char *fmt, ...) {
    char fb[256];
    sprintf(fb, "sni error %s", fmt);
    va_list va;
    va_start(va, fmt);
    VESmail_arch_vlog(fb, va);
    va_end(va);
}

int VESmail_daemon_snifn(VESmail_server *srv, const char *sni) {
    VESmail_daemon *daemon = srv->proc->daemon;
    VESmail_server_log(srv, "sni host=%s", sni);
    int r = VESmail_arch_mutex_lock(&daemon->sni.mutex);
    if (r) return r;
    unsigned char depth;
    struct VESmail_daemon_snirec *rec;
    void **pobj = jTree_seek(&daemon->sni.jtree, (void *) sni, NULL, &VESmail_daemon_snicmpfn, &depth);
    if (*pobj) {
	rec = *pobj;
	VESMAIL_DAEMON_DEBUG(daemon, 2, fprintf(stderr, "sni rec loaded for %s: %p\n", sni, rec))
    } else {
	rec = malloc(sizeof(struct VESmail_daemon_snirec) + strlen(sni) + 1);
	strcpy(rec->sni, sni);
	rec->ctx = NULL;
	rec->mtime = 0;
	*pobj = rec;
    }
    jVar *jconf = VESmail_conf_sni_read(daemon->conf, sni, &VESmail_daemon_snierrfn, &rec->mtime);
    if (jconf) {
	VESmail_server_log(srv, "sni conf loaded");
	VESmail_proc_ctx_free(rec->ctx);
	rec->ctx = VESmail_proc_ctx_new(srv->proc, jconf);
    } else if (!rec->ctx && daemon->conf->sni.require) {
	r = VESMAIL_E_CONF;
    }
    VESmail_proc_ctx_apply(rec->ctx, srv->proc);
    VESmail_arch_mutex_unlock(&daemon->sni.mutex);
    return r;
}

void VESmail_daemon_snifree(VESmail_daemon *daemon) {
    void **pobj;
    for (pobj = jTree_first(daemon->sni.jtree); pobj; pobj = jTree_next(pobj)) {
	struct VESmail_daemon_snirec *rec = *pobj;
	if (rec) {
	    VESmail_proc_ctx_free(rec->ctx);
	    free(rec);
	    *pobj = NULL;
	}
    }
    jTree_collapse(&daemon->sni.jtree);
    VESmail_arch_mutex_done(daemon->sni.mutex);
}

#endif

char VESmail_daemon_SIG = 0;

void VESmail_daemon_sigfn(int sig) {
    if (sig == VESMAIL_DAEMON_SIG_BRK) return;
    if (sig == VESMAIL_DAEMON_SIG_TERM || !VESmail_daemon_SIG) VESmail_daemon_SIG = sig;
}

int VESmail_daemon_sock_watch(struct VESmail_daemon_sock *sk, void (* watchfn)(VESmail_proc *, void *), void *arg) {
    VESmail_proc *p = sk->procs;
    VESmail_proc *p2;
    int rs = 0;
    if (sk->sock >= 0) rs++;
    if (p) {
	int kl = VESmail_daemon_SIG == VESMAIL_DAEMON_SIG_TERM;
	if (kl) VESmail_proc_kill(p);
	rs += VESmail_proc_watch(p, watchfn, arg);
	for (; (p2 = p->chain); p = p2) {
	    if (kl) VESmail_proc_kill(p2);
	    rs += VESmail_proc_watch(p2, watchfn, arg);
	    if (p2->flags & VESMAIL_PRF_DONE) {
		p->chain = p2->chain;
		VESmail_proc_free(p2);
		p2 = p;
	    }
	}
    }
    return rs;
}

int VESmail_daemon_watch(VESmail_daemon *daemon, void (* watchfn)(VESmail_proc *, void *), void *arg) {
    if (VESmail_daemon_SIG) {
	if (VESmail_daemon_shutdown(daemon) > 0) VESmail_arch_log("shutdown daemon=%s sig=%d", daemon->type, VESmail_daemon_SIG);
    }
    struct VESmail_daemon_sock *sk;
    int rs = 0;
    for (sk = daemon->sock; sk; sk = sk->chain) {
	rs += VESmail_daemon_sock_watch(sk, watchfn, arg);
    }
    return rs;
}

int VESmail_daemon_shutdown(VESmail_daemon *daemon) {
    int rs = 0;
    struct VESmail_daemon_sock *sk;
    for (sk = daemon->sock; sk; sk = sk->chain) {
	if (sk->sock >= 0) {
	    if (!(daemon->flags & VESMAIL_DMF_KEEPSOCK)) VESmail_arch_shutdown(sk->sock);
	    sk->sock = VESMAIL_DMSK_DOWN;
	    VESmail_arch_thread_kill(sk->thread);
	    rs++;
	}
    }
    return rs;
}

void VESmail_daemon_free(VESmail_daemon *daemon) {
    if (daemon) {
	if (daemon->sock && daemon->sock->ainfo) freeaddrinfo(daemon->sock->ainfo);
	struct VESmail_daemon_sock *sk, *sknext;
	for (sk = daemon->sock; sk; sk = sknext) {
	    sknext = sk->chain;
	    VESmail_arch_thread_done(sk->thread);
	    while (sk->procs) {
		VESmail_proc *p = sk->procs;
		sk->procs = p->chain;
		VESmail_proc_free(p);
	    }
	    free(sk);
	}
#ifndef VESMAIL_LOCAL
	VESmail_daemon_snifree(daemon);
#endif
    }
    free(daemon);
}


/****************************************************************
 * VESmail_daemon_execute() is supposed to be called once per pid,
 * not bothering with memory deallocation on failure
 ****************************************************************/
VESmail_daemon **VESmail_daemon_execute(struct VESmail_conf_daemon *cds) {
    if (!cds) return NULL;
    VESmail_arch_sigaction(VESMAIL_DAEMON_SIG_BRK, &VESmail_daemon_sigfn);
    VESmail_arch_sigaction(VESMAIL_DAEMON_SIG_DOWN, &VESmail_daemon_sigfn);
    VESmail_arch_sigaction(VESMAIL_DAEMON_SIG_TERM, &VESmail_daemon_sigfn);
    struct VESmail_conf_daemon *cdp;
    int i = 1;
    for (cdp = cds; cdp->type; cdp++) i++;
    VESmail_daemon **daemons = malloc(i * sizeof(VESmail_daemon *));
    VESmail_daemon **dp = daemons;
    cdp = cds;
    for (i = 0; cdp->type; i++) {
#ifndef VESMAIL_LOCAL
	if (cdp->conf->tls->snifn) cdp->conf->tls->snifn = &VESmail_daemon_snifn;
#endif
	if ((*dp = VESmail_daemon_new(cdp++))) dp++;
    }
    *dp = NULL;
    return daemons;
}

int VESmail_daemon_prepall(VESmail_daemon **daemons, int **pfd) {
    VESmail_daemon **pd, *d;
    int ct = 0;
    for (pd = daemons; (d = *pd); pd++) {
	d->flags |= VESMAIL_DMF_NB;
	struct VESmail_daemon_sock *sk;
	for (sk = d->sock; sk; sk = sk->chain) {
	    if (!sk->ainfo) continue;
	    if (sk->sock == VESMAIL_DMSK_NONE) VESmail_daemon_sock_listen(sk);
	    if (pfd) *pfd++ = &sk->sock;
	    ct++;
	}
    }
    if (pfd) *pfd = NULL;
    return ct;
}

int VESmail_daemon_pollall(VESmail_daemon **daemons) {
    VESmail_daemon **pd, *d;
    int rs = 0;
    for (pd = daemons; (d = *pd); pd++) if (d->flags & VESMAIL_DMF_NB) {
	struct VESmail_daemon_sock *sk;
	for (sk = d->sock; sk; sk = sk->chain) if (sk->ainfo) {
	    int r = VESmail_daemon_sock_run(sk);
	    if (rs >= 0) rs = r >= 0 ? rs + r : r;
	}
    }
    return rs;
}

int VESmail_daemon_launchall(VESmail_daemon **daemons) {
    VESmail_daemon **pd;
    for (pd = daemons; *pd; pd++) {
	int r = VESmail_daemon_launch(*pd);
	if (r < 0) return r;
    }
    return pd - daemons;
}

int VESmail_daemon_watchall(VESmail_daemon **daemons, void (* watchfn)(VESmail_proc *, void *), void *arg) {
    VESmail_daemon **pd;
    VESmail_daemon *d;
    int rs = 0;
    for (pd = daemons; (d = *pd); pd++) {
	rs += VESmail_daemon_watch(d, watchfn, arg);
    }
    if (watchfn) watchfn(NULL, arg);
    return rs;
}

void VESmail_daemon_killall(VESmail_daemon **daemons) {
    VESmail_daemon **pd;
    for (pd = daemons; *pd; pd++) {
	struct VESmail_daemon_sock *sk;
	for (sk = (*pd)->sock; sk; sk = sk->chain) {
	    VESmail_daemon_sock_error(sk);
	    VESmail_proc *proc;
	    for (proc = sk->procs; proc; proc = proc->chain) {
		VESmail_proc_kill(proc);
	    }
	}
    }
}

void VESmail_daemon_freeall(VESmail_daemon **daemons) {
    VESmail_daemon **pd;
    if (daemons) for (pd = daemons; *pd; pd++) {
	VESmail_daemon_free(*pd);
    }
    free(daemons);
}
