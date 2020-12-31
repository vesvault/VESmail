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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#endif

#include <jVar.h>
#include <stdarg.h>
#include <stdio.h>
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


VESmail_daemon *VESmail_daemon_new(VESmail_conf *conf, jVar *jconf, const char *type) {
    VESmail_daemon *daemon = malloc(sizeof(VESmail_daemon));
    daemon->type = type;
    daemon->conf = conf;
    daemon->jconf = jconf;
    daemon->thread = NULL;
    daemon->procs = NULL;
    daemon->sock = -1;
    daemon->debug = jVar_getInt(jVar_get(jconf, "debug"));
    daemon->sni.mutex = NULL;
    daemon->sni.jtree = NULL;
    return daemon;
}

int VESmail_daemon_listen(VESmail_daemon *daemon) {
    char *host = jVar_getString(jVar_get(daemon->jconf, "host"));
    char *port = jVar_getString(jVar_get(daemon->jconf, "port"));
    struct addrinfo hint = {
	.ai_family = AF_UNSPEC,
	.ai_socktype = SOCK_STREAM,
	.ai_protocol = 0,
	.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_PASSIVE,
	.ai_addrlen = 0,
	.ai_addr = NULL,
	.ai_canonname = NULL,
	.ai_next = NULL
    };
    struct addrinfo *res = NULL;
    int rs = 0;
    if (!getaddrinfo(host, port, &hint, &res)) {
	struct addrinfo *r;
	rs = VESMAIL_E_CONN;
	for (r = res; r; r = r->ai_next) {
	    if (daemon->sock < 0) {
		int fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (fd < 0) continue;
		int flg = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flg, sizeof(flg));
		setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &flg, sizeof(flg));
		daemon->sock = fd;
	    }
	    VESMAIL_DAEMON_DEBUG(daemon, 1, {
		char abuf[64];
		char pbuf[16];
		getnameinfo(r->ai_addr, r->ai_addrlen, abuf, sizeof(abuf), pbuf, sizeof(pbuf), NI_NUMERICHOST | NI_NUMERICSERV);
		fprintf(stderr, "Binding to [%s]:%s ...\n", abuf, pbuf);
	    })
	    int connr;
	    if ((connr = bind(daemon->sock, r->ai_addr, r->ai_addrlen)) < 0) {
		VESMAIL_DAEMON_DEBUG(daemon, 1, fprintf(stderr, "... bind failed (%d)\n", connr));
		continue;
	    }
	    if ((connr = listen(daemon->sock, 16)) < 0) {
		VESMAIL_DAEMON_DEBUG(daemon, 1, fprintf(stderr, "... listen failed (%d)\n", connr));
		continue;
	    }
	    VESMAIL_DAEMON_DEBUG(daemon, 1, fprintf(stderr, "... success\n"));
	    rs = 0;
	    break;
	}
	freeaddrinfo(res);
    } else {
	rs = VESMAIL_E_RESOLV;
    }
    free(port);
    free(host);
    return rs;
}

int VESmail_daemon_run(VESmail_daemon *daemon) {
    if (!strcmp(daemon->type, "imap")) {
	daemon->srvfn = &VESmail_server_new_imap;
    } else if (!strcmp(daemon->type, "smtp")) {
	daemon->srvfn = &VESmail_server_new_smtp;
    } else if (!strcmp(daemon->type, "now")) {
	daemon->srvfn = &VESmail_server_new_now;
    } else {
	VESmail_daemon_shutdown(daemon);
	return VESMAIL_E_CONF;
    }
    if (daemon->sock < 0) while (VESmail_daemon_listen(daemon)) {
	VESmail_arch_usleep(15000000);
    }
    int fd;
    while (daemon->sock >= 0) {
	fd = accept(daemon->sock, NULL, NULL);
	if (fd >= 0) {
	    VESmail_proc *p = daemon->procs = VESmail_proc_new(daemon, fd);
	    VESmail_proc_launch(p);
	} else {
	    VESmail_arch_usleep(1000000);
	}
    }
    return 0;
}

void *VESmail_daemon_run_fn(void *ptr) {
    VESmail_daemon_run(ptr);
    return NULL;
}

int VESmail_daemon_launch(VESmail_daemon *daemon) {
    if (daemon->thread) return 0;
    VESMAIL_DAEMON_DEBUG(daemon, 2, fprintf(stderr, "Launching %s...\n", daemon->type))
    return VESmail_arch_thread(daemon, &VESmail_daemon_run_fn, &daemon->thread);
}



struct VESmail_daemon_snirec {
    VESmail_conf *conf;
    jVar *jconf;
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
    VESmail_arch_vlog(fb, &va);
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
	VESMAIL_DAEMON_DEBUG(daemon, 2, fprintf(stderr, "sni rec loaded for %s: %lx\n", sni, rec))
    } else {
	jVar *jconf = VESmail_conf_sni_read(daemon->conf, sni, &VESmail_daemon_snierrfn);
	if (!jconf && daemon->conf->sni.require) {
	    r = VESMAIL_E_CONF;
	} else {
	    rec = malloc(sizeof(struct VESmail_daemon_snirec) + strlen(sni) + 1);
	    strcpy(rec->sni, sni);
	    if ((rec->jconf = jconf)) {
		rec->conf = VESmail_conf_clone(srv->proc->daemon->conf);
		VESmail_conf_apply(rec->conf, jVar_get(jconf, "*"));
		VESmail_conf_apply(rec->conf, jVar_get(jconf, srv->type));
	    } else {
		rec->conf = NULL;
	    }
	    *pobj = rec;
	    VESMAIL_DAEMON_DEBUG(daemon, 2, fprintf(stderr, "sni rec created for %s: %lx\n", sni, rec))
	}
    }
    if (!r && rec->conf) {
	srv->proc->conf = rec->conf;
	srv->optns = rec->conf->optns;
	srv->tls.server = rec->conf->tls;
    }
    if (!r) VESmail_tls_server_ctxinit(srv);
    VESmail_arch_mutex_unlock(&daemon->sni.mutex);
    return r;
}

void VESmail_daemon_snifree(VESmail_daemon *daemon) {
    void **pobj;
    for (pobj = jTree_first(daemon->sni.jtree); pobj; pobj = jTree_next(pobj)) {
	struct VESmail_daemon_snirec *rec = *pobj;
	if (rec) {
	    VESmail_conf_free(rec->conf);
	    jVar_free(rec->jconf);
	    free(rec);
	    *pobj = NULL;
	}
    }
    jTree_collapse(&daemon->sni.jtree);
    VESmail_arch_mutex_done(daemon->sni.mutex);
}


char VESmail_daemon_SIG = 0;

void VESmail_daemon_sigfn(int sig) {
    if (sig == VESMAIL_DAEMON_SIG_TERM || !VESmail_daemon_SIG) VESmail_daemon_SIG = sig;
}

int VESmail_daemon_watch(VESmail_daemon *daemon, void (* watchfn)(VESmail_proc *, void *), void *arg) {
    VESmail_proc *p = daemon->procs;
    VESmail_proc *p2;
    int rs = 0;
    if (VESmail_daemon_SIG) {
	if (daemon->sock >= 0) VESmail_arch_log("shutdown srv=%s sig=%d", daemon->type, VESmail_daemon_SIG);
	VESmail_daemon_shutdown(daemon);
    }
    if (daemon->sock >= 0) rs++;
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

void VESmail_daemon_shutdown(VESmail_daemon *daemon) {
    if (daemon->sock >= 0) {
	VESmail_arch_close(daemon->sock);
	VESmail_arch_thread_kill(daemon->thread);
	daemon->sock = -2;
    }
}

void VESmail_daemon_free(VESmail_daemon *daemon) {
    if (daemon) {
	VESmail_arch_thread_done(daemon->thread);
	while (daemon->procs) {
	    VESmail_proc *p = daemon->procs;
	    daemon->procs = p->chain;
	    VESmail_proc_free(p);
	}
	VESmail_daemon_snifree(daemon);
    }
    free(daemon);
}


/****************************************************************
 * VESmail_daemon_execute() is supposed to be called once per pid,
 * not bothering with memory deallocation on failure
 ****************************************************************/
VESmail_daemon **VESmail_daemon_execute(VESmail_conf *conf, jVar *jconf) {
    jVar *jds = jVar_get(jconf, "daemons");
    if (!jVar_isArray(jds) || !jds->len) return NULL;
    VESmail_arch_sigaction(VESMAIL_DAEMON_SIG_DOWN, &VESmail_daemon_sigfn);
    if (VESMAIL_DAEMON_SIG_DOWN2) VESmail_arch_sigaction(VESMAIL_DAEMON_SIG_DOWN2, &VESmail_daemon_sigfn);
    VESmail_arch_sigaction(VESMAIL_DAEMON_SIG_TERM, &VESmail_daemon_sigfn);
    VESmail_daemon **daemons = malloc((jds->len + 1) * sizeof(VESmail_daemon *));
    int i;
    for (i = 0; i < jds->len; i++) {
	jVar *jd = jVar_index(jds, i);
	VESmail_conf *cf = VESmail_conf_clone(conf);
	if (cf->tls->snifn) cf->tls->snifn = &VESmail_daemon_snifn;
	const char *srv = jVar_getStringP(jVar_get(jd, "server"));
	if (!srv) return NULL;
	if (!strncmp(srv, "ves-", 4)) srv += 4;
	VESmail_conf_applyroot(cf, jVar_get(jconf, srv), &VESmail_daemon_snifn);
	VESmail_conf_applyroot(cf, jd, &VESmail_daemon_snifn);
	jVar *tlsp = jVar_get(jVar_get(jd, "tls"), "persist");
	if (tlsp) cf->tls->persist = jVar_getBool(tlsp);
	daemons[i] = VESmail_daemon_new(cf, jd, srv);
    }
    daemons[i] = NULL;
    return daemons;
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

void VESmail_daemon_freeall(VESmail_daemon **daemons) {
    VESmail_daemon **pd;
    if (daemons) for (pd = daemons; *pd; pd++) {
	VESmail_conf *conf = (*pd)->conf;
	VESmail_daemon_free(*pd);
	VESmail_conf_free(conf);
    }
    free(daemons);
}
