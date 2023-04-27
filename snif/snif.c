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
 *
 *     _________
 *    /````````_\                  S N I F ~ e2e TLS trust for IoT
 *   /\     , / O\      ___
 *  | |     | \__|_____/  o\       e2e TLS SNI Forwarder
 *  | |     |  ``/`````\___/       e2e TLS CA Proxy
 *  | |     | . | <"""""""~~
 *  |  \___/ ``  \________/        https://snif.host
 *   \  '''  ``` /````````         (C) 2021 VESvault Corp
 *    \_________/                  Jim Zubov <jz@vesvault.com>
 *
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

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "conn.h"
#include "cert.h"
#include <openssl/ssl.h>
#include "../VESmail.h"
#include "../lib/xform.h"
#include "../lib/optns.h"
#include "../srv/arch.h"
#include "../srv/proc.h"
#include "../srv/daemon.h"
#include "../srv/server.h"
#include "../srv/tls.h"
#include "../srv/conf.h"
#ifdef VESMAIL_X509STORE
#include "../srv/x509store.h"
#endif
#include "snif.h"

const char *VESmail_snif_manifest = "{"
	    "\"schema\": \"VES-1.0\","
	    "\"servers\": ["
		"{"
		    "\"server\": \"ves-imap\","
		    "\"host\": \"%s\","
		    "\"port\": 993,"
		    "\"proto\": \"tcp\","
		    "\"tls\": {"
			"\"persist\": true,"
			"\"level\": \"high\""
		    "}"
		"},"
		"{"
		    "\"server\": \"ves-smtp\","
		    "\"host\": \"%s\","
		    "\"port\": 465,"
		    "\"proto\": \"tcp\","
		    "\"tls\": {"
			"\"persist\": true,"
			"\"level\": \"high\""
		    "}"
		"}"
	    "]"
	"}";

struct VESmail_snif_proc {
    VESmail_server *server;
    snif_conn *conn;
};

void VESmail_snif_procfreefn(VESmail_proc *proc) {
    if (proc) snif_conn_free(((struct VESmail_snif_proc *)&proc->ctl)->conn);
}

int VESmail_snif_abusefn(void *ref, void *key, int keylen, int val) {
    if (val <= 1) return 0;
    struct VESmail_snif_proc *snifp = (struct VESmail_snif_proc *)&((VESmail_proc *)ref)->ctl;
    if (!snifp->conn) return 0;
    char buf[160];
    char *p = buf;
    snif_conn_abuse(&p, sizeof(buf), snifp->conn, val * VESMAIL_SNIF_ABUSE);
    return VESmail_xform_process(snifp->server->rsp_out, 0, buf, p - buf);
}

VESmail_conf *VESmail_snif_mftconf(VESmail_snif *snif, VESmail_conf *conf) {
    if (!snif->mftconf) {
	snif->mftconf = malloc(sizeof(*snif->mftconf));
	memcpy(snif->mftconf, conf, sizeof(*snif->mftconf));
	snif->mftconf->optns = VESmail_optns_clone(snif->mftconf->optns);
	snif->mftconf->optns->ref = snif->mftconf;
	const char *host = snif_cert_hostname(snif->cert);
	sprintf((snif->mftconf->now.manifest = malloc(4096)),
	    VESmail_snif_manifest,
	    host,
	    host);
    }
    return snif->mftconf;
}

void *VESmail_snif_tlsctx(VESmail_snif *snif) {
    void *ctx = snif->tls->ctx = snif_cert_ctx(snif->cert);
    if (ctx) {
	SSL_CTX_set_options(ctx, VESMAIL_TLS_HIGHOPTNS | VESMAIL_TLS_SRVOPTNS);
#ifdef VESMAIL_TLS_SRVMODE
	SSL_CTX_set_mode(ctx, VESMAIL_TLS_SRVMODE);
#endif
    }
    return ctx;
}

int VESmail_snif_xform_fn(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    const char *s = src;
    const char *tail = s + *srclen;
    VESmail_snif *snif = (VESmail_snif *) &xform->server->ctl;
    while (s < tail) {
	snif->waiting = 0;
	snif_conn *conn = snif_conn_receive(&s, tail - s);
	if (!conn) break;
	VESmail_server_log(xform->server, "snif connid=%s port=%s remote=%s:%s", conn->connid, conn->srv.port, conn->cln.host, conn->cln.port);
	struct VESmail_snif_port *port = snif->ports;
	struct VESmail_daemon_sock *sock = NULL;
	if (port) for (; port->port; port++) {
	    if (!strcmp(port->port, conn->srv.port)) {
		sock = port->sock;
		break;
	    }
	}
	char buf[128];
	char *p = buf;
	int connr = VESMAIL_E_PARAM;
	if (sock) {
	    int fd = VESmail_server_connectsk(xform->server, conn->fwd.host, conn->fwd.port);
	    if (fd >= 0) {
		snif_conn_accept(&p, sizeof(buf), conn);
		int r = VESmail_xform_process(xform->server->rsp_out, 0, buf, p - buf);
		p = buf;
		snif_conn_forward(&p, sizeof(buf), conn);
		VESmail_proc *proc = VESmail_proc_init(malloc(sizeof(VESmail_proc) + sizeof(struct VESmail_snif_proc)), sock->daemon, fd);
		if (proc) {
		    if (!port->tls) proc->server->flags |= VESMAIL_SRVF_QUIET;
		    int w = VESmail_xform_process(proc->server->rsp_out, 0, buf, p - buf);
		    int lck = snif->mutex ? VESmail_arch_mutex_lock(&snif->mutex) : -1;
		    if (w >= 0 && VESmail_snif_tlsctx(snif)) {
			if (!strcmp(sock->daemon->type, "now")) {
			    proc->server->optns = VESmail_snif_mftconf(snif, proc->conf)->optns;
			}
			proc->server->tls.server = snif->tls;
			if ((connr = VESmail_tls_server_start(proc->server, 1)) >= 0) {
			    proc->chain = sock->procs;
			    sock->procs = proc;
			    if ((connr = VESmail_proc_launch(proc)) >= 0) {
				struct VESmail_snif_proc *snifp = (struct VESmail_snif_proc *)&proc->ctl;
				snifp->server = xform->server;
				snifp->conn = conn;
				proc->freefn = &VESmail_snif_procfreefn;
				proc->server->abusefn = &VESmail_snif_abusefn;
				if (lck >= 0) VESmail_arch_mutex_unlock(&snif->mutex);
				continue;
			    }
			}
		    } else connr = w;
		    if (lck >= 0) VESmail_arch_mutex_unlock(&snif->mutex);
		    VESmail_proc_free(proc);
		} else connr = VESMAIL_E_INTERNAL;
		if (r < 0) return r;
	    } else connr = fd;
	}
	snif_conn_reject(&p, sizeof(buf), conn);
	snif_conn_free(conn);
	VESmail_server_log(xform->server, "snif reject=%d", connr);
	int r = VESmail_xform_process(xform->server->rsp_out, 0, buf, p - buf);
	if (r < 0) return r;
    }
    *srclen = s - src;
    if (snif->msgout) {
	int r = VESmail_xform_process(xform->server->rsp_out, 0, snif->msgout, strlen(snif->msgout));
	if (r < 0) return r;
	free(snif->msgout);
	snif->msgout = NULL;
    }
    return final ? VESMAIL_E_IO : *srclen;
}

int VESmail_snif_run(VESmail_server *srv) {
    VESmail_snif *snif = (VESmail_snif *)&srv->ctl;
    int certerr = 0;
    int sniffd = -1;
    int *pfd[32] = { &sniffd, NULL };
    if (snif->daemons && VESmail_daemon_prepall(snif->daemons, pfd + 1) < 0) return VESMAIL_E_CONN;
    while (!(srv->flags & VESMAIL_SRVF_KILL)) {
	if (snif->hold) {
	    srv->flags &= ~VESMAIL_SRVF_SHUTDOWN;
	    VESmail_arch_usleep(15000000);
	    continue;
	}
	if (snif->daemons) VESmail_daemon_pollall(snif->daemons);
	int lck = snif->mutex ? VESmail_arch_mutex_lock(&snif->mutex) : -1;
	void *ctx = snif_cert_ctx(snif->cert);
	const char *host = snif_cert_hostname(snif->cert);
	if (!ctx || !(srv->flags & VESMAIL_SRVF_TLSS)) {
	    VESmail_server_log(srv, "snif cert host=%s error=%d", (host ? host : ""), snif->cert->error);
	}
	if (!ctx) {
	    if (snif->cert->error == SNIF_CE_CERT) {
		if (++certerr >= VESMAIL_SNIF_REKEY) {
		    snif_cert_alloccn(snif->cert);
		}
	    } else certerr = 0;
	}
	if (lck >= 0) VESmail_arch_mutex_unlock(&snif->mutex);
	if (!ctx) {
	    VESmail_arch_polltm(snif->backoff, -1, pfd);
	    snif->backoff += snif->backoff / 32 + 1;
	    continue;
	}
	certerr = 0;
	snif->backoff = VESMAIL_SNIF_BACKOFF;
	snif->tls->ctx = ctx;
	sniffd = VESmail_server_connectsk(srv, host, VESMAIL_SNIF_RPORT);
	if (sniffd < 0) {
	    VESmail_arch_polltm(15, -1, pfd);
	    continue;
	}
	srv->req_in->eof = 0;
	VESmail_arch_keepalive(sniffd);
	char buf[128];
	char *p = buf;
	snif_conn_start(&p, sizeof(buf), host);
	if (VESmail_server_set_sock(srv, sniffd) < 0
	    || VESmail_tls_server_start(srv, 1) < 0
	    || VESmail_xform_process(srv->rsp_out, 0, buf, p - buf) < 0
	) {
	    VESmail_server_unset_fd(srv);
	    VESmail_arch_polltm(15, -1, pfd);
	    continue;
	}
	char *local = VESmail_server_sockname(srv, 0);
	char *relay = VESmail_server_sockname(srv, 1);
	VESmail_server_log(srv, "snif connect relay=%s local=%s", relay, local);
	free(relay);
	free(local);
	snif->running = 1;
	snif->waiting = 0;
	srv->tmout = VESMAIL_SNIF_ALIVE;
	while (!(srv->flags & VESMAIL_SRVF_SHUTDOWN)) {
	    VESmail_arch_poll(-1, pfd);
	    if (VESmail_server_run(srv, VESMAIL_SRVR_NOTHR | VESMAIL_SRVR_NOLOOP | VESMAIL_SRVR_NOPOLL) < 0) break;
	    if (snif->daemons) VESmail_daemon_pollall(snif->daemons);
	}
	snif->running = 0;
	VESmail_server_unset_fd(srv);
	srv->flags &= ~(VESMAIL_SRVF_TMOUT | VESMAIL_SRVF_SHUTDOWN);
	srv->cycles = 0;
    }
    return 0;
}

void *VESmail_snif_run_fn(void *ref) {
    VESmail_snif_run(ref);
    return NULL;
}

int VESmail_snif_idle(VESmail_server *srv, int tmout) {
    VESmail_snif *snif = (VESmail_snif *)&srv->ctl;
    if (snif->waiting) {
	if ((srv->tmout = VESMAIL_SNIF_TMOUT - tmout) <= 0) srv->flags |= VESMAIL_SRVF_TMOUT;
    } else srv->tmout = VESMAIL_SNIF_ALIVE;
    if (tmout < VESMAIL_SNIF_ALIVE) return 0;
    if (tmout >= VESMAIL_SNIF_ALIVE + VESMAIL_SNIF_STALE) {
	srv->flags |= VESMAIL_SRVF_TMOUT;
	return 0;
    }
    snif_cert_idle(snif->cert);
    char buf[128];
    char *p = buf;
    snif->waiting = 1;
    return snif_conn_idle(&p, sizeof(buf)) > 0 ? VESmail_xform_process(srv->rsp_out, 0, buf, p - buf) : 0;
}

int VESmail_snif_stat(VESmail_server *srv) {
    VESmail_snif *snif = (VESmail_snif *)&srv->ctl;
    if (snif->running) return 1;
    int e = snif->cert->error;
    return e < 0 ? e : (snif->cert->authurl ? VESMAIL_SNIFST_AUTH : (snif->cert->ctx ? VESMAIL_SNIFST_RETRY : VESMAIL_SNIFST_INIT));
}

int VESmail_snif_awake(VESmail_server *srv, int awake) {
    VESmail_snif *snif = (VESmail_snif *)&srv->ctl;
    if ((snif->hold = !awake)) srv->flags |= VESMAIL_SRVF_SHUTDOWN;
    return VESmail_arch_thread_kill(snif->thread);
}

int VESmail_snif_msg(VESmail_server *srv, const char *msg) {
    char buf[640];
    VESmail_snif *snif = (VESmail_snif *)&srv->ctl;
    if (snif->msgout) return VESMAIL_E_BUF;
    char *p = buf;
    snif_conn_msg(&p, sizeof(buf), snif_cert_hostname(snif->cert), msg);
    int l = p - buf;
    if (l <= 0) return VESMAIL_E_BUF;
    snif->msgout = malloc(l + 1);
    memcpy(snif->msgout, buf, l);
    snif->msgout[l] = 0;
    VESmail_arch_thread_kill(snif->thread);
    return l;
}

void VESmail_snif_fn_free(VESmail_server *srv, int final) {
    if (!final) return;
    VESmail_snif *snif = (VESmail_snif *)&srv->ctl;
    srv->flags |= VESMAIL_SRVF_KILL;
    VESmail_arch_thread_kill(snif->thread);
    VESmail_arch_thread_done(snif->thread);
    VESmail_arch_mutex_done(snif->mutex);
    snif->tls->ctx = NULL;
    VESmail_tls_server_free(snif->tls);
    if (snif->mftconf) {
	VESmail_optns_free(snif->mftconf->optns);
	free(snif->mftconf->now.manifest);
	free(snif->mftconf);
	free(snif->msgout);
    }
}

VESmail_server *VESmail_snif_new(snif_cert *cert, struct VESmail_snif_port *ports, struct VESmail_daemon **daemons) {
    VESmail_server *srv = VESmail_server_init(malloc(sizeof(VESmail_server) + sizeof(VESmail_snif)), NULL);
    srv->type = "snif";
    srv->req_in = VESmail_xform_new(&VESmail_snif_xform_fn, NULL, srv);
    srv->rsp_out = NULL;
    srv->freefn = &VESmail_snif_fn_free;
    srv->idlefn = &VESmail_snif_idle;
    srv->logfn = (void (*)(void *, const char *, ...))&VESmail_conf_log;
    srv->logref = ports->sock->daemon->conf;
    VESmail_snif *snif = (VESmail_snif *)&srv->ctl;
    snif->cert = cert;
    snif->ports = ports;
    snif->thread = NULL;
    snif->mftconf = NULL;
    snif->msgout = NULL;
    snif->tls = VESmail_tls_server_new();
    snif->tls->persist = 0;
    snif->tls->level = VESMAIL_TLS_HIGH;
    srv->tls.server = snif->tls;
    snif->running = snif->hold = 0;
    snif->backoff = VESMAIL_SNIF_BACKOFF;
    snif->mutex = NULL;
    snif->daemons = daemons;
    int r = VESmail_arch_thread(srv, &VESmail_snif_run_fn, &snif->thread);
    if (r < 0) {
	VESmail_server_free(srv);
	srv = NULL;
    }
    return srv;
}

struct VESmail_daemon_sock *VESmail_snif_daemonsock(VESmail_daemon *daemon) {
    struct VESmail_daemon_sock **psk = &daemon->sock;
    while (*psk) psk = &(*psk)->chain;
    struct VESmail_daemon_sock *sk = malloc(sizeof(*sk));
    sk->daemon = daemon;
    sk->ainfo = NULL;
    sk->procs = NULL;
    sk->thread = NULL;
    sk->sock = VESMAIL_DMSK_NONE;
    sk->chain = NULL;
    return *psk = sk;
}


#ifndef VESMAIL_X509STORE
static SSL_CTX *VESmail_snif_sslctx = NULL;
#endif

void VESmail_snif_initcert(snif_cert *cert) {
#ifdef VESMAIL_X509STORE
    cert->rootstore = VESmail_x509store;
#else
    if (!VESmail_snif_sslctx) {
#if	(OPENSSL_VERSION_NUMBER >= 0x10100000L)
	VESmail_snif_sslctx = SSL_CTX_new(TLS_server_method());
#else
	VESmail_snif_sslctx = SSL_CTX_new(TLSv1_2_server_method());
#endif
	VESmail_tls_applyCA(VESmail_snif_sslctx);
    }
    cert->rootstore = SSL_CTX_get_cert_store(VESmail_snif_sslctx);
#endif
    cert->ctxfn = &VESmail_tls_initclientctx;
    snif_cert_init(cert);
}

