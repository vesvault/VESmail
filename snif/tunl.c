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
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bio.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip.h>
#endif
#include <snifl/tunl.h>
#include <snifl/sock.h>
#include <snifl/mgr.h>
#include <snifl/v4.h>
#include <snifl/tcp.h>
#include <snifl/dns.h>
#include "../VESmail.h"
#include "../srv/server.h"
#include "../srv/proc.h"
#include "../srv/daemon.h"
#include "../srv/conf.h"
#include "../srv/arch.h"
#include "../srv/tls.h"
#include "snif.h"
#include "tunl.h"


int VESmail_tunl_accept(snifl_sock *sock, const snifl_accept *ac);
int VESmail_tunl_recv(snifl_sock *sock, const void *buf, int len);
int VESmail_tunl_pktout(const snifl *tunl, const snifl_func *func, const void *pkt, int len);

char VESmail_tunl_dnsrsp_v4[] = {
    0xc0, 0x0c,			// ptr
    0x00, 0x01,			// qtype
    0x00, 0x01,			// qclass
    0x00, 0x00, 0x01, 0x2c,	// ttl
    0x00, 0x04,			// rlen
    0x7f, 0x00, 0x00, 0x01	// addr
};

snifl_lstn VESmail_tunl_udpfuncs[] = {
    {
	.func = &snifl_dns_lo,
	.lport = 53,
	.rport = 0,
	.addr = NULL,
	.arg = VESmail_tunl_dnsrsp_v4
    },
    {
	.func = NULL
    }
};

snifl_mgr VESmail_tunl_mgr = {
    .socks = NULL
};

snifl_accept VESmail_tunl_acpt = {
    .accept = &VESmail_tunl_accept,
    .recv = &VESmail_tunl_recv,
    .arg = &VESmail_tunl_mgr,
    .recvwin = 10240
};

snifl_lstn VESmail_tunl_tcpfuncs[] = {
    {
	.func = &snifl_mgr_tcpin,
	.lport = 0,
	.rport = 0,
	.addr = NULL,
	.arg = &VESmail_tunl_mgr
    },
    {
	.func = &snifl_tcp_accept,
	.lport = 993,
	.rport = 0,
	.addr = NULL,
	.arg = &VESmail_tunl_acpt
    },
    {
	.func = &snifl_tcp_accept,
	.lport = 465,
	.rport = 0,
	.addr = NULL,
	.arg = &VESmail_tunl_acpt
    },
    {
	.func = &snifl_tcp_accept,
	.lport = 7193,
	.rport = 0,
	.addr = NULL,
	.arg = &VESmail_tunl_acpt
    },
    {
	.func = &snifl_tcp_accept,
	.lport = 7165,
	.rport = 0,
	.addr = NULL,
	.arg = &VESmail_tunl_acpt
    },
    {
	.func = &snifl_tcp_accept,
	.lport = 7183,
	.rport = 0,
	.addr = NULL,
	.arg = &VESmail_tunl_acpt
    },
    {
	.func = &snifl_tcp_accept,
	.lport = 587,
	.rport = 0,
	.addr = NULL,
	.arg = &VESmail_tunl_acpt
    },
    {
	.func = &snifl_tcp_reset,
	.lport = 0,
	.rport = 0,
	.addr = NULL
    },
    {
	.func = NULL
    }
};

snifl_func VESmail_tunl_recvfuncs[] = {
    {
	.func = &snifl_v4_validate,
	.arg = NULL
    },
    {
	.func = &snifl_v4_recvudp,
	.protochain = VESmail_tunl_udpfuncs
    },
    {
	.func = &snifl_v4_recvtcp,
	.protochain = VESmail_tunl_tcpfuncs
    },
    {
	.func = NULL
    }
};

snifl_func VESmail_tunl_sendfuncs[] = {
    {
	.func = &VESmail_tunl_pktout,
	.arg = NULL
    },
    {
	.func = NULL
    }
};

snifl VESmail_tunl = {
    .inchain = VESmail_tunl_recvfuncs,
    .outchain = VESmail_tunl_sendfuncs
};

struct VESmail_tunl_port {
    struct VESmail_snif_port *snifport;
    uint16_t tcpport;
} VESmail_tunl_ports[16] = {
    { .tcpport = 0 }
};

VESmail_tls_server VESmail_tunl_tls = {
    .ctx = NULL,
    .level = VESMAIL_TLS_HIGH,
    .persist = 1,
    .snifn = NULL
};
VESmail_tls_server VESmail_tunl_starttls = {
    .ctx = NULL,
    .level = VESMAIL_TLS_HIGH,
    .persist = 0,
    .snifn = NULL,
    .cert = "",
    .key = ""
};

char VESmail_tunl_dnsaddr_v4[16] = "";

void *VESmail_tunl_mutex = NULL;


#if	(OPENSSL_VERSION_NUMBER >= 0x10101000L)
long VESmail_tunl_outfn_ex(BIO *bio, int oper, const char *argp, size_t argi, int argi2, long argl, int ret, size_t *processed) {
#else
long VESmail_tunl_outfn(BIO *bio, int oper, const char *argp, int argi, long argl, long ret) {
#endif
    VESmail_tunl_proc *tproc = (void *)BIO_get_callback_arg(bio);
    VESmail_arch_mutex_lock(&VESmail_tunl_mutex);
    if (tproc->sock) switch (oper) {
	case (BIO_CB_WRITE | BIO_CB_RETURN): {
	    if (!argp) break;
	    const char *s = argp;
	    const char *tail = s + argi;
	    while (s < tail) {
		int w = snifl_send(tproc->sock, s, tail - s, 0);
		if (w < 0) {
		    ret = w;
		    break;
		}
		if (!w) {
		    tproc->outcg = 1;
		    VESmail_arch_mutex_unlock(&VESmail_tunl_mutex);
		    VESmail_arch_usleep(5000000);
		    VESmail_arch_mutex_lock(&VESmail_tunl_mutex);
		    tproc->outcg = 0;
		}
		s += w;
	    }
	    break;
	}
	case BIO_CB_FREE:
	    snifl_shutdown(tproc->sock, SNIFL_SHUT_WR);
	    tproc->sock = NULL;
	default:
	    break;
    }
    VESmail_arch_mutex_unlock(&VESmail_tunl_mutex);
    return ret;
}

int VESmail_tunl_accept(snifl_sock *sock, const snifl_accept *ac) {
    struct VESmail_tunl_port *tp;
    struct VESmail_daemon_sock *dsock = NULL;
    for (tp = VESmail_tunl_ports; tp->tcpport; tp++) {
	if (tp->tcpport == sock->lport) {
	    dsock = tp->snifport->sock;
	    break;
	}
    }
    if (!dsock) return VESMAIL_E_PARAM;
    VESmail_proc *proc = VESmail_proc_init(malloc(sizeof(VESmail_proc) + sizeof(struct VESmail_tunl_proc)), dsock->daemon, -1);
    VESmail_tunl_proc *tproc = (VESmail_tunl_proc *)&proc->ctl;
    if (pipe(tproc->fd) < 0) {
	VESmail_proc_free(proc);
	return VESMAIL_E_IO;
    }
    tproc->sock = sock;
    sock->arg = tproc;
    tproc->outcg = 0;
    VESmail_server *snifsrv = sock->tunl->arg;
    VESmail_snif *snif = (VESmail_snif *)&snifsrv->ctl;
    BIO *out = BIO_new(BIO_s_null());
#if	(OPENSSL_VERSION_NUMBER >= 0x10101000L)
    BIO_set_callback_ex(out, &VESmail_tunl_outfn_ex);
#else
    BIO_set_callback(out, &VESmail_tunl_outfn);
#endif
    BIO_set_callback_arg(out, (void *)tproc);
    int connr = VESmail_server_set_bio(proc->server, BIO_new_fd(tproc->fd[0], BIO_CLOSE), out);
    if (connr >= 0) {
	VESmail_arch_mutex_lock(&snif->mutex);
	if (VESmail_snif_tlsctx(snif)) {
	    if (!strcmp(dsock->daemon->type, "now")) {
		proc->server->optns = VESmail_snif_mftconf(snif, dsock->daemon->conf)->optns;
	    }
	    VESmail_tls_server *tls = tp->snifport->tls ? &VESmail_tunl_tls : &VESmail_tunl_starttls;
	    tls->ctx = snif->tls->ctx;
	    proc->server->tls.server = tls;
	    proc->chain = dsock->procs;
	    dsock->procs = proc;
	} else connr = VESMAIL_E_TLS;
	VESmail_arch_mutex_unlock(&snif->mutex);
	if (connr >= 0) {
	    VESmail_proc_launch(proc);
	    return snifl_mgr_accept(sock, ac);
	} else sock->arg = NULL;
    } else {
	VESmail_arch_close(tproc->fd[0]);
	VESmail_arch_close(tproc->fd[1]);
    }
    VESmail_proc_free(proc);
    return connr;
}

int VESmail_tunl_recv(snifl_sock *sock, const void *buf, int len) {
    VESmail_tunl_proc *tproc = sock->arg;
    if (!buf) {
	VESmail_arch_close(tproc->fd[1]);
	tproc->fd[1] = -1;
	return 0;
    }
    if (tproc->outcg) VESmail_arch_thread_kill(((VESmail_proc *)((char *)tproc - offsetof(VESmail_proc, ctl)))->thread);
    VESmail_arch_mutex_unlock(&VESmail_tunl_mutex);
    const char *s = buf;
    const char *tail = s + len;
    while (s < tail) {
	int w = write(tproc->fd[1], s, tail - s);
	if (w < 0) {
	    len = w;
	    break;
	}
	s += w;
    }
    VESmail_arch_mutex_lock(&VESmail_tunl_mutex);
    return len;
}

int VESmail_tunl_pktin(const void *pkt, int len) {
    VESmail_arch_mutex_lock(&VESmail_tunl_mutex);
    int r = snifl_pktin(&VESmail_tunl, pkt, len);
    VESmail_arch_mutex_unlock(&VESmail_tunl_mutex);
    return r;
}

int VESmail_tunl_pktout(const snifl *tunl, const snifl_func *func, const void *pkt, int len) {
    void (* outfn)(const void *buf, int len) = func->arg;
    VESmail_arch_mutex_unlock(&VESmail_tunl_mutex);
    if (outfn) outfn(pkt, len);
    VESmail_arch_mutex_lock(&VESmail_tunl_mutex);
    return 1;
}

void VESmail_tunl_init(VESmail_server *snifsrv, const char *dnsaddr) {
    VESmail_snif *snif = (VESmail_snif *)&snifsrv->ctl;
    VESmail_tunl.arg = snifsrv;
    VESmail_arch_mutex_lock(&snif->mutex);
    VESmail_arch_mutex_unlock(&snif->mutex);
    struct VESmail_tunl_port *tp = VESmail_tunl_ports;
    struct VESmail_snif_port *sp = snif->ports;
    struct addrinfo hint = {
	.ai_family = AF_INET,
	.ai_socktype = SOCK_STREAM,
	.ai_protocol = 0,
	.ai_flags = AI_ADDRCONFIG,
	.ai_addrlen = 0,
	.ai_addr = NULL,
	.ai_canonname = NULL,
	.ai_next = NULL
    };
    struct addrinfo *res;
    while (sp->port && tp < VESmail_tunl_ports + (sizeof(VESmail_tunl_ports) / sizeof(*sp) - 1)) {
	res = NULL;
	if (!getaddrinfo(NULL, sp->port, &hint, &res)) {
	    tp->tcpport = ((struct sockaddr_in *)res->ai_addr)->sin_port;
	    tp->snifport = sp;
	    tp++;
	    freeaddrinfo(res);
	}
	sp++;
    }
    tp->tcpport = 0;
    res = NULL;
    if (!getaddrinfo(dnsaddr, NULL, &hint, &res)) {
	memcpy(VESmail_tunl_dnsrsp_v4 + 12, &((struct sockaddr_in *)res->ai_addr)->sin_addr, 4);
	getnameinfo(res->ai_addr, res->ai_addrlen, VESmail_tunl_dnsaddr_v4, sizeof(VESmail_tunl_dnsaddr_v4), NULL, 0, NI_NUMERICHOST);
	freeaddrinfo(res);
    }
}

void VESmail_tunl_conf(int mtu, void (* outfn)(const void *buf, int len)) {
    if (mtu > 0) VESmail_tunl.mtu = mtu;
    VESmail_tunl_sendfuncs[0].arg = outfn;
}

void VESmail_tunl_done() {
    snifl_mgr_done(&VESmail_tunl_mgr);
    VESmail_arch_mutex_done(VESmail_tunl_mutex);
}

const char *VESmail_tunl_get_dnsaddr_v4() {
    return VESmail_tunl_dnsaddr_v4;
}
