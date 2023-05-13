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
#include <libVES.h>
#include <stdio.h>
#include "../VESmail.h"
#include "../lib/optns.h"
#include "server.h"
#include "arch.h"
#include "tls.h"
#include "conf.h"
#include "daemon.h"
#include "proc.h"
#include "override.h"
#ifdef VESMAIL_LOCAL_SNIF
#include "../snif/snif.h"
#include "../snif/cert.h"
#endif
#ifdef VESMAIL_X509STORE
#include "x509store.h"
#endif
#include "../now/now.h"
#include "../now/now_options.h"
#include "../now/now_post.h"
#include "../now/now_manifest.h"
#include "../now/now_e2e.h"
#include "../now/now_probe.h"
#include "../now/now_feedback.h"
#include "../now/now_websock.h"
#ifdef VESMAIL_NOW_OAUTH
#include "../now/now_oauth.h"
#endif
#include "local.h"


char *VESmail_local_cors[] = {
    "Access-Control-Allow-Headers: *",
    "Access-Control-Allow-Methods: GET,POST,PUT,OPTIONS",
    "Access-Control-Allow-Origin: *",
    "Access-Control-Max-Age: 86400",
#ifdef VESMAIL_LOCAL_SNIF
    "Access-Control-Expose-Headers: X-VESmail-SNIF",
    NULL, // for X-VESmail-SNIF:
#endif
    NULL
};

VESmail_tls_server VESmail_local_tls = {
    .level = VESMAIL_TLS_NONE,
    .persist = 0,
    .snifn = NULL
};

char VESmail_local_host[] = "localhost\0";
char VESmail_local_nowurl[] = "https://my.vesmail.email/now?msgid=\0";
char *VESmail_local_bcc[] = { "my@now.vesmail.email", NULL };

void VESmail_local_wakefn(struct VESmail_conf *conf);

int (* VESmail_local_reqStack[])(VESmail_now_req *) = {
    &VESmail_now_options_reqStack,
    &VESmail_now_post_reqStack,
    &VESmail_now_manifest_reqStack,
    &VESmail_now_e2e_reqStack,
    &VESmail_now_websock_reqStack,
#ifdef VESMAIL_NOW_OAUTH
    &VESmail_now_oauth_reqStack,
#endif
    NULL
};

int (* VESmail_local_postStack[])(VESmail_server *, jVar *) = {
    &VESmail_now_probe_postStack,
    &VESmail_now_feedback_postStack,
    NULL
};

struct VESmail_conf_daemon VESmail_local_conf_daemon[];

VESmail_conf VESmail_local_conf = {
    .hostname = VESmail_local_host,
    .progname = "vesmail",
    .bannerPath = NULL,
    .banner = NULL,
    .manifest = NULL,
    .app = NULL,
    .guard = 0,
    .optns = NULL,
    .sni = {
	.prefix = NULL
    },
    .log = {
	.filename = NULL,
	.fh = NULL,
	.wakefn = &VESmail_local_wakefn
    },
    .now = {
	.manifest = "{"
	    "\"schema\": \"VES-1.0\","
	    "\"servers\": ["
		"{"
		    "\"server\": \"ves-imap\","
		    "\"host\": \"localhost\","
		    "\"port\": 7143,"
		    "\"proto\": \"tcp\","
		    "\"tls\": {"
			"\"persist\": false,"
			"\"level\": \"none\""
		    "}"
		"},"
		"{"
		    "\"server\": \"ves-smtp\","
		    "\"host\": \"localhost\","
		    "\"port\": 7125,"
		    "\"proto\": \"tcp\","
		    "\"tls\": {"
			"\"persist\": false,"
			"\"level\": \"none\""
		    "}"
		"}"
	    "]"
	"}",
	.headers = VESmail_local_cors,
	.reqStack = VESmail_local_reqStack,
	.postStack = VESmail_local_postStack,
	.feedbackFn = NULL,
	.websock = NULL
    },
    .tls = &VESmail_local_tls,
    .mutex = NULL,
    .abuseSense = 0,
    .overrides = VESMAIL_OVRD_ALLOW,
#ifdef VESMAIL_NOW_OAUTH
    .oauth = NULL,
#endif
#ifdef VESMAIL_DEBUG_DUMP
    .dumpfd = 2
#else
    .dumpfd = -1
#endif
};

struct VESmail_conf_daemon VESmail_local_conf_daemon[] = {
    {
	.type = "imap",
	.host = VESmail_local_host,
	.port = "7143",
	.conf = &VESmail_local_conf,
	.debug = VESMAIL_APP_DEBUG
    },
    {
	.type = "smtp",
	.host = VESmail_local_host,
	.port = "7125",
	.conf = &VESmail_local_conf,
	.debug = VESMAIL_APP_DEBUG
    },
#ifdef VESMAIL_STDPORTS
    {
	.type = "imap",
	.host = VESmail_local_host,
	.port = "143",
	.conf = &VESmail_local_conf,
	.debug = VESMAIL_APP_DEBUG
    },
    {
	.type = "smtp",
	.host = VESmail_local_host,
	.port = "587",
	.conf = &VESmail_local_conf,
	.debug = VESMAIL_APP_DEBUG
    },
#endif
    {
	.type = "now",
	.host = VESmail_local_host,
	.port = "7180",
	.conf = &VESmail_local_conf,
	.debug = VESMAIL_APP_DEBUG
    },
    {
	.type = NULL
    }
};

struct VESmail_local_stat {
    int stat;
    int reqbytes;
    int rspbytes;
    int reqprev;
    int rspprev;
} VESmail_local_stat[sizeof(VESmail_local_conf_daemon) / sizeof(VESmail_local_conf_daemon[0])];

struct VESmail_local_ustat {
    struct VESmail_local_ustat *chain;
    char *profileurl;
    struct VESmail_local_stat stat;
    short int authcode;
    unsigned char subcode;
    unsigned char tag;
    char login[0];
} *VESmail_local_ustat = NULL;

int VESmail_local_ulen = 0;

struct VESmail_local_ustat VESmail_local_unull = {
    .chain = NULL,
    .login = ""
};

struct VESmail_daemon **VESmail_local_daemons = NULL;

void (*VESmail_local_wakecb)() = NULL;
void *VESmail_local_wakemutex = NULL;

char *VESmail_local_feedback = NULL;
int (* VESmail_local_feedback_fn)(const char *fbk) = NULL;

struct VESmail_local_ustat *VESmail_local_ustat_free(struct VESmail_local_ustat *ustat) {
    struct VESmail_local_ustat *next;
    if (ustat) {
	next = ustat->chain;
	free(ustat->profileurl);
	free(ustat);
    } else next = NULL;
    return next;
}

void VESmail_local_init(const char *logfile) {
    static char init = 0;
    if (init) return;
    init = 1;
    libVES_init(VESMAIL_VERSION_SHORT);
    VESmail_arch_init();
    VESmail_tls_init();
    if (logfile) VESmail_local_conf.log.filename = (char *) logfile;
}

int VESmail_local_caBundle(const char *ca) {
#ifdef VESMAIL_X509STORE
    return VESmail_x509store_caBundle(ca);
#else
    if (ca) VESmail_tls_caBundle = strdup(ca);
    return 0;
#endif
}

void VESmail_local_setcrt(const char *crt, const char *pkey) {
    VESmail_local_tls.cert = strdup(crt);
    VESmail_local_tls.key = strdup(pkey);
    VESmail_local_tls.level = VESMAIL_TLS_OPTIONAL;
}

void VESmail_local_stat_init(struct VESmail_local_stat *st) {
    st->stat = 0;
    st->reqbytes = st->rspbytes = st->reqprev = st->rspprev = 0;
}

void VESmail_local_stat_collect(struct VESmail_local_stat *st) {
    if (st->reqbytes != st->reqprev) {
	st->stat |= VESMAIL_LCST_TRFREQ;
	st->reqprev = st->reqbytes;
    }
    if (st->rspbytes != st->rspprev) {
	st->stat |= VESMAIL_LCST_TRFRSP;
	st->rspprev = st->rspbytes;
    }
    st->reqbytes = st->rspbytes = 0;
}

VESmail_daemon **VESmail_local_start() {
    if (!VESmail_local_daemons) {
	if (!VESmail_local_conf.optns) {
	    VESmail_local_conf.optns = VESmail_optns_new();
	    VESmail_local_conf.optns->now.url = VESmail_local_nowurl;
	    VESmail_local_conf.optns->bcc = VESmail_local_bcc;
	    VESmail_local_conf.optns->ref = &VESmail_local_conf;
	}
	struct VESmail_conf_daemon *cd;
	int idx = 0;
	for (cd = VESmail_local_conf_daemon; cd->type; cd++) cd->tag = idx++;
	VESmail_conf_addwebsock(&VESmail_local_conf, VESmail_local_conf_daemon);
	VESmail_local_daemons = VESmail_daemon_execute(VESmail_local_conf_daemon);
	if (!VESmail_local_daemons) return NULL;
	VESmail_daemon **dp = VESmail_local_daemons;
	while (*dp) (*dp++)->flags |= VESMAIL_DMF_RECONNECT;
#ifdef VESMAIL_LOCAL_SNIF
	VESmail_daemon_prepall(VESmail_local_daemons, NULL);
#else
	VESmail_daemon_launchall(VESmail_local_daemons);
#endif
	struct VESmail_local_stat *st = VESmail_local_stat;
	for (dp = VESmail_local_daemons; st < VESmail_local_stat + sizeof(VESmail_local_stat) / sizeof(*VESmail_local_stat); st++) {
	    VESmail_local_stat_init(st);
	    if (*dp) (*dp++)->ref = st;
	}
	VESmail_local_stat_init(&VESmail_local_unull.stat);
    }
    return VESmail_local_daemons;
}

void VESmail_local_watchfn(VESmail_proc *proc, void *arg) {
    if (!proc) return;
    struct VESmail_local_stat *st = proc->daemon->ref;
    if (!proc->ref) {
	proc->ref = &VESmail_local_unull;
	st->stat |= VESMAIL_LCST_PROCNEW;
    }
    struct VESmail_local_ustat *ust = proc->ref;
    st->stat |= VESMAIL_LCST_PROC;
    if (proc->server) {
	if (proc->server->login && strcmp(proc->server->login, ust->login)) {
	    struct VESmail_local_ustat **usp;
	    for (usp = &VESmail_local_ustat; (ust = *usp); usp = &(*usp)->chain) {
		if (!strcmp(proc->server->login, ust->login)) break;
	    }
	    if (!ust) {
		*usp = ust = malloc(sizeof(*ust) + strlen(proc->server->login) + 1);
		strcpy(ust->login, proc->server->login);
		ust->chain = NULL;
		ust->profileurl = NULL;
		ust->tag = ust->authcode = 0;
		VESmail_local_stat_init(&ust->stat);
		VESmail_local_ulen++;
	    }
	}
	int setf;
	switch (proc->server->authcode) {
	    case 0:
		setf = VESMAIL_LCST_PROC | VESMAIL_LCST_LOGINOK;
		proc->server->authcode = VESMAIL_E_LCL_CHKD;
		break;
	    case VESMAIL_E_HOLD:
	    case VESMAIL_E_LCL_CHKD:
		setf = 0;
		break;
	    default:
		setf = VESMAIL_LCST_PROC | VESMAIL_LCST_LOGINERR;
		ust->authcode = proc->server->authcode;
		ust->subcode = proc->server->subcode;
		ust->tag = proc->daemon->tag;
		proc->server->authcode = VESMAIL_E_LCL_CHKD;
		break;
	}
	st->stat |= setf;
	ust->stat.stat |= setf;
	st->reqbytes += proc->server->reqbytes;
	st->rspbytes += proc->server->rspbytes;
	ust->stat.reqbytes += proc->server->reqbytes;
	ust->stat.rspbytes += proc->server->rspbytes;
	if (!ust->profileurl && proc->server->override) {
	    ust->profileurl = jVar_getString(jVar_get(proc->server->override->jvar, "profile-url"));
	}
    }
    if (proc->flags & VESMAIL_PRF_SHUTDOWN) {
	if (proc->exitcode) st->stat |= VESMAIL_LCST_PROCERR;
	st->stat |= VESMAIL_LCST_PROCDONE;
    }
}

int VESmail_local_watch() {
    if (!VESmail_local_daemons) return VESMAIL_E_PARAM;
    int r = VESmail_daemon_watchall(VESmail_local_daemons, &VESmail_local_watchfn, NULL);
    VESmail_daemon **dp;
    for (dp = VESmail_local_daemons; *dp; dp++) {
	struct VESmail_local_stat *st = (*dp)->ref;
	struct VESmail_daemon_sock *sk;
	for (sk = (*dp)->sock; sk; sk = sk->chain) {
	    if (!sk->ainfo) continue;
	    st->stat |= (sk->sock >= 0 ? VESMAIL_LCST_LSTN : VESMAIL_LCST_LSTNERR);
	}
	VESmail_local_stat_collect(st);
    }
    return r;
}

void VESmail_local_done() {
    VESmail_daemon_freeall(VESmail_local_daemons);
    VESmail_local_daemons = NULL;
    VESmail_daemon_cleanup();
    while (VESmail_local_ustat) VESmail_local_ustat = VESmail_local_ustat_free(VESmail_local_ustat);
    VESmail_optns_free(VESmail_local_conf.optns);
#ifdef VESMAIL_NOW_OAUTH
    VESmail_now_oauth_free(VESmail_local_conf.oauth);
#endif
    VESmail_conf_addwebsock(&VESmail_local_conf, NULL);
    VESmail_tls_done();
    VESmail_arch_done();
}

int VESmail_local_getstat(int idx) {
    if (idx < 0 || idx >= sizeof(VESmail_local_stat) / sizeof(*VESmail_local_stat)) return VESMAIL_E_PARAM;
    int r = VESmail_local_stat[idx].stat;
    VESmail_local_stat[idx].stat = 0;
    return r;
}

#define VESmail_local_login2user(ulogin)	((struct VESmail_local_ustat *)(ulogin - offsetof(struct VESmail_local_ustat, login)))

void VESmail_local_getuser(const char **usr, int *st) {
    struct VESmail_local_ustat *ust = *usr ? VESmail_local_login2user(*usr)->chain : VESmail_local_ustat;
    if (!ust) {
	*usr = NULL;
	if (st) *st = VESMAIL_E_PARAM;
	return;
    }
    *usr = ust->login;
    if (st) {
	VESmail_local_stat_collect(&ust->stat);
	if (ust->stat.stat & VESMAIL_LCST_PROC) {
	    ust->stat.stat &= ~(VESMAIL_LCST_LSTN | VESMAIL_LCST_LSTNERR);
	    if (ust->stat.stat & VESMAIL_LCST_LOGINERR) ust->stat.stat |= VESMAIL_LCST_LSTNERR | VESMAIL_LCST_PROCERR;
	    else if (ust->stat.stat & VESMAIL_LCST_LOGINOK) ust->stat.stat |= VESMAIL_LCST_LSTN;
	}
	*st = ust->stat.stat;
	ust->stat.stat &= (VESMAIL_LCST_LSTN | VESMAIL_LCST_LSTNERR);
    }
}

const char *VESmail_local_getuserprofileurl(const char *ulogin) {
    return ulogin ? VESmail_local_login2user(ulogin)->profileurl : NULL;
}

int VESmail_local_getusererror(const char *ulogin, char *err) {
    if (!ulogin) return 0;
    const char *fmt;
    struct VESmail_local_ustat *ust = VESmail_local_login2user(ulogin);
    switch (ust->authcode) {
	case VESMAIL_E_VES:
	    switch (ust->subcode) {
		case LIBVES_E_NOTFOUND:
		case LIBVES_E_CRYPTO:
		    break;
		default:
		    return 0;
	    }
	case VESMAIL_E_OVRD:
	    fmt = "%s.XVES%d.%d";
	    break;
	case VESMAIL_E_CONF:
	case VESMAIL_E_DENIED:
	case VESMAIL_E_RESOLV:
	case VESMAIL_E_CONN:
	case VESMAIL_E_TLS:
	case VESMAIL_E_SASL:
	case VESMAIL_E_RELAY:
	case VESMAIL_E_RAUTH:
	    fmt = "%s.XVES%d";
	    break;
	default:
	    return 0;
    }
    if (err) sprintf(err, fmt, VESmail_local_conf_daemon[ust->tag].type, ust->authcode, ust->subcode);
    return ust->authcode;
}

int VESmail_local_getunull() {
    VESmail_local_stat_collect(&VESmail_local_unull.stat);
    int r = VESmail_local_unull.stat.stat;
    VESmail_local_unull.stat.stat = 0;
    return r;
}

int VESmail_local_run(long udelay) {
    if (!VESmail_local_daemons) return VESMAIL_E_PARAM;
    while (1) {
	VESmail_arch_usleep(udelay);
	int r = VESmail_local_watch();
	if (r <= 0) return r;
    }
}

const char *VESmail_local_gethost(VESmail_daemon *daemon) {
    return daemon ? VESmail_local_conf_daemon[(unsigned) daemon->tag].host : NULL;
}

const char *VESmail_local_getport(VESmail_daemon *daemon) {
    return daemon ? VESmail_local_conf_daemon[(unsigned) daemon->tag].port : NULL;
}

struct {
    void (*fn)(void *);
    void *arg;
} VESmail_local_wake = {
    .fn = NULL
};

void VESmail_local_wakefn(struct VESmail_conf *conf) {
    if (!VESmail_local_wake.fn) return;
    VESmail_arch_mutex_lock(&VESmail_local_conf.mutex);
    if (VESmail_local_wake.fn) VESmail_local_wake.fn(VESmail_local_wake.arg);
    VESmail_local_wake.fn = NULL;
    VESmail_arch_mutex_unlock(&VESmail_local_conf.mutex);
}

void VESmail_local_sleep(void (* fn)(void *), void *arg) {
    VESmail_arch_log("sleep");
    VESmail_arch_mutex_lock(&VESmail_local_conf.mutex);
    VESmail_local_wake.fn = fn;
    VESmail_local_wake.arg = arg;
    VESmail_arch_mutex_unlock(&VESmail_local_conf.mutex);
}

#ifdef VESMAIL_LOCAL_SNIF

snif_cert VESmail_local_snif_cert = {
    .ou = "VESmail",
    .passphrase = NULL,
    .initurl = VESMAIL_SNIF_INITURL,
    .biofn = NULL
};
VESmail_server *VESmail_local_snif_srv = NULL;

struct VESmail_snif_port VESmail_local_snif_ports[] = {
    { .port = "993", .sock = (void *)0, .tls = 1},
    { .port = "7193", .sock = (void *)0, .tls = 1},
    { .port = "17193", .sock = (void *)0, .tls = 1},
    { .port = "465", .sock = (void *)1, .tls = 1},
    { .port = "7165", .sock = (void *)1, .tls = 1},
    { .port = "17165", .sock = (void *)1, .tls = 1},
    { .port = "587", .sock = (void *)1, .tls = 0},
    { .port = "7183", .sock = (void *)(sizeof(VESmail_local_conf_daemon) / sizeof(*VESmail_local_conf_daemon) - 2), .tls = 1},
    { .port = "17183", .sock = (void *)(sizeof(VESmail_local_conf_daemon) / sizeof(*VESmail_local_conf_daemon) - 2), .tls = 1},
    { .port = NULL }
};

VESmail_server *VESmail_local_snif(const char *crt, const char *pkey, const char *passphrase, const char *initurl) {
    if (VESmail_local_daemons && !VESmail_local_snif_srv) {
	VESmail_snif_initcert(&VESmail_local_snif_cert);
	VESmail_local_snif_cert.certfile = strdup(crt);
	VESmail_local_snif_cert.pkeyfile = strdup(pkey);
	if (passphrase) VESmail_local_snif_cert.passphrase = strdup(passphrase);
	if (initurl) VESmail_local_snif_cert.initurl = strdup(initurl);
	struct VESmail_snif_port *port;
	for (port = VESmail_local_snif_ports; port->port; port++) {
	    port->sock = VESmail_snif_daemonsock(VESmail_local_daemons[(long long)port->sock]);
	}
	VESmail_local_snif_srv = VESmail_snif_new(&VESmail_local_snif_cert, VESmail_local_snif_ports, VESmail_local_daemons);
    }
    return VESmail_local_snif_srv;
}

#define	VESmail_local_snifhdr	VESmail_local_cors[sizeof(VESmail_local_cors) / sizeof(*VESmail_local_cors) - 2]

const char *VESmail_local_snifhost() {
    if (!VESmail_local_snifhdr && VESmail_local_snif_cert.hostname) {
	sprintf((VESmail_local_snifhdr = malloc(strlen(VESmail_local_snif_cert.hostname) + 32)), "X-VESmail-SNIF: %s", VESmail_local_snif_cert.hostname);
    }
    return VESmail_local_snif_cert.hostname;
}

const char *VESmail_local_snifauthurl() {
    return VESmail_local_snif_cert.authurl;
}

int VESmail_local_snifstat() {
    return VESmail_local_snif_srv ? VESmail_snif_stat(VESmail_local_snif_srv) : 0;
}

void VESmail_local_snifawake(int awake) {
    if (!VESmail_local_snif_srv) return;
    VESmail_snif_awake(VESmail_local_snif_srv, awake);
    VESmail_daemon **pd;
    if (awake) for (pd = VESmail_local_daemons; *pd; pd++) (*pd)->flags |= VESMAIL_DMF_RECONNECT;
}

int VESmail_local_snifmsg(const char *msg) {
    return VESmail_local_snif_srv ? VESmail_snif_msg(VESmail_local_snif_srv, msg) : VESMAIL_E_PARAM;
}

void VESmail_local_snifdone() {
    VESmail_server_free(VESmail_local_snif_srv);
    VESmail_local_snif_srv = NULL;
    snif_cert_reset(&VESmail_local_snif_cert);
    free(VESmail_local_snifhdr);
}

#endif

void VESmail_local_killall() {
    if (!VESmail_local_daemons) return;
    VESmail_daemon **pd;
    for (pd = VESmail_local_daemons; *pd; pd++) (*pd)->flags &= ~VESMAIL_DMF_RECONNECT;
    VESmail_daemon_killall(VESmail_local_daemons);
}

int VESmail_local_feedbackfn(const char *fbk) {
    if (!fbk) {
	free(VESmail_local_feedback);
	VESmail_local_feedback = NULL;
	return 0;
    }
    if (strlen(fbk) > VESMAIL_LOCAL_FEEDBACKLEN) return VESMAIL_E_PARAM;
    if (!VESmail_local_feedback) memset((VESmail_local_feedback = malloc(VESMAIL_LOCAL_FEEDBACKLEN + 1)), 0, VESMAIL_LOCAL_FEEDBACKLEN + 1);
    strcpy(VESmail_local_feedback, fbk);
    return VESmail_local_feedback_fn ? VESmail_local_feedback_fn(VESmail_local_feedback) : 0;
}

void VESmail_local_setfeedback(int (* fbkfn)(const char *fbk)) {
    VESmail_local_feedback_fn = fbkfn;
    VESmail_local_conf.now.feedbackFn = &VESmail_local_feedbackfn;
}

#ifdef VESMAIL_NOW_OAUTH
void *VESmail_local_setoauth(const char *keyfile, const char *passwd) {
    VESmail_now_oauth_free(VESmail_local_conf.oauth);
    return VESmail_local_conf.oauth = VESmail_now_oauth_new(keyfile, passwd, NULL);
}
#endif

