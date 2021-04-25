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
#include "../VESmail.h"
#include "../lib/optns.h"
#include "server.h"
#include "arch.h"
#include "tls.h"
#include "conf.h"
#include "daemon.h"
#include "proc.h"
#include "override.h"
#include "local.h"


char *VESmail_local_cors[] = {
    "Access-Control-Allow-Headers: *",
    "Access-Control-Allow-Methods: *",
    "Access-Control-Allow-Origin: *",
    "Access-Control-Max-Age: 86400",
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
	.fh = NULL
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
	.headers = VESmail_local_cors
    },
    .tls = &VESmail_local_tls,
    .abuseSense = 0,
    .overrides = VESMAIL_OVRD_ALLOW,
    .dumpfd = -1
};

struct VESmail_conf_daemon VESmail_local_conf_daemon[] = {
    {
	.type = "imap",
	.host = VESmail_local_host,
	.port = "7143",
	.conf = &VESmail_local_conf,
	.debug = 0
    },
    {
	.type = "smtp",
	.host = VESmail_local_host,
	.port = "7125",
	.conf = &VESmail_local_conf,
	.debug = 0
    },
#ifdef VESMAIL_STDPORTS
    {
	.type = "imap",
	.host = VESmail_local_host,
	.port = "143",
	.conf = &VESmail_local_conf,
	.debug = 0
    },
    {
	.type = "smtp",
	.host = VESmail_local_host,
	.port = "587",
	.conf = &VESmail_local_conf,
	.debug = 0
    },
#endif
    {
	.type = "now",
	.host = VESmail_local_host,
	.port = "7180",
	.conf = &VESmail_local_conf,
	.debug = 0
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
    char login[0];
} *VESmail_local_ustat = NULL;

int VESmail_local_ulen = 0;

struct VESmail_local_ustat VESmail_local_unull = {
    .chain = NULL,
    .login = ""
};

struct VESmail_daemon **VESmail_local_daemons = NULL;


struct VESmail_local_ustat *VESmail_local_ustat_free(struct VESmail_local_ustat *ustat) {
    struct VESmail_local_ustat *next;
    if (ustat) {
	next = ustat->chain;
	free(ustat->profileurl);
	free(ustat);
    } else next = NULL;
    return next;
}

void VESmail_local_init() {
    static char init = 0;
    if (init) return;
    init = 1;
    libVES_init(VESMAIL_VERSION_SHORT);
    VESmail_arch_init();
    VESmail_tls_init();
}

VESmail_override *VESmail_local_ovrdfn(void *ovrdref) {
    return VESmail_override_new(VESmail_override_mode(&VESmail_local_conf));
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
	VESmail_local_daemons = VESmail_daemon_execute(VESmail_local_conf_daemon);
	if (VESmail_local_daemons) {
	    VESmail_daemon_launchall(VESmail_local_daemons);
	}
	struct VESmail_local_stat *st = VESmail_local_stat;
	VESmail_daemon **dp = VESmail_local_daemons;
	for (; st < VESmail_local_stat + sizeof(VESmail_local_stat) / sizeof(*VESmail_local_stat); st++) {
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
		VESmail_local_stat_init(&ust->stat);
		VESmail_local_ulen++;
	    }
	}
	int setf;
	switch (proc->server->authcode) {
	    case 0:
		setf = VESMAIL_LCST_PROC | VESMAIL_LCST_LOGINOK;
		break;
	    case VESMAIL_E_HOLD:
		setf = VESMAIL_LCST_PROC;
		break;
	    default:
		setf = VESMAIL_LCST_PROC | VESMAIL_LCST_LOGINERR;
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
	    st->stat |= (sk->sock >= 0 ? VESMAIL_LCST_LSTN : VESMAIL_LCST_LSTNERR);
	}
	VESmail_local_stat_collect(st);
    }
    if (r <= 0) {
	VESmail_daemon_freeall(VESmail_local_daemons);
	VESmail_local_daemons = NULL;
	VESmail_daemon_cleanup();
	while (VESmail_local_ustat) VESmail_local_ustat = VESmail_local_ustat_free(VESmail_local_ustat);
    }
    return r;
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
	    if (ust->stat.stat & VESMAIL_LCST_LOGINOK) ust->stat.stat |= VESMAIL_LCST_LSTN;
	    if (ust->stat.stat & VESMAIL_LCST_LOGINERR) ust->stat.stat |= VESMAIL_LCST_LSTNERR;
	}
	*st = ust->stat.stat;
	ust->stat.stat &= (VESMAIL_LCST_LSTN | VESMAIL_LCST_LSTNERR);
    }
}

const char *VESmail_local_getuserprofileurl(const char *ulogin) {
    return ulogin ? VESmail_local_login2user(ulogin)->profileurl : NULL;
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

