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
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <jVar.h>
#include <libVES.h>
#include <libVES/VaultKey.h>
#include <libVES/Ref.h>
#include "../VESmail.h"
#include "../lib/mail.h"
#include "../lib/parse.h"
#include "../lib/optns.h"
#include "../lib/xform.h"
#include "../srv/server.h"
#include "../srv/arch.h"
#include "../srv/tls.h"
#include "../imap/imap.h"
#include "../smtp/smtp.h"
#include "../now/now.h"
#include "../now/now_store.h"
#include "../srv/conf.h"
#include "../srv/daemon.h"
#include "../srv/proc.h"
#include "../srv/guard.h"
#include "help.h"
#include "vesmail.h"

struct VESmail_conf conf = {
    .bannerPath = NULL,
    .banner = NULL,
    .manifest = NULL,
    .app = NULL,
    .guard = 0,
    .bcc = NULL,
    .sni = {
	.prefix = NULL
    },
    .log = {
	.filename = NULL,
	.fh = NULL
    },
    .now = {
	.manifest = NULL,
	.headers = NULL,
	.maxSize = 1048576
    }
};

struct param_st params = {
    .user = NULL,
    .veskey = NULL,
    .token = NULL,
    .confPath = VESMAIL_CONF_PATH "vesmail.conf",
    .veskeyPath = VESMAIL_CONF_PATH "veskeys/",
    .sni = NULL,
    .input = NULL,
    .debug = 0
};

int vm_error(int e) {
    switch (e) {
	case 0: return 0;
	case VESMAIL_E_IO: return E_IO;
	case VESMAIL_E_VES: return E_VES;
	default: return E_INTERNAL;
    }
}

void cli_logfn(void *logref, const char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    VESmail_conf_vlog(&conf, fmt, va);
    va_end(va);
}

void errfn_stderr(const char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    vfprintf(stderr, fmt, va);
    va_end(va);
}

void errfn_sni(const char *fmt, ...) {
    char fb[256];
    sprintf(fb, "sni error %s", fmt);
    va_list va;
    va_start(va, fmt);
    VESmail_arch_vlog(fb, va);
    va_end(va);
}

int cli_snifn(VESmail_server *srv, const char *sni) {
    VESmail_arch_log("sni host=%s", sni);
    jVar *jconf = VESmail_conf_sni_read(&conf, sni, &errfn_sni, NULL);
    if (!jconf && conf.sni.require) return VESMAIL_E_CONF;
    VESmail_conf_apply(&conf, jVar_get(jconf, "*"));
    if (srv) {
	VESmail_conf_apply(&conf, jVar_get(jconf, srv->type));
	VESmail_tls_server_ctxreset(srv->tls.server);
    }
    return 0;
}

int do_convert(VESmail *mail, int in, int out) {
    char src[16];
    char *dst = NULL;
    if (params.sni && conf.tls->snifn) conf.tls->snifn(NULL, params.sni);
    while (1) {
	int srcl = VESmail_arch_read(in, src, sizeof(src));
	if (srcl < 0) {
	    return E_IO;
	}
	int dstl = VESmail_convert(mail, &dst, !srcl, src, srcl);
	if (dstl < 0) {
	    return vm_error(dstl);
	} else {
	    if (!dst && dstl > 0) {
		return E_INTERNAL;
	    }
	    char *d = dst;
	    while (dstl > 0) {
		int wl = VESmail_arch_write(out, d, dstl);
		if (wl < 0) return E_IO;
		dstl -= wl;
		d += wl;
	    }
	}
	free(dst);
	dst = NULL;
	if (!srcl) break;
    }
    return 0;
}

int run_server(VESmail_server *srv, int in, int out) {
    srv->debug = params.debug;
    srv->logfn = &cli_logfn;
    if (params.sni && conf.tls->snifn) conf.tls->snifn(srv, params.sni);
    if (params.dumpfd) sscanf(params.dumpfd, "%d", &srv->dumpfd);
    if (conf.hostname) srv->host = conf.hostname;
    VESmail_server_set_tls(srv, conf.tls);
    int r = VESmail_server_set_fd(srv, in, out);
    if (params.input) {
	const char *s = params.input;
	while (r >= 0 && *s) {
	    const char *e = strchr(s, '\\');
	    if (!e) {
		r = VESmail_xform_process(srv->req_in, 0, s, strlen(s));
		break;
	    }
	    r = VESmail_xform_process(srv->req_in, 0, s, e - s);
	    if (r < 0) break;
	    char c;
	    switch ((c = *++e)) {
		case 'r':
		    c = '\r';
		    break;
		case 'n':
		    c = '\n';
		    break;
		default:
		    break;
	    }
	    r = VESmail_xform_process(srv->req_in, 0, &c, 1);
	    s = e + 1;
	}
    }
    if (r >= 0) r = VESmail_server_run(srv, VESMAIL_SRVR_NOTHR);
    if (r < 0) {
	if (srv->debug > 0) {
	    char *er = VESmail_server_errorStr(srv, r);
	    fprintf(stderr, "%s\n", er);
	    free(er);
	}
    }
    VESmail_server_free(srv);
    return vm_error(r);
}

void apply_conf(jVar *jconf) {
    VESmail_conf_applyroot(&conf, jconf, &cli_snifn);
    VESmail_conf_setstr(&params.veskeyPath, jVar_get(jconf, "veskey-dir"));
}

int main(int argc, char **argv) {
#ifdef VESMAIL_MTRACE
    mtrace();
#endif
    char **argend = argv + argc;
    char **argp = argv + 1;
    char *arg = NULL;
    enum { o_null, o_error, o_data, o_ver, o_a, o_f, o_x, o_v, o_tls, o_sni, o_demo, o_cap, o_rcpt, o_noenc, o_xchg, o_token,
	o_help, o_dumpfd, o_conf, o_guard, o_input } op = o_null;
    enum { cmd_null, cmd_enc, cmd_dec, cmd_smtp, cmd_imap, cmd_now, cmd_daemon } cmd = cmd_null;
    const struct { char op; char *argw; } argwords[] = {
	{o_a, "account"}, {o_x, "debug"}, {o_v, "veskey"}, {o_v, "VESkey"}, {o_v, "unlock"}, {o_token, "token"},
	{o_tls, "tls"}, {o_cap, "capabilities"}, {o_ver, "version"}, {o_rcpt, "rcpt"}, {o_noenc, "headers"},
	{o_guard, "guard"}, {o_conf, "conf"}, {o_sni, "sni"}, {o_demo, "demo"}, {o_input, "input"},
	{o_help, "help"}, {o_dumpfd, "dumpfd"}
    };
    const struct { char cmd; char *cmdw; } cmdwords[] = {
	{cmd_enc, "encrypt"}, {cmd_dec, "decrypt"}, {cmd_smtp, "smtp"}, {cmd_imap, "imap"}, {cmd_now, "now"},
	{cmd_daemon, "daemon"}
    };
    struct {
	void **ptr;
	void *(*putfn)(const char *, size_t, void **);
	void *(*getfn)(const char *, size_t *, void **);
	struct setfn_st *setptr;
    } in = {.ptr = NULL, .putfn = NULL, .getfn = NULL, .setptr = NULL};

    conf.hostname = VESmail_arch_gethostname();
    conf.progname = conf.progpath = argv[0];
    const char *prg1;
    for (; (prg1 = strchr(conf.progname, '/')); conf.progname = prg1 + 1);
    for (; (prg1 = strchr(conf.progname, '\\')); conf.progname = prg1 + 1);
    conf.optns = VESmail_optns_new();
    conf.optns->idBase = malloc(strlen(conf.hostname) + 12);
    sprintf(conf.optns->idBase, ".VESmail@%s", conf.hostname);
    conf.tls = VESmail_tls_server_new();
//    params.optns->getBanners = &init_banner;
    
    /**************************************
     * Collect the command line arguments
     */
    while (arg || argp < argend) {
	op = o_null;
	if (!arg) {
	    arg = *argp++;
	    if (*arg == '-') {
		arg++;
		if (*arg == '-') {
		    int i;
		    for (i = 0; i < sizeof(argwords) / sizeof(*argwords); i++) {
			char *s = argwords[i].argw;
			char *d = arg + 1;
			while (*s && *s++ == *d++);
			if (*s) continue;
			switch (*d) {
			    case '=': case '-': case 0:
				op = argwords[i].op;
				arg = d;
			    default: break;
			}
			if (op != o_null) break;
		    }
		    if (op == o_null) {
			fprintf(stderr, "Unrecognized option: %s\nUse help' for option list\n", arg - 1);
			op = o_error;
		    }
		}
	    } else op = o_data;
	}
	if (op == o_null) switch (*arg++) {
	    case 0: arg = NULL; break;
	    case 'a': op = o_a; break;
	    case 'i': op = o_input; break;
	    case 'u': case 'v': op = o_v; break;
	    case 'x': op = o_x; break;
	    case 's': op = o_sni; break;
	    case 't': op = o_tls; break;
	    case 'T': op = o_token; break;
	    case 'V': op = o_ver; break;
	    case 'C': op = o_conf; break;
	    case 'G': op = o_guard; break;
	    case '-': break;
	    case '=': op = o_data; break;
	    default:
		fprintf(stderr, "Unrecognized option: '-%c' (%s)\nUse '--help' for option list\n", *(arg - 1), *(argp - 1));
		op = o_error;
		break;
	}
	switch (op) {
	    case o_null:
	    case o_error:
		break;
	    case o_help:
		VESmail_help(0);
		return 0;
	    default:
		if (in.ptr) switch (op) {
		    case o_data: {
			size_t len;
			char *val;
			if (in.getfn) val = in.getfn(arg, &len, in.ptr);
			else len = strlen(val = strdup(arg));
			if (!val) return E_PARAM;
			if (in.putfn) {
			    if (!in.putfn(val, len, in.ptr)) return E_PARAM;
			} else *((char **) in.ptr) = val;
			in.ptr = NULL;
			in.putfn = NULL;
			in.getfn = NULL;
			in.setptr = NULL;
			arg = NULL;
			break;
		    }
		    default:
			fprintf(stderr, "expected: value or action modifier, see '--help'\n");
			op = o_error;
			break;
		} else switch(op) {
		    case o_a:
			in.ptr = (void *) &params.user;
			break;
		    case o_v:
			in.ptr = (void *) &params.veskey;
			break;
		    case o_token:
			in.ptr = (void *) &params.token;
			break;
		    case o_sni:
			in.ptr = (void *) &params.sni;
			break;
		    case o_conf:
			in.ptr = (void *) &params.confPath;
			break;
		    case o_guard:
			conf.guard++;
			break;
		    case o_input:
			in.ptr = (void *) &params.input;
			break;
		    case o_dumpfd:
			in.ptr = (void *) &params.dumpfd;
			break;
		    case o_tls:
			conf.tls->persist = 1;
			break;
		    case o_x:
			if (params.debug < 0) params.debug = 1;
			else params.debug++;
			break;
		    case o_ver:
			printf("%s\n", VESMAIL_VERSION_STR);
			return 0;
		    case o_null:
			break;
		    case o_data: {
			int i;
			int l = strlen(arg);
			for (i = 0; i < sizeof(cmdwords) / sizeof(*cmdwords); i++) {
			    if (!strncmp(arg, cmdwords[i].cmdw, l)) {
				if (cmd != cmd_null && cmd != cmdwords[i].cmd) {
				    fprintf(stderr, "Ambiguous or duplicate command: %s\n", *(argp - 1));
				    op = o_error;
				} else {
				    cmd = cmdwords[i].cmd;
				}
			    }
			}
			if (cmd == cmd_null) {
			    fprintf(stderr, "Unrecognized command: %s\n", *(argp - 1));
			    op = o_error;
			} else arg = NULL;
			break;
		    }
		    default:
			fprintf(stderr, "Unexpected argument in this context: %s\n", *(argp - 1));
			op = o_error;
			break;
		}
		break;
	}
	if (op == o_error) break;
    }
    if (op == o_error) return E_PARAM;
    if (in.ptr) {
	fprintf(stderr, "Unexpected end of argument list\n");
	return E_PARAM;
    }
    if (cmd == cmd_null) {
	VESmail_help(1);
	fprintf(stderr, "Missing a command, see --help\n");
	return E_PARAM;
    }
    
    jVar *jconf = VESmail_conf_read(params.confPath, &errfn_stderr);
    apply_conf(jVar_get(jconf, "*"));
    
    libVES_init(VESMAIL_VERSION_SHORT);
    VESmail_arch_init();
    VESmail_tls_init();
    
    int rs = 0;
    switch (cmd) {
	case cmd_enc:
	case cmd_dec: {
	    if (params.user && !params.veskey && params.veskeyPath) {
		char *f = malloc(strlen(params.user) + strlen(params.veskeyPath) + 2);
		strcpy(f, params.veskeyPath);
		strcat(f, params.user);
		params.veskey = VESmail_conf_get_content(f);
		if (!params.veskey) {
		    if (params.debug >= 0) fprintf(stderr, "Error reading VESkey from %s\n", f);
		    return E_IO;
		}
	    }
	    if ((!params.user || !params.veskey) && !params.token) {
		fprintf(stderr, "Required: -a <email> [-u <VESkey>] | -T <token>\n");
		return E_PARAM;
	    }
	    libVES *ves;
	    if (!params.user || strchr(params.user, '/')) {
		ves = libVES_new(params.user);
	    } else {
		libVES_Ref *ref = libVES_External_new(VESMAIL_VES_DOMAIN, params.user);
		ves = libVES_fromRef(ref);
	    }
	    VESmail_tls_initVES(ves);
	    if (params.debug > 1) ves->debug = params.debug - 1;
	    if (params.token) libVES_setSessionToken(ves, params.token);
	    if (!params.veskey || libVES_unlock(ves, strlen(params.veskey), params.veskey)) {
		VESmail *mail = cmd == cmd_enc
		    ? VESmail_now_store_apply(VESmail_new_encrypt(ves, conf.optns))
		    : VESmail_new_decrypt(ves, conf.optns);
		if (mail) {
		    mail->logfn = &cli_logfn;
		    rs = do_convert(mail, 0, 1);
		    VESmail_free(mail);
		} else {
		    rs = E_INTERNAL;
		}
	    } else {
		rs = E_VES;
	    }
	    libVES_free(ves);
	    break;
	}
	case cmd_imap: {
	    apply_conf(jVar_get(jconf, "imap"));
	    rs = vm_error(run_server(VESmail_server_new_imap(conf.optns), 0, 1));
	    break;
	}
	case cmd_smtp: {
	    apply_conf(jVar_get(jconf, "smtp"));
	    rs = vm_error(run_server(VESmail_server_new_smtp(conf.optns), 0, 1));
	    break;
	}
	case cmd_now: {
	    apply_conf(jVar_get(jconf, "now"));
	    rs = vm_error(run_server(VESmail_server_new_now(conf.optns), 0, 1));
	    break;
	}
	case cmd_daemon: {
	    struct VESmail_conf_daemon *cds = VESmail_conf_daemon_build(&conf, jconf);
	    VESmail_daemon **daemons = VESmail_daemon_execute(cds);
	    if (!daemons) {
		rs = E_CONF;
		break;
	    }
	    if (params.debug) {
		VESmail_daemon **d;
		for (d = daemons; *d; d++) (*d)->debug += params.debug;
	    }
	    int g = VESmail_guard(daemons, conf.guard);
	    if (g > 0) {
		if (VESmail_daemon_launchall(daemons) > 0) {
		    VESmail_arch_usleep(2000000);
		    while (VESmail_daemon_watchall(daemons, NULL, NULL) > 0) {
			VESmail_arch_usleep(2000000);
		    }
		} else {
		    rs = E_IO;
		}
	    } else if (g < 0) {
		rs = E_IO;
	    }
	    VESmail_daemon_freeall(daemons);
	    VESmail_conf_daemon_free(cds);
	    break;
	}
	default:
	    break;
    }
    free(conf.optns->idBase);
    VESmail_optns_free(conf.optns);
    VESmail_tls_server_free(conf.tls);
    jVar_free(jconf);
    return rs;
}
