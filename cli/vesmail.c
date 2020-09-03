/***************************************************************************
 *  _____
 * |\    | >                   VESmail Project
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
#include <fcntl.h>
#include <jVar.h>
#include <libVES.h>
#include <libVES/VaultKey.h>
#include <libVES/Ref.h>
#include "../VESmail.h"
#include "../lib/mail.h"
#include "../lib/parse.h"
#include "../lib/optns.h"
#include "../srv/server.h"
#include "../srv/arch.h"
#include "../srv/tls.h"
#include "../imap/imap.h"
#include "../smtp/smtp.h"
#include "../now/now.h"
#include "../now/now_store.h"
#include "help.h"
#include "conf.h"
#include "vesmail.h"

struct VESmail_tls_server tls_srv = {
    .cert = NULL,
    .ca = NULL,
    .key = NULL,
    .persist = 0
};
struct param_st params = {
    .user = NULL,
    .veskey = NULL,
    .token = NULL,
    .confPath = VESMAIL_CONF_PATH "vesmail.conf",
    .veskeyPath = VESMAIL_CONF_PATH "veskeys/",
    .bannerPath = NULL,
    .banner = NULL,
    .debug = 0
};

int vm_error(e) {
    switch (e) {
	case VESMAIL_E_IO: return E_IO;
	case VESMAIL_E_VES: return E_VES;
	default: return E_INTERNAL;
    }
}

int do_convert(VESmail *mail, int in, int out) {
    char src[16];
    char *dst = NULL;
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

char *get_content(const char *path) {
    int fd = VESmail_arch_openr(path);
    if (fd < 0) return NULL;
    int max = 65536;
    int len = 0;
    char *cont = malloc(max);
    int r;
    while (1) {
	r = VESmail_arch_read(fd, cont + len, max - len);
	if (r <= 0) break;
	len += r;
	if (len == max) {
	    max += 65536;
	    cont = realloc(cont, max);
	}
    }
    VESmail_arch_close(fd);
    if (r < 0) {
	free(cont);
	cont = NULL;
    } else {
	cont = realloc(cont, len + 1);
	cont[len] = 0;
    }
    return cont;
}

char *add_banner(const char *path) {
    char *banner = get_content(path);
    if (banner) {
	int l;
	if (params.banner) {
	    for (l = 0; params.banner[l]; l++);
	} else l = 0;
	params.banner = realloc(params.banner, sizeof(*(params.banner)) * (l + 2));
	params.banner[l] = banner;
	params.banner[l + 1] = NULL;
    }
    return banner;
}

const char **init_banner(VESmail_optns *optns) {
    if (!params.banner) {
	if (params.bannerPath) {
	    char **p = params.bannerPath;
	    while (*p) add_banner(*p++);
	    if (!params.banner) *(params.banner = malloc(sizeof(*params.banner))) = NULL;
	} else {
	    add_banner(VESMAIL_CONF_PATH "vesmail-banner-txt");
	    add_banner(VESMAIL_CONF_PATH "vesmail-banner-html");
	}
    }
    return params.banner;
}

int run_server(VESmail_server *srv, int in, int out) {
    srv->debug = params.debug;
    if (params.dumpfd) sscanf(params.dumpfd, "%d", &srv->dumpfd);
    if (params.hostname) srv->host = params.hostname;
    VESmail_server_set_tls(srv, &tls_srv);
    int r = VESmail_server_set_fd(srv, in, out);
    if (r >= 0) r = VESmail_server_run(srv, 0);
    VESmail_server_free(srv);
    if (r < 0) {
	if (srv->debug > 0) {
	    char *er = VESmail_server_errorStr(srv, r);
	    fprintf(stderr, "%s\n", er);
	    free(er);
	}
	return vm_error(r);
    }
    return r;
}

int main(int argc, char **argv) {
#ifdef VESMAIL_MTRACE
    mtrace();
#endif
    char **argend = argv + argc;
    char **argp = argv + 1;
    char *arg = NULL;
    enum { o_null, o_error, o_data, o_ver, o_a, o_f, o_x, o_v, o_tls, o_demo, o_cap, o_rcpt, o_noenc, o_xchg, o_token,
	o_help, o_dumpfd, o_conf } op = o_null;
    enum { cmd_null, cmd_enc, cmd_dec, cmd_smtp, cmd_imap, cmd_now } cmd = cmd_null;
    const struct { char op; char *argw; } argwords[] = {
	{o_a, "account"}, {o_x, "debug"}, {o_v, "veskey"}, {o_v, "VESkey"}, {o_v, "unlock"}, {o_token, "token"},
	{o_tls, "tls"}, {o_cap, "capabilities"}, {o_ver, "version"}, {o_rcpt, "rcpt"}, {o_noenc, "headers"},
	{o_conf, "conf"}, {o_demo, "demo"}, {o_help, "help"}, {o_dumpfd, "dumpfd"}
    };
    const struct { char cmd; char *cmdw; } cmdwords[] = {
	{cmd_enc, "encrypt"}, {cmd_dec, "decrypt"}, {cmd_smtp, "smtp"}, {cmd_imap, "imap"}, {cmd_now, "now"}
    };
    struct {
	void **ptr;
	void *(*putfn)(const char *, size_t, void **);
	void *(*getfn)(const char *, size_t *, void **);
	struct setfn_st *setptr;
    } in = {.ptr = NULL, .putfn = NULL, .getfn = NULL, .setptr = NULL};

    params.hostname = VESmail_arch_gethostname();
    params.optns = VESmail_optns_new();
    params.optns->getBanners = &init_banner;
    
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
	    case 'u': case 'v': op = o_v; break;
	    case 'x': op = o_x; break;
	    case 't': op = o_tls; break;
	    case 'T': op = o_token; break;
	    case 'V': op = o_ver; break;
	    case 'C': op = o_conf; break;
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
		VESmail_help();
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
		    case o_conf:
			in.ptr = (void *) &params.confPath;
			break;
		    case o_dumpfd:
			in.ptr = (void *) &params.dumpfd;
			break;
		    case o_tls:
			tls_srv.persist = 1;
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
	VESmail_help();
	fprintf(stderr, "Missing a command\n");
	return E_PARAM;
    }
    
    jVar *conf = read_conf(params.confPath);
    apply_conf(jVar_get(conf, "*"));
    
    libVES_init(VESMAIL_VERSION_SHORT);
    VESmail_tls_init();
    
    int rs = 0;
    switch (cmd) {
	case cmd_enc:
	case cmd_dec: {
	    if (params.user && !params.veskey && params.veskeyPath) {
		char *f = malloc(strlen(params.user) + strlen(params.veskeyPath) + 2);
		strcpy(f, params.veskeyPath);
		strcat(f, params.user);
		params.veskey = get_content(f);
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
	    if (params.debug > 1) ves->debug = params.debug - 1;
	    if (params.token) libVES_setSessionToken(ves, params.token);
	    if (!params.veskey || libVES_unlock(ves, strlen(params.veskey), params.veskey)) {
		VESmail *mail = cmd == cmd_enc
		    ? VESmail_now_store_apply(VESmail_new_encrypt(ves, params.optns))
		    : VESmail_new_decrypt(ves, params.optns);
		if (mail) {
		    mail->logfn = &VESmail_arch_log;
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
	    apply_conf(jVar_get(conf, "imap"));
	    return run_server(VESmail_server_new_imap(params.optns), 0, 1);
	}
	case cmd_smtp: {
	    apply_conf(jVar_get(conf, "smtp"));
	    return run_server(VESmail_server_new_smtp(params.optns), 0, 1);
	}
	case cmd_now: {
	    apply_conf(jVar_get(conf, "now"));
	    return run_server(VESmail_server_new_now(params.optns), 0, 1);
	}
	default:
	    break;
    }
    return rs;
}
