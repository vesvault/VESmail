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
#include <jVar.h>
#include "../VESmail.h"
#include "../lib/optns.h"
#include "../srv/tls.h"
#include "../srv/arch.h"
#include "conf.h"


jVar *VESmail_conf_read(const char *path, void (* errfn)(const char *fmt, ...)) {
    int fd = VESmail_arch_openr(path);
    if (fd < 0) return NULL;
    char buf[4096];
    enum { st_init, st_parse, st_skip } st = st_init;
    int lineno = 1;
    jVarParser *jp = jVarParser_new(NULL);
    int r = 0;
    while (r >= 0) {
	r = VESmail_arch_read(fd, buf, sizeof(buf));
	if (r <= 0) break;
	char *s = buf;
	char *tail = s + r;
	while (s < tail) {
	    char *nl = memchr(s, '\n', tail - s);
	    char *eol = nl ? nl + 1 : tail;
	    if (st == st_init) switch (*s) {
		case '#': case '/': case ';':
		    st = st_skip;
		    break;
		default:
		    st = st_parse;
		    break;
	    }
	    if (jp && st == st_parse) {
		jp = jVarParser_parse(jp, s, eol - s);
		if (jVarParser_isError(jp)) {
		    if (errfn) errfn("%s:%d: JSON parse error\n", path, lineno);
		    r = VESMAIL_E_CONF;
		    break;
		}
	    }
	    s = eol;
	    if (nl) {
		lineno++;
		st = st_init;
	    }
	}
    }
    VESmail_arch_close(fd);
    if (r >= 0 && !jVarParser_isComplete(jp)) {
	if (errfn) errfn("%s:EOF: JSON parse error\n", path);
	r = VESMAIL_E_CONF;
    }
    if (r < 0) {
	if (jp) jVar_free(jVarParser_done(jp));
	return NULL;
    }
    return jVarParser_done(jp);
}

char *VESmail_conf_get_content(const char *path) {
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

char *VESmail_conf_add_banner(VESmail_conf *conf, const char *path) {
    char *banner = VESmail_conf_get_content(path);
    if (banner) {
	int l;
	if (conf->banner) {
	    for (l = 0; conf->banner[l]; l++);
	} else l = 0;
	conf->banner = realloc(conf->banner, sizeof(*(conf->banner)) * ((l + 6) / 4));
	conf->banner[l] = banner;
	conf->banner[l + 1] = NULL;
    }
    return banner;
}

const char **VESmail_conf_get_banners(VESmail_optns *optns) {
    VESmail_conf *conf = optns->ref;
    if (!conf->banner) {
	if (conf->bannerPath) {
	    char **p = conf->bannerPath;
	    while (*p) VESmail_conf_add_banner(conf, *p++);
	    if (!conf->banner) *(conf->banner = malloc(sizeof(*conf->banner))) = NULL;
	} else {
	    VESmail_conf_add_banner(conf, VESMAIL_CONF_PATH "vesmail-banner-txt");
	    VESmail_conf_add_banner(conf, VESMAIL_CONF_PATH "vesmail-banner-html");
	}
    }
    return conf->banner;
}

jVar *VESmail_conf_get_app(VESmail_optns *optns) {
    VESmail_conf *conf = optns->ref;
    if (!conf->app) {
	jVar *capp = NULL;
	int cl = 0;
	if (conf->manifest) {
	    jVar *mft = VESmail_conf_read(conf->manifest, NULL);
	    jVar *apps = jVar_get(mft, "apps");
	    if (jVar_isArray(apps)) {
		int i;
		for (i = 0; i < apps->len; i++) {
		    jVar *app = jVar_index(apps, i);
		    const char *p = jVar_getStringP(jVar_get(app, "href"));
		    if (p) {
			int l = strlen(p);
			if (l < cl) continue;
			const char *now = conf->optns->now.url;
			if (*p == '/') {
			    now = strchr(now, '/');
			    if (now && p[1] != '/') now = strchr(now + 2, '/');
			    if (now && !strncmp(now, p, l)) {
				capp = app;
				cl = l;
			    }
			}
		    }
		}
	    }
	    if (capp) capp = jVar_detach(capp);
	    jVar_free(mft);
	}
	conf->app = capp ? capp : jVar_object();
    }
    return conf->app;
}

void VESmail_conf_setstr(char **val, jVar *conf) {
    if (conf) *val = jVar_getStringP(conf);
}

void VESmail_conf_apply(VESmail_conf *conf, jVar *jconf) {
    VESmail_conf_setstr(&conf->optns->acl, jVar_get(jconf, "acl"));
    VESmail_conf_setstr(&conf->optns->now.url, jVar_get(jconf, "now-url"));
    VESmail_conf_setstr(&conf->optns->now.dir, jVar_get(jconf, "now-dir"));
    VESmail_conf_setstr(&conf->tls->cert, jVar_get(jconf, "cert"));
    VESmail_conf_setstr(&conf->tls->ca, jVar_get(jconf, "ca"));
    VESmail_conf_setstr(&conf->tls->key, jVar_get(jconf, "pkey"));
    VESmail_conf_setstr(&conf->manifest, jVar_get(jconf, "manifest"));

    jVar *b = jVar_get(jconf, "banner");
    if (jVar_isArray(b)) {
	char **p = conf->bannerPath = malloc((jVar_count(b) + 1) * sizeof(*p));
	int i;
	for (i = 0; i < jVar_count(b); i++) {
	    *p = jVar_getStringP(jVar_index(b, i));
	    if (*p) p++;
	}
	*p = NULL;
    } else if (jVar_isNull(b)) {
	conf->bannerPath = NULL;
    }
    conf->optns->getBanners = &VESmail_conf_get_banners;
    conf->optns->getApp = &VESmail_conf_get_app;
    conf->optns->ref = conf;
}

jVar *VESmail_conf_sni_read(VESmail_conf *conf, const char *sni, void (* errfn)(const char *fmt, ...)) {
    if (!conf->sni.prefix || !sni) return NULL;
    if (!conf->sni.suffix) conf->sni.suffix = "";
    char *buf = malloc(strlen(conf->sni.prefix) + strlen(sni) + strlen(conf->sni.suffix) + 1);
    sprintf(buf, "%s%s%s", conf->sni.prefix, sni, conf->sni.suffix);
    jVar *jconf = VESmail_conf_read(buf, errfn);
    free(buf);
    return jconf;
}

