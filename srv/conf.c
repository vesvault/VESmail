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
#include <jVar.h>
#include <time.h>
#include "../VESmail.h"
#include "../lib/optns.h"
#include "tls.h"
#include "override.h"
#include "arch.h"

#ifdef VESMAIL_NOW_OAUTH
#include "../now/now_oauth.h"
#endif

#include "conf.h"


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

#define VESmail_conf_ALLOCD_bannerPath		0x01
#define VESmail_conf_ALLOCD_now_websock		0x02
#define VESmail_conf_ALLOCD_now_manifest	0x04
#define VESmail_conf_ALLOCD_now_headers		0x08
#define VESmail_conf_ALLOCD_audit		0x10
#define VESmail_conf_ALLOCD_bcc			0x20
#define VESmail_conf_ALLOCD_oauth		0x40

#ifndef VESMAIL_LOCAL

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

char *VESmail_conf_add_banner(VESmail_conf *conf, const char *path) {
    char *banner = VESmail_conf_get_content(path);
    if (banner) {
	int l;
	if (conf->banner) {
	    for (l = 0; conf->banner[l]; l++);
	} else l = 0;
	conf->banner = realloc(conf->banner, 4 * sizeof(*(conf->banner)) * ((l + 6) / 4));
	conf->banner[l] = banner;
	conf->banner[l + 1] = NULL;
    }
    return banner;
}

const char **VESmail_conf_get_banners(VESmail_optns *optns) {
    VESmail_conf *conf = optns->ref;
    if (conf->mutex && VESmail_arch_mutex_lock(&conf->mutex)) return NULL;
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
    if (conf->mutex) VESmail_arch_mutex_unlock(&conf->mutex);
    return conf->banner;
}

jVar *VESmail_conf_get_app(VESmail_optns *optns) {
    VESmail_conf *conf = optns->ref;
    if (conf->mutex && VESmail_arch_mutex_lock(&conf->mutex)) return NULL;
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
    if (conf->mutex) VESmail_arch_mutex_unlock(&conf->mutex);
    return conf->app;
}

#endif

void VESmail_conf_setstr(char **val, jVar *conf) {
    if (conf) *val = jVar_getStringP(conf);
}

int VESmail_conf_setpstr(char ***d, jVar *b, int f) {
    char **p;
    if (jVar_isArray(b)) {
	p = malloc((jVar_count(b) + 1) * sizeof(*p));
	int i;
	char **pp = p;
	for (i = 0; i < jVar_count(b); i++) {
	    if ((*pp = jVar_getStringP(jVar_index(b, i)))) pp++;
	}
	*pp = NULL;
    } else if (jVar_isString(b)) {
	p = malloc(2 * sizeof(*p));
	p[0] = jVar_getStringP(b);
	p[1] = NULL;
    } else if (jVar_isNull(b)) {
	p = NULL;
    } else {
	return 0;
    }
    if (f) free(*d);
    *d = p;
    return p ? 1 : 0;
}

#ifndef VESMAIL_LOCAL

void VESmail_conf_apply(VESmail_conf *conf, jVar *jconf) {
    VESmail_conf_setstr(&conf->optns->acl, jVar_get(jconf, "acl"));
    VESmail_conf_setstr(&conf->optns->now.url, jVar_get(jconf, "now-url"));
    VESmail_conf_setstr(&conf->optns->now.dir, jVar_get(jconf, "now-dir"));
    VESmail_conf_setstr(&conf->optns->subj, jVar_get(jconf, "subject"));
    VESmail_conf_setstr(&conf->tls->cert, jVar_get(jconf, "cert"));
    VESmail_conf_setstr(&conf->tls->key, jVar_get(jconf, "pkey"));
    VESmail_conf_setstr(&conf->manifest, jVar_get(jconf, "manifest"));
    jVar *jnow = jVar_get(jconf, "now");
    if (jnow) {
	VESmail_conf_setstr(&conf->optns->now.url, jVar_get(jnow, "url"));
	VESmail_conf_setstr(&conf->optns->now.dir, jVar_get(jnow, "dir"));
	if (VESmail_conf_setpstr(&conf->now.headers, jVar_get(jnow, "headers"), (conf->allocd & VESmail_conf_ALLOCD_now_headers))) conf->allocd |= VESmail_conf_ALLOCD_now_headers;
	jVar *max = jVar_get(jnow, "maxsize");
	if (jVar_isInt(max)) conf->now.maxSize = jVar_getInt(max);
	jVar *ws = jVar_get(jnow, "websock");
	if (ws) {
	    if (conf->allocd & VESmail_conf_ALLOCD_now_websock) jVar_free(conf->now.websock);
	    conf->now.websock = ws;
	    conf->allocd &= ~VESmail_conf_ALLOCD_now_websock;
	}
    }
    jVar *jtls = jVar_get(jconf, "tls");
    if (jtls) {
	VESmail_conf_setstr(&conf->tls->cert, jVar_get(jtls, "cert"));
	VESmail_conf_setstr(&conf->tls->key, jVar_get(jtls, "pkey"));
	int lvl = jVar_getEnum(jVar_get(jtls, "level"), VESmail_tls_levels);
	if (lvl >= 0) conf->tls->level = lvl;
    }
    jVar *maxbuf = jVar_get(jconf, "maxbuf");
    if (jVar_isInt(maxbuf)) conf->optns->maxbuf = jVar_getInt(maxbuf);
    jVar *jlog = jVar_get(jconf, "log");
    if (jlog) {
	VESmail_conf_closelog(conf);
	VESmail_conf_setstr(&conf->log.filename, jlog);
    }
    if (VESmail_conf_setpstr(&conf->bannerPath, jVar_get(jconf, "banner"), (conf->allocd & VESmail_conf_ALLOCD_bannerPath))) conf->allocd |= VESmail_conf_ALLOCD_bannerPath;
    if (VESmail_conf_setpstr(&conf->optns->audit, jVar_get(jconf, "audit"), (conf->allocd & VESmail_conf_ALLOCD_audit))) conf->allocd |= VESmail_conf_ALLOCD_audit;
    if (VESmail_conf_setpstr(&conf->optns->bcc, jVar_get(jconf, "bcc"), (conf->allocd & VESmail_conf_ALLOCD_bcc))) conf->allocd |= VESmail_conf_ALLOCD_bcc;
    jVar *jovrs = jVar_get(jconf, "overrides");
    if (jovrs) conf->overrides = jVar_getEnum(jovrs, VESmail_override_modes);
#ifdef VESMAIL_NOW_OAUTH
    jVar *joauth = jVar_get(jconf, "oauth-key");
    if (joauth) {
	if (conf->allocd & VESmail_conf_ALLOCD_oauth) VESmail_now_oauth_free(conf->oauth);
	if ((conf->oauth = VESmail_now_oauth_new(jVar_getStringP(joauth), NULL, NULL))) conf->allocd |= VESmail_conf_ALLOCD_oauth;
    }
#endif
    conf->optns->getBanners = &VESmail_conf_get_banners;
    conf->optns->getApp = &VESmail_conf_get_app;
    conf->optns->ref = conf;
}

void VESmail_conf_applyroot(VESmail_conf *conf, jVar *jconf, int (* snifn)(struct VESmail_server *, const char *)) {
    VESmail_conf_apply(conf, jconf);
    jVar *sni = jVar_get(jconf, "sni");
    if (sni) {
	VESmail_conf_setstr(&conf->sni.prefix, jVar_get(sni, "prefix"));
	VESmail_conf_setstr(&conf->sni.suffix, jVar_get(sni, "suffix"));
	jVar *rq = jVar_get(sni, "require");
	if (rq) conf->sni.require = jVar_getBool(rq);
	conf->tls->snifn = snifn;
    }
#ifndef VESMAIL_X509STORE
    VESmail_conf_setstr(&VESmail_tls_caBundle, jVar_get(jconf, "caBundle"));
#endif
    jVar *mft = jVar_get(jVar_get(jconf, "now"), "manifest");
    if (!mft) mft = jVar_get(jconf, "now-manifest");
    if (mft) {
	if (conf->allocd & VESmail_conf_ALLOCD_now_manifest) free(conf->now.manifest);
	if (jVar_isString(mft)) {
	    conf->now.manifest = jVar_getStringP(mft);
	    conf->allocd &= ~VESmail_conf_ALLOCD_now_manifest;
	} else if (jVar_isObject(mft)) {
	    conf->now.manifest = jVar_toJSON(mft);
	    conf->allocd |= VESmail_conf_ALLOCD_now_manifest;
	} else {
	    conf->now.manifest = NULL;
	}
    }
    jVar *abuse = jVar_get(jconf, "abuse-sense");
    if (abuse) conf->abuseSense = jVar_getInt(abuse);
}

jVar *VESmail_conf_sni_read(VESmail_conf *conf, const char *sni, void (* errfn)(const char *fmt, ...), unsigned long *mtime) {
    if (!conf->sni.prefix || !sni) return NULL;
    if (!conf->sni.suffix) conf->sni.suffix = "";
    char *buf = malloc(strlen(conf->sni.prefix) + strlen(sni) + strlen(conf->sni.suffix) + 1);
    sprintf(buf, "%s%s%s", conf->sni.prefix, sni, conf->sni.suffix);
    if (mtime) {
	unsigned long t = VESmail_arch_mtime(buf);
	if (t == *mtime) return free(buf), NULL;
	*mtime = t;
    }
    jVar *jconf = VESmail_conf_read(buf, errfn);
    free(buf);
    return jconf;
}

void *VESmail_conf_mutex_init(VESmail_conf *conf) {
    conf->mutex = NULL;
    if (VESmail_arch_mutex_lock(&conf->mutex)) return NULL;
    VESmail_arch_mutex_unlock(&conf->mutex);
    return conf->mutex;
}

VESmail_conf *VESmail_conf_clone(VESmail_conf *conf) {
    VESmail_conf *cf = malloc(sizeof(VESmail_conf));
    memcpy(cf, conf, sizeof(*cf));
    if (!VESmail_conf_mutex_init(cf)) return free(cf), NULL;
    if (cf->optns) cf->optns = VESmail_optns_clone(cf->optns);
    if (cf->tls) cf->tls = VESmail_tls_server_clone(cf->tls);
    cf->banner = NULL;
    cf->allocd = 0;
    return cf;
}

#endif

void VESmail_conf_vlog(VESmail_conf *conf, const char *fmt, va_list va) {
    static void *mutex = NULL;
    if (conf->log.wakefn) conf->log.wakefn(conf);
    if (conf->log.filename) {
	if (!conf->log.fh) {
	    if ((conf->log.fh = fopen(conf->log.filename, "a"))) VESmail_arch_setlinebuf(conf->log.fh);
	}
	if (conf->log.fh) {
	    char fbuf[320];
	    time_t t = time(NULL);
	    strftime(fbuf, sizeof(fbuf), "%b %d %H:%M:%S ", localtime(&t));
	    char *d = fbuf + strlen(fbuf);
	    sprintf(d, "%s %s[%d]: %s\n", conf->hostname, conf->progname, VESmail_arch_getpid(), fmt);
	    int r = (!VESMAIL_LOG_MUTEX || !VESmail_arch_mutex_lock(&mutex)) && (vfprintf(conf->log.fh, fbuf, va) > 0);
	    if (VESMAIL_LOG_MUTEX) VESmail_arch_mutex_unlock(&mutex);
	    if (r) return;
	}
    }
    VESmail_arch_vlog(fmt, va);
}

void VESmail_conf_log(VESmail_conf *conf, const char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    VESmail_conf_vlog(conf, fmt, va);
    va_end(va);
}

void VESmail_conf_addwebsock(VESmail_conf *conf, struct VESmail_conf_daemon *cd) {
    if (!cd) {
	if (!(conf->allocd & VESmail_conf_ALLOCD_now_websock)) return;
	jVar_free(conf->now.websock);
	conf->allocd &= ~VESmail_conf_ALLOCD_now_websock;
	return;
    }
    if (conf->now.websock) return;
    jVar *ws = conf->now.websock = jVar_object();
    conf->allocd |= VESmail_conf_ALLOCD_now_websock;
    struct VESmail_conf_daemon *c;
    for (c = cd; c->type; c++) {
	if (c->conf && !c->conf->now.websock) c->conf->now.websock = ws;
	if (jVar_get(ws, c->type)) continue;
	jVar *cf = jVar_put(jVar_put(jVar_object(), "host", jVar_string(conf->hostname)), "port", jVar_string(c->port));
	if (c->conf->tls && c->conf->tls->persist) jVar_put(cf, "tls", jVar_put(jVar_object(), "persist", jVar_bool(1)));
	jVar_put(ws, c->type, cf);
    }
}

#ifndef VESMAIL_LOCAL

void VESmail_conf_closelog(VESmail_conf *conf) {
    if (conf->log.fh) {
	if (conf->log.filename) fclose(conf->log.fh);
	conf->log.fh = NULL;
    }
}

void VESmail_conf_free(VESmail_conf *conf) {
    if (conf) {
	if (conf->allocd & VESmail_conf_ALLOCD_audit) free(conf->optns->audit);
	if (conf->allocd & VESmail_conf_ALLOCD_bcc) free(conf->optns->bcc);
	VESmail_optns_free(conf->optns);
	VESmail_tls_server_free(conf->tls);
	jVar_free(conf->app);
	if (conf->banner) {
	    char **b;
	    for (b = (char **) conf->banner; *b; b++) free(*b);
	    free(conf->banner);
	}
	if (conf->allocd & VESmail_conf_ALLOCD_bannerPath) free(conf->bannerPath);
	if (conf->allocd & VESmail_conf_ALLOCD_now_manifest) free(conf->now.manifest);
	if (conf->allocd & VESmail_conf_ALLOCD_now_headers) free(conf->now.headers);
	if (conf->allocd & VESmail_conf_ALLOCD_now_websock) jVar_free(conf->now.websock);
#ifdef VESMAIL_NOW_OAUTH
	if (conf->allocd & VESmail_conf_ALLOCD_oauth) VESmail_now_oauth_free(conf->oauth);
#endif
	VESmail_arch_mutex_done(conf->mutex);
    }
    free(conf);
}


struct VESmail_conf_daemon *VESmail_conf_daemon_build(VESmail_conf *conf, jVar *jconf) {
    jVar *jds = jVar_get(jconf, "daemons");
    if (!jVar_isArray(jds) || !jds->len) return NULL;
    struct VESmail_conf_daemon *cds = malloc(jds->len * sizeof(struct VESmail_conf_daemon) + offsetof(struct VESmail_conf_daemon, type) + sizeof(cds->type));
    struct VESmail_conf_daemon *dp = cds;
    int i;
    for (i = 0; i < jds->len; i++) {
	jVar *jd = jVar_index(jds, i);
	const char *srv = jVar_getStringP(jVar_get(jd, "server"));
	if (!srv) continue;
	if (!strncmp(srv, "ves-", 4)) srv += 4;
	dp->type = srv;
	dp->conf = VESmail_conf_clone(conf);
	VESmail_conf_applyroot(dp->conf, jVar_get(jconf, srv), conf->tls->snifn);
	VESmail_conf_applyroot(dp->conf, jd, conf->tls->snifn);
	jVar *tlsp = jVar_get(jVar_get(jd, "tls"), "persist");
	if (tlsp && dp->conf->tls) dp->conf->tls->persist = jVar_getBool(tlsp);
	dp->host = jVar_getString(jVar_get(jd, "host"));
	dp->port = jVar_getString(jVar_get(jd, "port"));
	dp->debug = jVar_getInt(jVar_get(jd, "debug"));
	dp->tag = 0;
	dp++;
    }
    dp->type = NULL;
    return cds;
}

void VESmail_conf_daemon_free(struct VESmail_conf_daemon *cds) {
    if (!cds) return;
    struct VESmail_conf_daemon *dp;
    for (dp = cds; dp->type; dp++) {
	VESmail_conf_free(dp->conf);
	free(dp->host);
	free(dp->port);
    }
    free(cds);
}

#endif
