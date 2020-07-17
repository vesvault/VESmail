/***************************************************************************
 *  _____
 * |\    | >                   VESmail Project
 * | \   | >  ___       ___    Email Encryption made Convenient and Reliable
 * |  \  | > /   \     /   \                              https://mail.ves.world
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
#include "vesmail.h"
#include "conf.h"


void set_conf_str(char **val, jVar *conf) {
    if (conf) *val = jVar_getString0(conf);
}

void apply_conf(jVar *conf) {
    set_conf_str(&params.optns->acl, jVar_get(conf, "acl"));
    set_conf_str(&params.optns->now.url, jVar_get(conf, "now-url"));
    set_conf_str(&params.optns->now.dir, jVar_get(conf, "now-dir"));
    set_conf_str(&tls_srv.cert, jVar_get(conf, "cert"));
    set_conf_str(&tls_srv.ca, jVar_get(conf, "ca"));
    set_conf_str(&tls_srv.key, jVar_get(conf, "pkey"));
    set_conf_str(&params.veskeyPath, jVar_get(conf, "veskey-dir"));

    jVar *b = jVar_get(conf, "banner");
    if (jVar_isArray(b)) {
	char **p = params.bannerPath = malloc((jVar_count(b) + 1) * sizeof(*p));
	int i;
	for (i = 0; i < jVar_count(b); i++) {
	    *p = jVar_getString0(jVar_index(b, i));
	    if (*p) p++;
	}
	*p = NULL;
    } else if (jVar_isNull(b)) {
	params.bannerPath = NULL;
    }
}

jVar *read_conf(const char *path) {
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
		    fprintf(stderr, "%s:%d: JSON parse error\n", path, lineno);
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
	fprintf(stderr, "%s:EOF: JSON parse error\n", path);
	r = VESMAIL_E_CONF;
    }
    if (r < 0) {
	if (jp) jVar_free(jVarParser_done(jp));
	return NULL;
    }
    return jVarParser_done(jp);
}
