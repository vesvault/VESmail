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
#include "../VESmail.h"
#include "../srv/server.h"
#include "../srv/arch.h"
#include "../srv/tls.h"
#include "../now/now.h"
#include "../now/now_options.h"
#include "../now/now_post.h"
#include "../now/now_store.h"
#include "../now/now_manifest.h"
#include "../now/now_probe.h"
#include "../now/now_websock.h"

#ifdef VESMAIL_NOW_OAUTH
#include "../now/now_oauth.h"
#endif

#include "../srv/conf.h"
#include "../srv/override.h"
#include "cli.h"


int (* cli_reqStack[])(VESmail_now_req *) = {
    &VESmail_now_options_reqStack,
    &VESmail_now_post_reqStack,
    &VESmail_now_store_reqStack,
    &VESmail_now_manifest_reqStack,
#ifdef VESMAIL_NOW_OAUTH
    &VESmail_now_oauth_reqStack,
#endif
    &VESmail_now_websock_reqStack,
    NULL
};

int (* cli_postStack[])(VESmail_server *, jVar *) = {
    &VESmail_now_probe_postStack,
    &VESmail_now_store_postStack,
    NULL
};

struct VESmail_conf cli_conf = {
    .bannerPath = NULL,
    .banner = NULL,
    .manifest = NULL,
    .app = NULL,
    .guard = 0,
    .sni = {
	.prefix = NULL
    },
    .log = {
	.filename = NULL,
	.fh = NULL,
	.wakefn = NULL
    },
    .now = {
	.manifest = NULL,
	.headers = NULL,
	.reqStack = cli_reqStack,
	.postStack = cli_postStack,
	.websock = NULL,
	.maxSize = 1048576
    },
    .abuseSense = 0,
    .overrides = VESMAIL_OVRD_AUTO,
    .oauth = NULL
};

void cli_logfn(void *logref, const char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    VESmail_conf_vlog(&cli_conf, fmt, va);
    va_end(va);
}

void cli_errfn_sni(const char *fmt, ...) {
    char fb[256];
    sprintf(fb, "sni error %s", fmt);
    va_list va;
    va_start(va, fmt);
    VESmail_arch_vlog(fb, va);
    va_end(va);
}

int cli_snifn(VESmail_server *srv, const char *sni) {
    VESmail_arch_log("sni host=%s", sni);
    jVar *jconf = VESmail_conf_sni_read(&cli_conf, sni, &cli_errfn_sni, NULL);
    if (!jconf && cli_conf.sni.require) return VESMAIL_E_CONF;
    VESmail_conf_apply(&cli_conf, jVar_get(jconf, "*"));
    if (srv) {
	VESmail_conf_apply(&cli_conf, jVar_get(jconf, srv->type));
	VESmail_tls_server_ctxreset(srv->tls.server);
    }
    return 0;
}

VESmail_override *cli_ovrdfn(void *ovrdref) {
    return VESmail_override_new(VESmail_override_mode(&cli_conf));
}

