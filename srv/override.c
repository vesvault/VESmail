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

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <libVES.h>
#include <libVES/VaultItem.h>
#include <jVar.h>
#include "../VESmail.h"
#include "../lib/optns.h"
#include "conf.h"
#include "override.h"


#define VESMAIL_VERB(verb, str)	str,
const char *VESmail_override_modes[] = { VESMAIL_OVRD_MODES() NULL };
#undef VESMAIL_VERB

VESmail_override *VESmail_override_new(int mode) {
    if (mode == VESMAIL_OVRD_IGNORE) {
	return NULL;
    }
    VESmail_override *ovrd = malloc(sizeof(VESmail_override));
    ovrd->jvar = NULL;
    ovrd->mode = mode;
    ovrd->optns1 = NULL;
    ovrd->banner = NULL;
    ovrd->code = 0;
    return ovrd;
}

int VESmail_override_load(VESmail_override *ovrd, const char *url, libVES_VaultItem *vitem, libVES *ves) {
    if (ovrd->mode != VESMAIL_OVRD_ALLOW) {
	return VESMAIL_E_DENIED;
    }
    ovrd->jvar = libVES_VaultItem_VESauthGET(vitem, ves, url, &ovrd->code);
    if (ovrd->code != 200) {
	jVar_free(ovrd->jvar);
	ovrd->jvar = NULL;
    }
    if (!ovrd->jvar) return VESMAIL_E_OVRD;
    return 0;
}

const char **VESmail_override_get_banners(VESmail_optns *optns) {
    return (const char **)(((VESmail_override *)(optns->ref))->banner);
}

jVar *VESmail_override_get_app(VESmail_optns *optns) {
    VESmail_override *ovrd = optns->ref;
    return ovrd->optns0->getApp ? ovrd->optns0->getApp(ovrd->optns0->ref) : NULL;
}

int VESmail_override_apply(VESmail_override *ovrd, VESmail_optns **poptns) {
    if (!ovrd->jvar) return 0;
    ovrd->optns0 = *poptns;
    VESmail_optns *op = ovrd->optns1 = VESmail_optns_clone(ovrd->optns0);
    VESmail_conf_setpstr(&op->audit, jVar_get(ovrd->jvar, "audit"), 0);
    VESmail_conf_setpstr(&op->bcc, jVar_get(ovrd->jvar, "bcc"), 0);
    VESmail_conf_setpstr(&ovrd->banner, jVar_get(ovrd->jvar, "banner-content"), 0);
    VESmail_conf_setstr(&op->now.url, jVar_get(ovrd->jvar, "now-url"));
    op->ref = ovrd;
    op->getBanners = &VESmail_override_get_banners;
    op->getApp = &VESmail_override_get_app;
    *poptns = op;
    return 0;
}

int VESmail_override_geterror(VESmail_override *ovrd, libVES *ves, char *buf) {
    if (ovrd->jvar) return *buf = 0;
    const char *err, *info;
    int e = libVES_getErrorInfo(ves, &err, &info);
    char *d = buf;
    if (ovrd->code) {
	sprintf(d, " [HTTP %ld]", ovrd->code);
	d += strlen(d);
    }
    if (e && info) {
	sprintf(d, " %.160s", info);
    }
    return e;
}

int VESmail_override_mode(VESmail_conf *conf) {
    switch (conf->overrides) {
	case VESMAIL_OVRD_AUTO:
	    return conf->optns->acl ? VESMAIL_OVRD_IGNORE : VESMAIL_OVRD_ALLOW;
	default:
	    return conf->overrides;
    }
}

void VESmail_override_free(VESmail_override *ovrd) {
    if (ovrd) {
	if (ovrd->optns1) {
	    if (ovrd->optns1->audit != ovrd->optns0->audit) free(ovrd->optns1->audit);
	    if (ovrd->optns1->bcc != ovrd->optns0->bcc) free(ovrd->optns1->bcc);
	    VESmail_optns_free(ovrd->optns1);
	}
	free(ovrd->banner);
	jVar_free(ovrd->jvar);
    }
    free(ovrd);
}
