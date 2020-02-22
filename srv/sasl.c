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

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "../VESmail.h"
#include "../lib/util.h"
#include "sasl.h"

#define VESMAIL_VERB(verb)	#verb,
const char *VESmail_sasl_mechs[] = { VESMAIL_SASL_MECHS() NULL };
#undef VESMAIL_VERB

VESmail_sasl *VESmail_sasl_init(VESmail_sasl *sasl, int mech, char *(*tokenfn)(VESmail_sasl *, const char *, int)) {
    sasl->mech = mech;
    sasl->user = sasl->passwd = NULL;
    sasl->pwlen = 0;
    sasl->state = 0;
    sasl->tokenfn = tokenfn;
    sasl->freefn = NULL;
    return sasl;
}

char *VESmail_sasl_fn_cln_plain(VESmail_sasl *sasl, const char *token, int len) {
    if (sasl->state > 0) return NULL;
    sasl->state = 1;
    int ul = sasl->user ? strlen(sasl->user) : 0;
    int pl = sasl->pwlen;
    int l;
    char *saslt = malloc(l = ul + pl + 2);
    saslt[0] = 0;
    if (ul > 0) memcpy(saslt + 1, sasl->user, ul);
    saslt[ul + 1] = 0;
    if (pl > 0) memcpy(saslt + ul + 2, sasl->passwd, pl);
    char *b64 = VESmail_b64encode(saslt, l, NULL);
    free(saslt);
    return b64;
}

char *VESmail_sasl_fn_srv_plain(VESmail_sasl *sasl, const char *token, int len) {
    if (!token) return strdup("");
    char *buf = NULL;
    const char *er = NULL;
    int l = VESmail_b64decode(&buf, token, &len, &er);
    if (!er && l > 0) {
	char *tail = buf + l;
	char *usr = memchr(buf, 0, l);
	if (usr) {
	    usr++;
	    char *pwd = memchr(usr, 0, tail - usr);
	    if (pwd) {
		pwd++;
		free(sasl->user);
		free(sasl->passwd);
		sasl->user = strdup(usr);
		sasl->pwlen = tail - pwd;
		memcpy((sasl->passwd = malloc(sasl->pwlen)), pwd, sasl->pwlen);
	    }
	}
    }
    free(buf);
    return NULL;
}

char *VESmail_sasl_fn_cln_login(VESmail_sasl *sasl, const char *token, int len) {
    if (!token) return NULL;
    const char *s;
    int l;
    switch (sasl->state++) {
	case 0:
	    s = sasl->user;
	    l = strlen(s);
	    break;
	case 1:
	    s = sasl->passwd;
	    l = sasl->pwlen;
	    break;
	default:
	    return NULL;
    }
    return s ? VESmail_b64encode(s, l, NULL) : strdup("=");
}

char *VESmail_sasl_fn_srv_login(VESmail_sasl *sasl, const char *token, int len) {
    char **ptr;
    const char *rsp;
    int *lptr;
    switch (sasl->state++) {
	case 0:
	    ptr = NULL;
	    rsp = "VXNlcm5hbWU6";	// Username:
	    break;
	case 1:
	    ptr = &sasl->user;
	    lptr = NULL;
	    rsp = "UGFzc3dvcmQ6";	// Password:
	    break;
	case 2:
	    ptr = &sasl->passwd;
	    lptr = &sasl->pwlen;
	    rsp = NULL;
	    break;
	default:
	    return NULL;
    }
    if (ptr) {
	free(*ptr);
	*ptr = lptr ? NULL : malloc(VESmail_b64decsize(len) + 1);
	const char *er = NULL;
	int l = VESmail_b64decode(ptr, token, &len, &er);
	if (er || l < 0) {
	    free(*ptr);
	    return *ptr = NULL;
	}
	if (lptr) *lptr = l;
	else (*ptr)[l] = 0;
    }
    return rsp ? strdup(rsp) : NULL;
}

VESmail_sasl *VESmail_sasl_new_client(int mech) {
    switch (mech) {
	case VESMAIL_SASL_M_PLAIN:
	    return VESmail_sasl_init(malloc(sizeof(VESmail_sasl)), VESMAIL_SASL_M_PLAIN, &VESmail_sasl_fn_cln_plain);
	case VESMAIL_SASL_M_LOGIN:
	    return VESmail_sasl_init(malloc(sizeof(VESmail_sasl)), VESMAIL_SASL_M_LOGIN, &VESmail_sasl_fn_cln_login);
	default:
	    return NULL;
    }
}

VESmail_sasl *VESmail_sasl_new_server(int mech) {
    switch (mech) {
	case VESMAIL_SASL_M_PLAIN:
	    return VESmail_sasl_init(malloc(sizeof(VESmail_sasl)), VESMAIL_SASL_M_PLAIN, &VESmail_sasl_fn_srv_plain);
	case VESMAIL_SASL_M_LOGIN:
	    return VESmail_sasl_init(malloc(sizeof(VESmail_sasl)), VESMAIL_SASL_M_LOGIN, &VESmail_sasl_fn_srv_login);
	default:
	    return NULL;
    }
}

void VESmail_sasl_set_user(struct VESmail_sasl *sasl, const char *user, int len) {
    free(sasl->user);
    if (user) {
	memcpy((sasl->user = malloc(len + 1)), user, len);
	sasl->user[len] = 0;
    } else {
	sasl->user = NULL;
    }
}

void VESmail_sasl_set_passwd(struct VESmail_sasl *sasl, const char *passwd, int len) {
    free(sasl->passwd);
    if (passwd) {
	memcpy((sasl->passwd = malloc(len)), passwd, (sasl->pwlen = len));
    } else {
	sasl->passwd = NULL;
	sasl->pwlen = 0;
    }
}


char *VESmail_sasl_process(VESmail_sasl *sasl, const char *token, int len) {
    if (len < 0 && token) len = strlen(token);
    return sasl->tokenfn(sasl, token, len);
}

void VESmail_sasl_free(VESmail_sasl *sasl) {
    if (sasl) {
	if (sasl->freefn) sasl->freefn(sasl);
	free(sasl->user);
	free(sasl->passwd);
    }
    free(sasl);
}
