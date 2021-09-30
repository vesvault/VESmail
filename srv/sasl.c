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
#include <stdio.h>
#include "../VESmail.h"

#ifdef HAVE_CURL_CURL_H
#include <curl/curl.h>
#include <jVar.h>
#include "tls.h"
#ifdef VESMAIL_X509STORE
#include "x509store.h"
#endif
#ifdef VESMAIL_CURLSH
#include "curlsh.h"
#endif
#endif

#include "../lib/util.h"
#include "arch.h"
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
    VESmail_cleanse(saslt, l);
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
    VESmail_cleanse(buf, l);
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

#ifdef HAVE_CURL_CURL_H
size_t VESmail_sasl_xoauth2_curlfn(void *ptr, size_t size, size_t nmemb, void *stream) {
    int len = size * nmemb;
#ifdef VESMAIL_DEBUG_OAUTH2
    printf("<<<< %.*s\n", len, ptr);
#endif
    jVarParser **parser = stream;
    if (!*parser) *parser = jVarParser_new(NULL);
    *parser = jVarParser_parse(*parser, ptr, len);
    return len;
}
#endif

char *VESmail_sasl_xoauth2_mktoken(VESmail_sasl *sasl) {
#ifdef HAVE_CURL_CURL_H
    if (sasl->pwlen > 8 && !strncmp(sasl->passwd, "https://", 8)) {
	char *post = memchr(sasl->passwd, '#', sasl->pwlen);
	if (!post) return NULL;
	*post++ = 0;
	CURL *curl = curl_easy_init();
#ifdef VESMAIL_DEBUG_OAUTH2
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
#endif
	VESmail_tls_setcurlctx(curl);
	curl_easy_setopt(curl, CURLOPT_URL, sasl->passwd);
	struct curl_slist *hdrs = curl_slist_append(NULL, "Accept: application/json");
	char buf[1024];
	sprintf(buf, "User-Agent: VESmail SASL (https://vesmail.email) %s (%s)", VESMAIL_VERSION, curl_version());
	hdrs = curl_slist_append(hdrs, buf);
	int postl = sasl->pwlen - (post - sasl->passwd);
	if (postl > 0) {
	    hdrs = curl_slist_append(hdrs, (*post == '{' ? "Content-Type: application/json" : "Content-Type: application/x-www-form-urlencoded"));
	    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
	    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, postl);
	}
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
	jVarParser *parser = NULL;
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &VESmail_sasl_xoauth2_curlfn);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &parser);
	int curlerr = curl_easy_perform(curl);
	long code = 0;
	if (curlerr == CURLE_OK) curlerr = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
	curl_slist_free_all(hdrs);
	curl_easy_reset(curl);
	jVar *rsp;
	if (parser) {
	    int cpl = jVarParser_isComplete(parser);
	    rsp = jVarParser_done(parser);
	    if (!cpl) {
		jVar_free(rsp);
		rsp = NULL;
	    }
	} else {
	    rsp = NULL;
	}
	free(sasl->passwd);
	sasl->passwd = (code == 200) ? jVar_getString0(jVar_get(rsp, "access_token")) : NULL;
	sasl->pwlen = sasl->passwd ? strlen(sasl->passwd) : 0;
	if (code != 200 || sasl->pwlen <= 0) {
	    const char *e = jVar_getString0(jVar_get(rsp, "error"));
	    VESmail_arch_log("sasl mech=%s curl=%ld pwlen=%d error=%s", VESmail_sasl_get_name(sasl), code, sasl->pwlen, (e ? e : ""));
	}
	jVar_free(rsp);
	curl_easy_cleanup(curl);
    }
#else
#pragma message ("Building without SASL XOAUTH2 refresh token support - need curl/curl.h")
#endif
    return sasl->passwd;
}

char *VESmail_sasl_fn_cln_xoauth2(VESmail_sasl *sasl, const char *token, int len) {
    if (!sasl->user) return NULL;
    if (sasl->state > 0) {
	if (sasl->state > 1) return NULL;
	if (token) {
	    char *buf = NULL;
	    const char *er = NULL;
	    int l = VESmail_b64decode(&buf, token, &len, &er);
	    if (l >= 0) VESmail_arch_log("sasl mech=%s rsp=%.*s", VESmail_sasl_get_name(sasl), l, buf);
	    free(buf);
	}
	sasl->state++;
	return strdup("");
    }
    if (!VESmail_sasl_xoauth2_mktoken(sasl)) return NULL;
    sasl->state = 1;
    char *saslt = malloc(strlen(sasl->user) + sasl->pwlen + 24);
    sprintf(saslt, "user=%s" "\x01" "auth=Bearer %.*s" "\x01" "\x01", sasl->user, sasl->pwlen, sasl->passwd);
    char *b64 = VESmail_b64encode(saslt, strlen(saslt), NULL);
    VESmail_cleanse(saslt, strlen(saslt));
    free(saslt);
    return b64;
}

VESmail_sasl *VESmail_sasl_new_client(int mech) {
    switch (mech) {
	case VESMAIL_SASL_M_PLAIN:
	    return VESmail_sasl_init(malloc(sizeof(VESmail_sasl)), VESMAIL_SASL_M_PLAIN, &VESmail_sasl_fn_cln_plain);
	case VESMAIL_SASL_M_LOGIN:
	    return VESmail_sasl_init(malloc(sizeof(VESmail_sasl)), VESMAIL_SASL_M_LOGIN, &VESmail_sasl_fn_cln_login);
	case VESMAIL_SASL_M_XOAUTH2:
	    return VESmail_sasl_init(malloc(sizeof(VESmail_sasl)), VESMAIL_SASL_M_XOAUTH2, &VESmail_sasl_fn_cln_xoauth2);
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
	if (sasl->user) VESmail_cleanse(sasl->user, strlen(sasl->user));
	free(sasl->user);
	VESmail_cleanse(sasl->passwd, sasl->pwlen);
	free(sasl->passwd);
    }
    free(sasl);
}
