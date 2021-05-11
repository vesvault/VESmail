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
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip.h>
#endif

#include <time.h>

#include <openssl/bio.h>

#include <libVES.h>
#include <libVES/VaultItem.h>
#include <libVES/Cipher.h>
#include <libVES/Ref.h>
#include <libVES/User.h>
#include <jVar.h>
#include "../VESmail.h"
#include "../lib/util.h"
#include "../lib/xform.h"
#include "tls.h"
#include "sasl.h"
#include "override.h"
#include "../lib/optns.h"
#include "arch.h"
#include "server.h"

VESmail_server *VESmail_server_init(VESmail_server *srv, VESmail_optns *optns) {
    srv->req_in = NULL;
    srv->req_out = NULL;
    srv->rsp_in = NULL;
    srv->rsp_out = NULL;
    srv->req_bio = srv->rsp_bio = NULL;
    srv->debugfn = NULL;
    srv->freefn = NULL;
    srv->ves = NULL;
    srv->optns = optns ? optns : &VESmail_optns_default;
    srv->uconf = NULL;
    srv->tls.client = NULL;
    srv->tls.server = NULL;
    srv->sasl = NULL;
    srv->override = NULL;
    srv->idlefn = NULL;
    srv->host = "localhost";
    srv->login = NULL;
    srv->logfn = NULL;
    srv->abusefn = NULL;
    srv->flags = 0;
    srv->debug = 0;
    srv->dumpfd = -1;
    srv->subcode = 0;
    srv->authcode = VESMAIL_E_HOLD;
    srv->stat = 0;
    srv->lastwrite = time(NULL);
    srv->reqbytes = srv->rspbytes = 0;
    srv->tmout.unauthd = 30;
    srv->tmout.authd = 900;
    srv->tmout.data = 900;
    return srv;
}

#ifndef VESMAIL_DEBUG_DUMP
#define VESMAIL_DEBUG_DUMP	0
#endif
#if VESMAIL_DEBUG_DUMP
#define VESmail_server_dump(fd, src, len)	if ((fd) >= 0) VESmail_arch_write(fd, src, len)
#endif

#define	VESMAIL_SRV_OUTBUF	4096

int VESmail_server_fn_bio_out(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) {
	if (*srclen > VESMAIL_SRV_OUTBUF) *srclen = VESMAIL_SRV_OUTBUF;
	return 0;
    }
    int srcl = *srclen;
    *srclen = 0;
    const char *tail;
    if (!final) for (tail = src + srcl - 1; ; tail--) {
	if (tail < src) {
	    if (srcl >= VESMAIL_SRV_OUTBUF) break;
	    return 0;
	}
	if (*tail == '\n') {
	    srcl = tail - src + 1;
	    break;
	}
    }
    while (1) {
	VESmail_arch_set_nb(BIO_get_fd(xform->bio, NULL), 0);
	int w = BIO_write(xform->bio, src, srcl);
	if (w < 0) {
	    if (BIO_should_write(xform->bio)) {
		w = 0;
	    } else {
		return VESMAIL_E_IO;
	    }
	}
	xform->server->lastwrite = time(NULL);
#if VESMAIL_DEBUG_DUMP
	VESmail_server_dump(xform->server->dumpfd, src, w);
#endif
	if (!final) return *srclen = w;
	*srclen += w;
	srcl -= w;
	if (srcl <= 0) break;
	src += w;
    }
    return *srclen;
}

void VESmail_server_fn_free_bio(VESmail_xform *xform) {
    BIO_free_all(xform->bio);
}

VESmail_xform *VESmail_server_xform_new_bio_out(VESmail_server *srv, BIO *bio) {
    VESmail_xform *xform = VESmail_xform_new(&VESmail_server_fn_bio_out, NULL, srv);
    xform->bio = bio;
    xform->freefn = &VESmail_server_fn_free_bio;
    return xform;
}

int VESmail_server_bio_read(BIO *bio, VESmail_xform *chain, int nb) {
    if (!bio) return 0;
    if (VESmail_arch_set_nb(BIO_get_fd(bio, NULL), nb) < 0 && nb) return 0;
    char buf[4096];
    int rd = BIO_read(bio, &buf, sizeof(buf));
    if (rd < 0) {
	if (BIO_should_read(bio)) {
	    return VESmail_xform_process(chain, 0, buf, 0);
	} else {
	    return VESMAIL_E_IO;
	}
#if VESMAIL_DEBUG_DUMP
    } else {
	VESmail_server_dump(chain->server->dumpfd, buf, rd);
#endif
    }
    int r = VESmail_xform_process(chain, !rd, buf, rd);
    VESmail_cleanse(buf, rd);
    return r;
}


int VESmail_server_set_fd(VESmail_server *srv, int in, int out) {
    if (srv->rsp_out || !srv->req_in) return VESMAIL_E_PARAM;
    VESmail_xform_free(srv->rsp_out);
    srv->rsp_out = VESmail_server_xform_new_bio_out(srv, BIO_new_fd(out, BIO_NOCLOSE));
    BIO_free(srv->req_bio);
    srv->req_bio = BIO_new_fd(in, BIO_NOCLOSE);
    return VESmail_tls_server_start(srv, 0);
}

int VESmail_server_set_sock(VESmail_server *srv, int sock) {
    if (srv->rsp_out || !srv->req_in) return VESMAIL_E_PARAM;
    VESmail_xform_free(srv->rsp_out);
    srv->rsp_out = VESmail_server_xform_new_bio_out(srv, BIO_new_socket(sock, BIO_CLOSE));
    BIO_free(srv->req_bio);
    srv->req_bio = BIO_new_socket(sock, BIO_NOCLOSE);
    return VESmail_tls_server_start(srv, 0);
}

void *VESmail_server_fn_th_rsp(void *srv) {
    VESmail_server_run((VESmail_server *) srv, VESMAIL_SRVR_NOTHR | VESMAIL_SRVR_NOREQ);
    return NULL;
}

void VESmail_server_bytes(VESmail_server *srv, int done, int st) {
    long long int req = srv->reqbytes;
    long long int rsp = srv->rspbytes;
    VESmail_server_log(srv, "bytes proto=%s exit=%d st=%d req=%llu rsp=%llu", srv->type, done, st, req, rsp);
    srv->reqbytes -= req;
    srv->rspbytes -= rsp;
}

int VESmail_server_run(VESmail_server *srv, int flags) {
    int rs = 0;
    while (!(srv->flags & VESMAIL_SRVF_SHUTDOWN)) {
	if (!(flags & VESMAIL_SRVR_NOTHR) && (srv->flags & VESMAIL_SRVF_OVER)) {
	    flags |= VESMAIL_SRVR_NOTHR;
	    if (VESmail_arch_thread(srv, &VESmail_server_fn_th_rsp, NULL) >= 0) flags |= VESMAIL_SRVR_NORSP;
	}
	if (!(flags & VESMAIL_SRVR_NOREQ)) {
	    rs = VESmail_xform_process(srv->req_in, 0, "", 0);
	    if (rs < 0) break;
	    srv->reqbytes += rs;
	}
	int pl = VESmail_arch_poll(2, BIO_get_fd(srv->req_bio, NULL), BIO_get_fd(srv->rsp_bio, NULL));
	VESMAIL_SRV_DEBUG(srv, 2, sprintf(debug, "[poll] %d", pl))
	if (!(flags & VESMAIL_SRVR_NOREQ)) {
	    rs = VESmail_server_bio_read(srv->req_bio, srv->req_in, pl >= 0 || (srv->flags & VESMAIL_SRVF_OVER));
	    if (rs < 0) break;
	    srv->reqbytes += rs;
	}
	if (!(flags & VESMAIL_SRVR_NORSP)) {
	    rs = VESmail_server_bio_read(srv->rsp_bio, srv->rsp_in, pl >= 0 || !(srv->flags & VESMAIL_SRVF_OVER));
	    if (rs < 0) break;
	    srv->rspbytes += rs;
	}
	if (srv->idlefn) {
	    rs = srv->idlefn(srv, time(NULL) - srv->lastwrite);
	    if (rs < 0) break;
	    if (srv->flags & (VESMAIL_SRVF_TMOUT | VESMAIL_SRVF_KILL)) {
		if (!(flags & VESMAIL_SRVR_NOLOG)) VESmail_server_log(srv, (srv->flags & VESMAIL_SRVF_TMOUT ? "timeout" : "shutdown"));
		rs = VESmail_xform_process(srv->req_in, 1, "", 0);
		if (rs < 0) break;
		rs = VESmail_xform_process(srv->req_out, 1, "", 0);
		if (rs < 0) break;
	    }
	}
	if (flags & VESMAIL_SRVR_NOLOOP) break;
    }
    if (rs > 0) rs = 0;
    if (!(flags & VESMAIL_SRVR_NOLOG)) VESmail_server_bytes(srv, 1, rs);
    return rs;
}

int VESmail_server_logauth(VESmail_server *srv, int er, long usec) {
    srv->authcode = er;
    char *host = VESmail_server_sockname(srv, 0);
    char *peer = VESmail_server_sockname(srv, 1);
    const char *st;
    switch (er) {
	case VESMAIL_E_OK:
	    st = "OK";
	    break;
	case VESMAIL_E_DENIED:
	case VESMAIL_E_SRV_STARTTLS:
	case VESMAIL_E_ABUSE:
	    st = "DENIED";
	    break;
	default:
	    st = "FAIL";
	    break;
    }
    VESmail_server_log(srv, "auth %s(%d.%d) srv=%s peer=%s user=%s", st, er, srv->subcode, host, peer, (srv->login ? srv->login : ""));
    free(peer);
    free(host);
    if (usec) VESmail_arch_usleep(usec);
    return er;
}

int VESmail_server_auth(VESmail_server *srv, const char *user, const char *pwd, int pwlen) {
    srv->authcode = VESMAIL_E_HOLD;
    srv->subcode = 0;
    free(srv->login);
    srv->login = VESmail_strndup(user, VESMAIL_SRV_MAXLOGIN);
    if (!VESmail_tls_server_allow_plain(srv)) {
	return VESmail_server_logauth(srv, VESMAIL_E_SRV_STARTTLS, 2000000);
    }
    const char *ext = strchr(user, '#');
    const char *tail = ext ? ext : user + strlen(user);
    const char *exc = memchr(user, '!', tail - user);
    if (exc) tail = exc;
    libVES_free(srv->ves);
    if (memchr(user, '/', tail - user)) {
	srv->ves = libVES_new(user);
    } else {
	libVES_Ref *ref = libVES_External_new(srv->optns->vesDomain, user);
	ref->externalId[tail - user] = 0;
	srv->ves = libVES_fromRef(ref);
    }
    VESmail_tls_initVES(srv->ves);
    if (srv->debug > VESMAIL_DEBUG_LIBVES) srv->ves->debug = srv->debug - VESMAIL_DEBUG_LIBVES;
    if (libVES_unlock(srv->ves, pwlen, pwd)) {
	if (srv->optns->acl) {
	    const char *uri = srv->optns->acl;
	    libVES_VaultItem *vi = libVES_VaultItem_loadFromURI(&uri, srv->ves);
	    int ok = vi && vi->value;
	    libVES_VaultItem_free(vi);
	    if (!vi) {
		srv->subcode = srv->ves->error;
		return VESmail_server_logauth(srv, VESMAIL_E_VES, 1000000);
	    } else if (!ok) {
		return VESmail_server_logauth(srv, VESMAIL_E_DENIED, 2000000);
	    }
	}
	if (VESmail_server_abuse_user(srv, 0) < 0) {
	    return VESmail_server_logauth(srv, VESMAIL_E_ABUSE, 2000000);
	}
	const char *rf;
	char *userx = NULL;
	if (ext) {
	    rf = ext[1] == '#' ? ext + 2 : user;
	} else if (exc) {
	    rf = user;
	} else {
	    int l = tail - user;
	    userx = malloc(l + 2);
	    memcpy(userx, user, l);
	    userx[l] = '!';
	    userx[l + 1] = 0;
	    rf = userx;
	}
	libVES_Ref *ref = libVES_External_new(srv->optns->vesDomain, rf);
	free(userx);
	libVES_VaultItem *vi = libVES_VaultItem_get(ref, srv->ves);
	libVES_Cipher *ci = libVES_VaultItem_getCipher(vi, srv->ves);
	jVar_free(srv->uconf);
	srv->uconf = jVar_detach(libVES_Cipher_getMeta(ci));
	int rs = 0;
	const char *ovrd = jVar_getStringP(jVar_get(jVar_get(srv->uconf, srv->type), "override"));
	if (ovrd) {
	    if (!srv->override) srv->override = srv->ovrdfn(srv->ovrdref);
	    if (srv->override) {
		rs = VESmail_override_load(srv->override, ovrd, vi, srv->ves);
		if (rs >= 0) rs = VESmail_override_apply(srv->override, &srv->optns);
	    }
	}
	libVES_Cipher_free(ci);
	libVES_VaultItem_free(vi);
	libVES_Ref_free(ref);
	return srv->uconf ? rs : VESmail_server_logauth(srv, VESMAIL_E_CONF, 500000);
    } else {
	int er;
	switch ((srv->subcode = srv->ves->error)) {
	    case LIBVES_E_NOTFOUND:
	    case LIBVES_E_CRYPTO:
		er = VESMAIL_E_VES;
		break;
	    default:
		er = VESMAIL_E_AUTH;
		break;
	}
	return VESmail_server_logauth(srv, er, 2000000);
    }
}

VESmail_sasl *VESmail_server_sasl_client(int mech, jVar *uconf) {
    VESmail_sasl *sasl = VESmail_sasl_new_client(mech);
    if (sasl) {
	jVar *u = jVar_get(uconf, "login");
	VESmail_sasl_set_user(sasl, (u ? u->vString : ""), (u ? u->len : 0));
	jVar *p = jVar_get(uconf, "password");
	VESmail_sasl_set_passwd(sasl, (p ? p->vString : ""), (p ? p->len : 0));
    }
    return sasl;
}

int VESmail_server_connect(VESmail_server *srv, jVar *conf, const char *dport) {
    if (!conf) return VESMAIL_E_CONF;
    char *host = jVar_getString(jVar_get(conf, "host"));
    char *port = jVar_getString(jVar_get(conf, "port"));
    struct addrinfo hint = {
	.ai_family = AF_UNSPEC,
	.ai_socktype = SOCK_STREAM,
	.ai_protocol = 0,
	.ai_flags = AI_ADDRCONFIG,
	.ai_addrlen = 0,
	.ai_addr = NULL,
	.ai_canonname = NULL,
	.ai_next = NULL
    };
    struct addrinfo *res = NULL;
    int rs = 0;
    if (!getaddrinfo(host, (port ? port : dport), &hint, &res)) {
	struct addrinfo *r;
	rs = VESMAIL_E_CONN;
	for (r = res; r; r = r->ai_next) {
	    int fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
	    if (fd < 0) continue;
	    VESMAIL_SRV_DEBUG(srv, 1, {
		char abuf[64];
		char pbuf[16];
		getnameinfo(r->ai_addr, r->ai_addrlen, abuf, sizeof(abuf), pbuf, sizeof(pbuf), NI_NUMERICHOST | NI_NUMERICSERV);
		sprintf(debug, "Connecting to [%s]:%s ...", abuf, pbuf);
	    })
	    int connr;
	    if ((connr = connect(fd, r->ai_addr, r->ai_addrlen)) < 0) {
		VESMAIL_SRV_DEBUG(srv, 1, sprintf(debug, "... failed (%d)", connr));
		shutdown(fd, 2);
		continue;
	    }
	    VESMAIL_SRV_DEBUG(srv, 1, sprintf(debug, "... connected"))
	    VESmail_xform_free(srv->req_out);
	    srv->req_out = VESmail_server_xform_new_bio_out(srv, BIO_new_socket(fd, BIO_CLOSE));
	    srv->rsp_bio = BIO_new_socket(fd, BIO_NOCLOSE);
	    srv->tls.client = VESmail_tls_client_new(jVar_get(conf, "tls"), host);
	    VESmail_sasl_free(srv->sasl);
	    srv->sasl = VESmail_server_sasl_client(jVar_getEnum(jVar_get(conf, "sasl"), VESmail_sasl_mechs), conf);
	    host = NULL;
	    rs = VESmail_tls_client_start(srv, 0);
	    break;
	}
	freeaddrinfo(res);
    } else {
	rs = VESMAIL_E_RESOLV;
    }
    free(port);
    free(host);
    if (rs < 0) VESmail_server_disconnect(srv);
    return rs;
}

int VESmail_server_disconnect(VESmail_server *srv) {
    VESmail_tls_client_done(srv);
    BIO_free_all(srv->rsp_bio);
    srv->rsp_bio = NULL;
    VESmail_xform_free(srv->req_out);
    srv->req_out = NULL;
    srv->flags &= ~VESMAIL_SRVF_TLSC;
    libVES_free(srv->ves);
    srv->ves = NULL;
    return 0;
}

char *VESmail_server_errorStr(VESmail_server *srv, int err) {
    char *rs = malloc(256);
    sprintf(rs, "XVES%d", err);
    char *d = rs + strlen(rs);
    srv->subcode = 0;
    switch (err) {
	case VESMAIL_E_OK:
	    strcpy(d, " OK");
	    break;
	case VESMAIL_E_IO: {
	    sprintf(d, ".%d I/O error: %.160s", (srv->subcode = errno), strerror(errno));
	    break;
	}
	case VESMAIL_E_VES: {
	    if (srv->ves) {
		const char *str;
		const char *msg;
		int veserr = srv->subcode = libVES_getErrorInfo(srv->ves, &str, &msg);
		if (str) {
		    if (!msg) msg = "";
		    sprintf(d, ".%d libVES: %.40s: %.192s", veserr, str, msg);
		    break;
		}
	    }
	    strcpy(d, " libVES: [unspecified error]");
	    break;
	}
	case VESMAIL_E_TLS:
	    strcpy(d, " TLS error");
	    break;
	case VESMAIL_E_AUTH:
	    strcpy(d, " Invalid VESmail credentials");
	    break;
	case VESMAIL_E_CONF:
	    strcpy(d, " Invalid or missing VESmail profile object");
	    break;
	case VESMAIL_E_DENIED:
	    strcpy(d, " Access denied");
	    break;
	case VESMAIL_E_RESOLV:
	    strcpy(d, " DNS error, check the hostname in the VESmail profile");
	    break;
	case VESMAIL_E_CONN:
	    strcpy(d, " Connection error, check host & port in the VESmail profile");
	    break;
	case VESMAIL_E_SASL:
	    strcpy(d, " Incorrect SASL authentication sequence");
	    break;
	case VESMAIL_E_RELAY:
	    strcpy(d, " Unexpected response from the remote server");
	    break;
	case VESMAIL_E_ABUSE:
	    strcpy(d, " Abuse detected, try later");
	    break;
	case VESMAIL_E_OVRD:
	    if (srv->override) {
		srv->subcode = VESmail_override_geterror(srv->override, srv->ves, d + 16);
		sprintf(d, ".%d Override:", srv->subcode);
		memmove(d + strlen(d), d + 16, strlen(d + 16) + 1);
	    }
	    break;
	case VESMAIL_E_PARAM:
	    strcpy(d, " Invalid parameters or VESmail configuration error");
	    break;
	case VESMAIL_E_SRV_STARTTLS:
	    strcpy(d, " Denied, STARTTLS first");
	    break;
	default:
	    strcpy(d, " Internal error");
	    break;
    }
    return rs;
}

char *VESmail_server_sockname(VESmail_server *srv, int peer) {
    char *name;
    struct sockaddr sa;
    socklen_t l = sizeof(sa);
    int sk = BIO_get_fd(srv->req_bio, NULL);
    if (sk >= 0 && (peer ? getpeername(sk, &sa, &l) : getsockname(sk, &sa, &l)) >= 0) {
	char abuf[64];
	char pbuf[16];
	if (getnameinfo(&sa, l, abuf, sizeof(abuf), pbuf, sizeof(pbuf), NI_NUMERICHOST | NI_NUMERICSERV) >= 0) {
	    name = malloc(strlen(abuf) + strlen(pbuf) + 16);
	    sprintf(name, "[%s]:%s", abuf, pbuf);
	    return name;
	}
    }
    name = malloc(32);
    sprintf(name, "(fd=%d,uid=%d)", sk, VESmail_arch_getuid());
    return name;
}

char *VESmail_server_timestamp() {
    char tstamp[64];
    time_t t = time(NULL);
    strftime(tstamp, sizeof(tstamp), "%a, %d %b %Y %T %z", localtime(&t));
    return strdup(tstamp);
}

int VESmail_server_abuse_peer(VESmail_server *srv, int val) {
    if (!srv->abusefn) return 0;
    struct sockaddr sa;
    socklen_t l = sizeof(sa);
    if (getpeername(BIO_get_fd(srv->req_bio, NULL), &sa, &l) < 0) return 0;
    switch (sa.sa_family) {
	case AF_INET:
	    return srv->abusefn(srv->abuseref, &((struct sockaddr_in *) &sa)->sin_addr, sizeof(((struct sockaddr_in *) &sa)->sin_addr), val);
	case AF_INET6:
	    return srv->abusefn(srv->abuseref, &((struct sockaddr_in6 *) &sa)->sin6_addr, sizeof(((struct sockaddr_in6 *) &sa)->sin6_addr), val);
	default:
	    return 0;
    }
}

int VESmail_server_abuse_user(VESmail_server *srv, int val) {
    if (!srv->abusefn || !srv->ves) return 0;
    libVES_User *me = libVES_me(srv->ves);
    return me ? srv->abusefn(srv->abuseref, &me->id, sizeof(me->id), val) : 0;
}

void VESmail_server_shutdown(VESmail_server *srv) {
    if (!srv || (srv->flags & VESMAIL_SRVF_DONE)) return;
    VESmail_server_disconnect(srv);
    if (srv->freefn) srv->freefn(srv);
    VESmail_tls_server_done(srv);
    BIO_free_all(srv->req_bio);
    srv->req_bio = NULL;
    VESmail_xform_free(srv->req_in);
    VESmail_xform_free(srv->req_out);
    VESmail_xform_free(srv->rsp_in);
    VESmail_xform_free(srv->rsp_out);
    srv->req_in = srv->req_out = srv->rsp_in = srv->rsp_out = NULL;
    VESmail_sasl_free(srv->sasl);
    srv->sasl = NULL;
    srv->flags |= VESMAIL_SRVF_DONE;
}

void VESmail_server_free(VESmail_server *srv) {
    if (srv) {
	VESmail_server_shutdown(srv);
	libVES_cleanseJVar(srv->uconf);
	jVar_free(srv->uconf);
	VESmail_override_free(srv->override);
	free(srv->login);
    }
    free(srv);
}
