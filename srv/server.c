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
#endif

#include <time.h>

#include <openssl/bio.h>

#include <libVES.h>
#include <libVES/VaultItem.h>
#include <libVES/Cipher.h>
#include <libVES/Ref.h>
#include <jVar.h>
#include "../VESmail.h"
#include "../lib/util.h"
#include "../lib/xform.h"
#include "tls.h"
#include "sasl.h"
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
    srv->idlefn = NULL;
    srv->host = "localhost";
    srv->flags = 0;
    srv->debug = 0;
    srv->dumpfd = -1;
    srv->lastwrite = time(NULL);
    srv->reqbytes = srv->rspbytes = 0;
    srv->tmout.unauthd = 30;
    srv->tmout.authd = 900;
    srv->tmout.data = 900;
    return srv;
}

#define VESmail_server_dump(fd, src, len)	if ((fd) >= 0) VESmail_arch_write(fd, src, len)

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
	VESmail_server_dump(xform->server->dumpfd, src, w);
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
    } else {
	VESmail_server_dump(chain->server->dumpfd, buf, rd);
    }
    return VESmail_xform_process(chain, !rd, buf, rd);
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
	}
	int pl = VESmail_arch_poll(2, BIO_get_fd(srv->req_bio, NULL), BIO_get_fd(srv->rsp_bio, NULL));
	VESMAIL_SRV_DEBUG(srv, 2, sprintf(debug, "[poll] %d", pl))
	rs = VESmail_server_bio_read(srv->req_bio, srv->req_in, pl >= 0 || (!(flags & VESMAIL_SRVR_NORSP) && (srv->flags & VESMAIL_SRVF_OVER)));
	if (rs < 0) break;
	srv->reqbytes += rs;
	rs = VESmail_server_bio_read(srv->rsp_bio, srv->rsp_in, pl >= 0 || (!(flags & VESMAIL_SRVR_NOREQ) && !(srv->flags & VESMAIL_SRVF_OVER)));
	if (rs < 0) break;
	srv->rspbytes += rs;
	if (srv->idlefn) {
	    rs = srv->idlefn(srv, time(NULL) - srv->lastwrite);
	    if (rs < 0) break;
	    if (srv->flags & (VESMAIL_SRVF_TMOUT | VESMAIL_SRVF_KILL)) {
		VESmail_server_log(srv, (srv->flags & VESMAIL_SRVF_TMOUT ? "timeout" : "shutdown"));
		rs = VESmail_xform_process(srv->req_in, 1, "", 0);
		if (rs < 0) break;
		rs = VESmail_xform_process(srv->req_out, 1, "", 0);
		if (rs < 0) break;
	    }
	}
    }
    if (rs > 0) rs = 0;
    VESmail_server_bytes(srv, 1, rs);
    return rs;
}

void VESmail_server_logauth(VESmail_server *srv, const char *user, const char *st) {
    char *host = VESmail_server_sockname(srv, 0);
    char *peer = VESmail_server_sockname(srv, 1);
    VESmail_server_log(srv, "auth %s(%d) srv=%s peer=%s user=%s", st, (srv->ves ? srv->ves->error : 0), host, peer, user);
    free(peer);
    free(host);
}

int VESmail_server_auth(VESmail_server *srv, const char *user, const char *pwd, int pwlen) {
    if (!VESmail_tls_server_allow_plain(srv)) {
	VESmail_server_logauth(srv, "(TLS required)", "DENIED");
	VESmail_arch_usleep(2000000);
	return VESMAIL_E_SRV_STARTTLS;
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
	    if (!vi && libVES_checkError(srv->ves, LIBVES_E_NOTFOUND)) return VESMAIL_E_PARAM;
	    int ok = vi && vi->value;
	    libVES_VaultItem_free(vi);
	    if (!ok) {
		VESmail_server_logauth(srv, user, (vi ? "DENIED" : "ERROR"));
		VESmail_arch_usleep(2000000);
		return vi ? VESMAIL_E_DENIED : VESMAIL_E_VES;
	    }
	}
	VESmail_server_logauth(srv, user, "OK");
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
	libVES_Cipher_free(ci);
	libVES_VaultItem_free(vi);
	libVES_Ref_free(ref);
	return srv->uconf ? 0 : VESMAIL_E_CONF;
    } else {
	VESmail_server_logauth(srv, user, "FAIL");
	VESmail_arch_usleep(2000000);
	return ((
	    libVES_checkError(srv->ves, LIBVES_E_NOTFOUND) || libVES_checkError(srv->ves, LIBVES_E_CRYPTO)
	) ? VESMAIL_E_AUTH : VESMAIL_E_VES);
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
	.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG,
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
    switch (err) {
	case VESMAIL_E_OK:
	    return strdup("OK");
	case VESMAIL_E_IO: {
	    char *rs = malloc(256);
	    sprintf(rs, "I/O error (%d) %.160s", errno, strerror(errno));
	    return rs;
	}
	case VESMAIL_E_VES: {
	    if (srv->ves) {
		const char *str;
		const char *msg;
		libVES_getErrorInfo(srv->ves, &str, &msg);
		if (str) {
		    if (!msg) msg = "";
		    char *rs = malloc(strlen(str) + strlen(msg) + 64);
		    sprintf(rs, "libVES: %s: %s", str, msg);
		    return rs;
		}
	    }
	    return strdup("libVES: [unspecified error]");
	}
	case VESMAIL_E_TLS:
	    return strdup("TLS error");
	case VESMAIL_E_AUTH:
	    return strdup("Invalid VESmail credentials");
	case VESMAIL_E_CONF:
	    return strdup("Invalid or missing VESmail profile object");
	case VESMAIL_E_DENIED:
	    return strdup("Access denied");
	case VESMAIL_E_PARAM:
	    return strdup("Invalid parameters or VESmail configuration error");
	case VESMAIL_E_SRV_STARTTLS:
	    return strdup("Denied, STARTTLS first");
	default: {
	    char *rs = malloc(80);
	    sprintf(rs, "Internal error (%d)", err);
	    return rs;
	}
    }
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

void VESmail_server_free(VESmail_server *srv) {
    if (srv) {
	if (srv->freefn) srv->freefn(srv);
	VESmail_server_disconnect(srv);
	VESmail_tls_server_done(srv);
	BIO_free_all(srv->req_bio);
	VESmail_xform_free(srv->req_in);
	VESmail_xform_free(srv->req_out);
	VESmail_xform_free(srv->rsp_in);
	VESmail_xform_free(srv->rsp_out);
	jVar_free(srv->uconf);
	VESmail_sasl_free(srv->sasl);
    }
    free(srv);
}
