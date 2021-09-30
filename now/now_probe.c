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
#include <jVar.h>
#include <libVES.h>
#include <libVES/User.h>
#include <libVES/Ref.h>
#include <libVES/VaultItem.h>
#include <time.h>
#include "../VESmail.h"
#include "../srv/server.h"
#include "../srv/tls.h"
#include "../lib/xform.h"
#include "../lib/optns.h"
#include "../imap/imap.h"
#include "../imap/imap_start.h"
#include "../smtp/smtp.h"
#include "../smtp/smtp_start.h"
#include "now.h"
#include "now_probe.h"


#define	VESMAIL_NOW_ABUSE_ADJUST	-3600

int VESmail_now_probe(VESmail_server *srv, jVar *uconf, const char *token) {
    if (!VESmail_tls_server_allow_plain(srv)) return VESmail_now_error(srv, 426, "TLS required\r\n");
    int abuse = VESmail_server_abuse_peer(srv, 0);
    if (abuse < VESMAIL_NOW_ABUSE_ADJUST) {
	VESmail_now_log(srv, "POST", 503, NULL);
	return VESmail_now_error(srv, 503, "Too many attempts from the IP address, try later");
    }
    if (!token) {
	VESmail_now_log(srv, "POST", 401, NULL);
	return VESmail_now_error(srv, 401, "VES token required");
    }
    libVES_free(srv->ves);
    srv->ves = libVES_new(NULL);
    VESmail_tls_initVES(srv->ves);
    libVES_setSessionToken(srv->ves, token);
    libVES_User *me = libVES_me(srv->ves);
    if (me && srv->optns->acl) {
	libVES_Ref *ref = libVES_External_new(srv->optns->vesDomain, srv->optns->acl);
	libVES_VaultItem *vi = libVES_VaultItem_get(ref, srv->ves);
	int l = vi ? vi->sharelen : 0;
	libVES_VaultItem_free(vi);
	libVES_Ref_free(ref);
	if (vi) {
	    if (l <= 0) {
		VESmail_now_log(srv, "POST", 403, "user", libVES_User_getEmail(me), NULL);
		return VESmail_now_error(srv, 403, "Not on the ACL");
	    }
	} else {
	    me = NULL;
	}
    }
    if (!me) {
	char *err = VESmail_server_errorStr(srv, VESMAIL_E_VES);
	VESmail_now_log(srv, "POST", 502, NULL);
	int r = VESmail_now_error(srv, 502, err);
	free(err);
	return r;
    }
    int abuse_u = VESmail_server_abuse_user(srv, 0);
    if (abuse_u < VESMAIL_NOW_ABUSE_ADJUST) {
	VESmail_now_log(srv, "POST", 503, "user", libVES_User_getEmail(me), NULL);
	return VESmail_now_error(srv, 503, "Too many attempts from the VES user, try later");
    } else if (abuse_u < abuse) {
	abuse = abuse_u;
    }
    VESmail_server *usrv = NULL;
    int (* probefn)(VESmail_server *, jVar *);
    jVar *ucf;
    if (jVar_isObject(uconf)) {
	int i;
	for (i = 0; i < uconf->len; i++) {
	    const char *type = jVar_getStringP(uconf->vObject[i].key);
	    if (!type) continue;
	    ucf = uconf->vObject[i].val;
	    if (!strcmp(type, "imap")) {
		usrv = VESmail_server_new_imap(srv->optns);
		probefn = &VESmail_imap_start_probe;
		break;
	    } else if (!strcmp(type, "smtp")) {
		usrv = VESmail_server_new_smtp(srv->optns);
		probefn = &VESmail_smtp_start_probe;
		break;
	    }
	}
    }
    if (!usrv) {
	VESmail_now_log(srv, "POST", 400, "probe", "", NULL);
	return VESmail_now_error(srv, 400, "Unknown service to probe, expected imap | smtp\r\n");
    }
    usrv->rsp_out = srv->rsp_out;
    usrv->debug = 1;
    usrv->dumpfd = srv->dumpfd;
    usrv->abusefn = srv->abusefn;
    usrv->abuseref = srv->abuseref;
    usrv->ves = srv->ves;
    srv->ves = NULL;
    VESmail_now_log(srv, "POST", 200, "probe", usrv->type, "user", libVES_User_getEmail(me), NULL);
    int rs = VESmail_now_send_status(srv, 200);
    int r;
    if (rs >= 0) {
	char buf[64];
	sprintf(buf, "X-VESmail-Abuse: %d\r\n", abuse);
	r = VESmail_now_send(srv, 0, buf);
	if (r >= 0) rs += r;
	else rs = r;
    }
    if (rs >= 0) {
	r = VESmail_now_send(srv, 0, "Content-Type: text/plain\r\n");
	if (r >= 0) rs += r;
	else rs = r;
    }
    if (rs >= 0) {
	r = VESmail_now_sendhdrs(srv);
	if (r >= 0) rs += r;
	else rs = r;
    }
    if (rs >= 0) {
	r = probefn(usrv, ucf);
	if (r >= 0) rs += r;
	else rs = r;
    }
    while (rs >= 0 && (usrv->flags & (VESMAIL_SRVF_OVER | VESMAIL_SRVF_SHUTDOWN)) == VESMAIL_SRVF_OVER) {
	int r = VESmail_xform_process(usrv->req_in, 0, "", 0);
	if (r < 0) {
	    rs = r;
	    break;
	}
	rs += r;
	usrv->tmout = VESMAIL_NOW_PROBE_TMOUT;
	r = VESmail_server_run(usrv, (VESMAIL_SRVR_NOTHR | VESMAIL_SRVR_NOREQ | VESMAIL_SRVR_NOLOG | VESMAIL_SRVR_NOLOOP));
	if (r < 0) rs = r;
	else rs += r;
	if (time(NULL) - usrv->lastwrite >= VESMAIL_NOW_PROBE_TMOUT) break;
    }
    usrv->rsp_out = NULL;
    VESmail_server_free(usrv);
    if (rs >= 0) {
	r = VESmail_now_send(srv, 1, "");
	if (r < 0) rs = r;
	else rs += r;
    }
    srv->flags |= VESMAIL_SRVF_SHUTDOWN;
    return rs;
}

