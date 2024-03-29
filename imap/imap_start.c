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
#include "../VESmail.h"
#include "../lib/util.h"
#include "../lib/xform.h"
#include "../srv/server.h"
#include "../srv/tls.h"
#include "../srv/sasl.h"
#include "imap.h"
#include "imap_token.h"
#include "imap_track.h"
#include "imap_proxy.h"
#include "imap_xform.h"
#include "imap_xves.h"
#include "imap_start.h"

int VESmail_imap_rsp_send_hello(VESmail_server *srv) {
    VESmail_imap_token *rsp;
    if (VESmail_server_abuse_peer(srv, 0) < 0) {
	rsp = VESmail_imap_rsp_new(NULL, "NO");
	VESmail_imap_token_splice(rsp, -1, 0, 1,
	    VESmail_imap_token_atom(VESmail_server_ERRCODE(VESMAIL_E_ABUSE) " Too many login attempts, try again later.")
	);
	srv->flags |= VESMAIL_SRVF_SHUTDOWN;
    } else if (!(srv->flags & VESMAIL_SRVF_QUIET)) {
	rsp = VESmail_imap_rsp_new(NULL, "OK");
	VESmail_imap_token_splice(rsp, -1, 0, 2,
	    VESmail_imap_token_lset(VESmail_imap_caps(srv, VESmail_imap_token_index(1, VESmail_imap_token_atom("CAPABILITY")), 1)),
	    VESmail_imap_token_atom(VESMAIL_SHORT_NAME " ready.")
	);
    } else return 0;
    int rs = VESmail_imap_rsp_send(srv, rsp);
    VESmail_imap_token_free(rsp);
    return rs;
}

int VESmail_imap_start_ready(VESmail_server *srv) {
    if (VESMAIL_IMAP(srv)->state != VESMAIL_IMAP_S_HELLO) return 0;
    VESMAIL_IMAP(srv)->state = VESMAIL_IMAP_S_START;
    return VESmail_imap_rsp_send_hello(srv);
}

int VESmail_imap_start_login_fail(VESmail_server *srv, int er, const char *msg, VESmail_imap_token *relayed) {
    VESmail_imap *imap = VESMAIL_IMAP(srv);
    if (imap->state == VESMAIL_IMAP_S_FAIL) return 0;
    imap->state = VESMAIL_IMAP_S_FAIL;
    VESmail_server_logauth(srv, er, 0);
    if (srv->req_out) {
	VESmail_server_abuse_peer(srv, 2);
	VESmail_server_abuse_user(srv, 2);
    }
    VESmail_imap_token *tag = VESmail_imap_track_cp_tag(imap->track);
    VESmail_imap_track_done(&imap->track);
    VESmail_imap_token *rsp = VESmail_imap_rsp_new(tag, "NO");
    if (msg) VESmail_imap_token_splice(rsp, -1, 0, 1, VESmail_imap_token_atom(msg));
    if (relayed) {
	VESmail_imap_token *rel = VESmail_imap_token_clone(relayed);
	if (rel->type == VESMAIL_IMAP_T_LINE) rel->type = VESMAIL_IMAP_T_LIST;
	VESmail_imap_token_push(rsp, rel);
    }
    int rs = VESmail_imap_rsp_send(srv, rsp);
    VESmail_imap_token_free(rsp);
    srv->req_in->imap->procfn = &VESmail_imap_start_req_fn;
    srv->req_in->imap->state = VESMAIL_IMAP_X_INIT;
    VESmail_server_disconnect(srv);
    return rs;
}

int VESmail_imap_fwd_login(VESmail_server *srv) {
    int rs;
    VESmail_imap_track *trk = VESMAIL_IMAP(srv)->track;
    VESmail_imap_token *tag = VESmail_imap_track_cp_tag(trk);
    VESmail_imap_token *req;
    if (srv->sasl) {
	VESMAIL_SRV_DEBUG(srv, 1, sprintf(debug, "AUTHENTICATE %s", VESmail_sasl_get_name(srv->sasl)))
	req = VESmail_imap_req_new(tag, "AUTHENTICATE");
	VESmail_imap_token_push(req, VESmail_imap_token_atom(VESmail_sasl_get_name(srv->sasl)));
/*
// This code should not be used unless SASL-IR capability is detected. Not worth the headache.

	char *ir = VESmail_sasl_process(srv->sasl, NULL, 0);
	if (ir) {
	    VESmail_imap_token_push(req, VESmail_imap_token_atom(ir));
	    free(ir);
	}
*/
    } else {
	VESMAIL_SRV_DEBUG(srv, 1, sprintf(debug, "LOGIN"))
	char *user = jVar_getString(jVar_get(VESMAIL_IMAP(srv)->uconf, "login"));
	char *pwd = jVar_getString(jVar_get(VESMAIL_IMAP(srv)->uconf, "password"));
	req = VESmail_imap_req_new(tag, "LOGIN");
	VESmail_imap_token_push(req, VESmail_imap_token_astring(user ? user : ""));
	VESmail_imap_token_push(req, VESmail_imap_token_astring(pwd ? pwd : ""));
	free(user);
	free(pwd);
    }
    rs = VESmail_imap_req_fwd(srv, req, VESMAIL_IMAP_F_DETACHD);
    return rs;
}

int VESmail_imap_start_sasl_cont(struct VESmail_server *srv, struct VESmail_imap_token *chlg) {
    if (!srv->sasl) return VESMAIL_E_SASL;
    if (chlg) {
	char *tk = VESmail_sasl_process(srv->sasl, VESmail_imap_token_data(chlg), chlg->len);
	if (tk) {
	    VESmail_imap_token *chlr = VESmail_imap_token_line();
	    VESmail_imap_token_push(chlr, VESmail_imap_token_atom(tk));
	    VESmail_cleanse(tk, strlen(tk));
	    free(tk);
	    int r = VESmail_imap_req_fwd(srv, chlr, 0);
	    VESmail_imap_token_free(chlr);
	    return r;
	}
    }
    return VESmail_imap_start_login_fail(srv, VESMAIL_E_SASL, VESmail_server_ERRCODE(VESMAIL_E_SASL) " Error negotiating SASL with the server", NULL);
}

int VESmail_imap_start_fn_rsp_starttls(int verb, VESmail_imap_token *rsp, VESmail_imap_track *trk) {
    VESmail_server *srv = trk->server;
    VESmail_imap_track_free(trk);
    int r;
    switch (verb) {
	case VESMAIL_IMAP_V_OK:
	    r = VESmail_tls_client_start(srv, 1);
	    if (r >= 0) break;
	    char *err = VESmail_server_errorStr(srv, r);
	    r = VESmail_imap_start_login_fail(srv, r, err, rsp);
	    free(err);
	    return r;
	default:
	    if (VESmail_tls_client_require(srv)) return VESmail_imap_start_login_fail(srv, VESMAIL_E_TLS, VESmail_server_ERRCODE(VESMAIL_E_TLS) " Bad response to STARTTLS", rsp);
	    break;
    }
    return VESmail_imap_fwd_login(srv);
}

int VESmail_imap_fwd_starttls(VESmail_server *srv) {
    VESMAIL_SRV_DEBUG(srv, 1, sprintf(debug, "STARTTLS"))
    VESmail_imap_token *req = VESmail_imap_req_new(NULL, "STARTTLS");
    VESmail_imap_track *trk = VESmail_imap_track_new_fwd(srv, req);
    trk->rspfn = &VESmail_imap_start_fn_rsp_starttls;
    return VESmail_imap_req_fwd(srv, req, VESMAIL_IMAP_F_DETACHD);
}

VESmail_imap_token *VESmail_imap_start_get_caps(VESmail_imap_token *rsp) {
    VESmail_imap_token *caps;
    if (rsp->len > 2
	&& VESmail_imap_token_isLSet(rsp->list[2])
	&& VESmail_imap_token_isIndex((caps = rsp->list[2]->list[0]))
	&& caps->len > 1
	&& VESmail_imap_get_verb(caps->list[0], VESmail_imap_verbs) == VESMAIL_IMAP_V_CAPABILITY
	) return caps;
    return NULL;
}

int VESmail_imap_start_check_cap(VESmail_imap_token *caps, int verb) {
    int i;
    if (caps) for (i = 0; i < caps->len; i++) if (VESmail_imap_get_verb(caps->list[i], VESmail_imap_verbs) == verb) return 1;
    return 0;
}

int VESmail_imap_start_fn_u_conn(int verb, VESmail_imap_token *token, VESmail_server *srv) {
    if (VESMAIL_IMAP(srv)->state == VESMAIL_IMAP_S_CONN) switch (verb) {
	case VESMAIL_IMAP_V_OK: {
	    VESmail_imap_token *caps = VESmail_imap_start_get_caps(token);
	    if (VESmail_imap_start_check_cap(caps, VESMAIL_IMAP_V_XVES)) {
		return VESmail_imap_start_login_fail(srv, VESMAIL_E_RELAY, VESmail_server_ERRCODE(VESMAIL_E_RELAY) " Forbidden remote capability XVES", token);
	    }
	    int ftls;
	    if (VESmail_tls_client_started(srv)) {
		ftls = 0;
	    } else {
		ftls = VESmail_tls_client_require(srv);
		if (!ftls && !VESmail_tls_client_none(srv)) {
		    ftls = VESmail_imap_start_check_cap(caps, VESMAIL_IMAP_V_STARTTLS);
		}
	    }
	    VESMAIL_IMAP(srv)->state = VESMAIL_IMAP_S_LOGIN;
	    return ftls ? VESmail_imap_fwd_starttls(srv) : VESmail_imap_fwd_login(srv);
	}
	case VESMAIL_IMAP_V_PREAUTH:
	    VESmail_imap_proxy_init(srv);
	    return 0;
	default:
	    break;
    }
    if (VESMAIL_IMAP(srv)->state == VESMAIL_IMAP_S_FAIL) return 0;
    switch (verb) {
	case VESMAIL_IMAP_V_BYE:
	case VESMAIL_IMAP_V_NO:
	case VESMAIL_IMAP_V_BAD:
	    break;
	default:
	    if (token->len < 1 || !VESmail_imap_token_isAtom(token->list[0]) || token->list[0]->len != 1 || token->list[0]->data[0] != '*') break;
	    return 0;
    }
    return VESmail_imap_start_login_fail(srv, VESMAIL_E_RELAY, VESmail_server_ERRCODE(VESMAIL_E_RELAY) " greeting", token);
}

int VESmail_imap_start_connect(VESmail_server *srv) {
    VESMAIL_IMAP(srv)->untaggedfn = &VESmail_imap_start_fn_u_conn;
    VESMAIL_IMAP(srv)->state = VESMAIL_IMAP_S_CONN;
    srv->flags |= VESMAIL_SRVF_OVER;
    srv->req_in->imap->state = VESMAIL_IMAP_X_HOLD;
    return 0;
}

int VESmail_imap_auth(VESmail_server *srv, const char *user, const char *pwd, int pwlen) {
    VESMAIL_IMAP(srv)->state = VESMAIL_IMAP_S_START;
    int r = VESmail_server_auth(srv, user, pwd, pwlen);
    if (r >= 0) r = VESmail_server_connect(srv, (VESMAIL_IMAP(srv)->uconf = jVar_get(srv->uconf, "imap")), "imap");
    if (r >= 0) {
	VESmail_server_set_keepalive(srv);
	VESmail_imap_start_connect(srv);
    }
    return r;
}

int VESmail_imap_start_fn_rsp_login(int verb, VESmail_imap_token *rsp, VESmail_imap_track *trk) {
    VESmail_sasl_free(trk->server->sasl);
    trk->server->sasl = NULL;
    switch (verb) {
	case VESMAIL_IMAP_V_OK: {
	    VESmail_imap_token *caps = VESmail_imap_start_get_caps(rsp);
	    if (!caps || !VESmail_imap_start_check_cap(caps, VESMAIL_IMAP_V_XVES)) {
		if (caps) VESmail_imap_caps(trk->server, caps, 0);
		VESmail_server_abuse_user(trk->server, 1);
		VESmail_imap_proxy_init(trk->server);
		break;
	    }
	}
	default:
	    VESmail_server_logauth(trk->server, VESMAIL_E_RAUTH, 0);
	    VESmail_server_abuse_peer(trk->server, 10);
	    VESmail_server_abuse_user(trk->server, 10);
	    VESmail_server_disconnect(trk->server);
	    trk->server->req_in->imap->procfn = &VESmail_imap_start_req_fn;
	    break;
    }
    int rs = VESmail_imap_rsp_send(trk->server, rsp);
    trk->server->req_in->imap->state = VESMAIL_IMAP_X_INIT;
    VESmail_imap_track_free(trk);
    return rs;
}

int VESmail_imap_start_probe(VESmail_server *srv, jVar *uconf) {
    VESmail_imap_token *token = VESmail_imap_token_splice(
	VESmail_imap_token_line(),
	0, 0, 1,
	VESmail_imap_token_atom("probe")
    );
    VESmail_imap_track *trk = VESmail_imap_track_new_fwd(srv, token);
    trk->token = token;
    trk->rspfn = &VESmail_imap_start_fn_rsp_login;
    int r = VESmail_server_connect(srv, (VESMAIL_IMAP(srv)->uconf = uconf), NULL);
    if (r < 0) {
	r = VESmail_imap_rsp_send_error(srv, VESmail_imap_cp_tag(token), r);
	VESmail_imap_track_done(&VESMAIL_IMAP(srv)->track);
	return r;
    }
    return VESmail_imap_start_connect(srv);
}

int VESmail_imap_start_req_fn_sasl(VESmail_server *srv, VESmail_imap_token *token) {
    if (token->len != 1 || !VESmail_imap_token_isAtom(token->list[0])) {
	return VESmail_imap_start_login_fail(srv, VESMAIL_E_SASL, VESmail_server_ERRCODE(VESMAIL_E_SASL) " Invalid SASL response from the client", NULL);
    }
    return VESmail_imap_start_sasl(srv, token->list[0]);
}

int VESmail_imap_start_sasl(VESmail_server *srv, VESmail_imap_token *req) {
    VESmail_sasl *sasl = srv->sasl;
    if (!sasl) return VESMAIL_E_PARAM;
    char *chlg = VESmail_sasl_process(sasl, (req ? VESmail_imap_token_data(req) : NULL), (req ? req->len : 0));
    if (chlg) {
	srv->req_in->imap->state = VESMAIL_IMAP_X_HOLD;
	srv->req_in->imap->procfn = &VESmail_imap_start_req_fn_sasl;
	int rs = VESmail_imap_cont(srv, chlg);
	free(chlg);
	return rs;
    }
    int rs = VESMAIL_E_SASL;
    if (VESmail_sasl_authd(sasl)) {
	rs = VESmail_imap_auth(srv, sasl->user, sasl->passwd, sasl->pwlen);
    }
    if (rs < 0) {
	char *err = VESmail_server_errorStr(srv, rs);
	rs = VESmail_imap_start_login_fail(srv, rs, err, NULL);
	free(err);
    }
    return rs;
}

int VESmail_imap_start_req_fn(VESmail_server *srv, VESmail_imap_token *token) {
    VESmail_imap_token *tag = VESmail_imap_cp_tag(token);
    const char *er = NULL;
    int verb;
    if (tag && token->len > 1) {
	verb = VESmail_imap_get_verb(token->list[1], VESmail_imap_verbs);
	int rs = VESMAIL_E_UNKNOWN;
	switch (verb) {
	    case VESMAIL_IMAP_V_NOOP:
		rs = 0;
		break;
	    case VESMAIL_IMAP_V_CAPABILITY: {
		VESmail_imap_token *caps = VESmail_imap_rsp_new(NULL, "CAPABILITY");
		VESmail_imap_caps(srv, caps, 1);
		rs = VESmail_imap_rsp_send(srv, caps);
		VESmail_imap_token_free(caps);
		break;
	    }
	    case VESMAIL_IMAP_V_ID: {
		if (token->len > 2 && (token->list[2]->type != VESMAIL_IMAP_T_LSET || token->list[2]->list[0]->type != VESMAIL_IMAP_T_LIST)) return VESMAIL_E_PARAM;
		VESmail_imap_token *rsp = VESmail_imap_rsp_new(NULL, "ID");
		VESmail_imap_token_push(rsp, VESmail_imap_token_list(2, VESmail_imap_token_quoted("name"), VESmail_imap_token_quoted(VESMAIL_SHORT_NAME)));
		rs = VESmail_imap_rsp_send(srv, rsp);
		VESmail_imap_token_free(rsp);
		break;
	    }
	    case VESMAIL_IMAP_V_LOGIN: {
		char user[256];
		rs = 0;
		VESmail_imap_token_free(tag);
		VESmail_imap_ARG_CHK(rs, srv, token, 2, AString)
		if (rs >= 0 && token->list[2]->len > sizeof(user) - 1) rs = VESMAIL_E_PARAM;
		VESmail_imap_ARG_CHK(rs, srv, token, 3, AString)
		if (rs < 0) return VESmail_imap_rsp_send_bad(srv, VESmail_imap_cp_tag(token), "Expected: LOGIN <VESmail_ID> <VESkey>");
		VESmail_imap_track *trk = VESmail_imap_track_new_fwd(srv, token);
		trk->rspfn = &VESmail_imap_start_fn_rsp_login;
		memcpy(user, VESmail_imap_token_data(token->list[2]), token->list[2]->len);
		user[token->list[2]->len] = 0;
		rs = VESmail_imap_auth(srv, user, VESmail_imap_token_data(token->list[3]), token->list[3]->len);
		if (rs < 0) {
		    char *err = VESmail_server_errorStr(srv, rs);
		    rs = VESmail_imap_start_login_fail(srv, rs, err, NULL);
		    free(err);
		}
		return rs;
	    }
	    case VESMAIL_IMAP_V_AUTHENTICATE: {
		if (token->len >= 3) {
		    VESmail_sasl_free(srv->sasl);
		    srv->sasl = VESmail_sasl_new_server(VESmail_imap_get_verb(token->list[2], VESmail_sasl_mechs), srv);
		    if (srv->sasl) {
			VESmail_imap_token *ir;
			if (token->len > 3) {
			    rs = 0;
			    VESmail_imap_ARG_CHK(rs, srv, token, 3, AString)
			    if (rs < 0) return VESmail_imap_rsp_send_bad(srv, tag, "Invalid SASL-IR");
			    ir = token->list[3];
			} else ir = NULL;
			VESmail_imap_token_free(tag);
			VESmail_imap_track *trk = VESmail_imap_track_new_fwd(srv, token);
			trk->rspfn = &VESmail_imap_start_fn_rsp_login;
			return VESmail_imap_start_sasl(srv, ir);
		    }
		}
		return VESmail_imap_rsp_send_bad(srv, tag, "Expected: AUTHENTICATE <mechanism>[ <base64>]");
	    }
	    case VESMAIL_IMAP_V_STARTTLS: {
		if (!VESmail_tls_server_allow_starttls(srv)) {
		    er = "Not allowed in this context";
		    break;
		}
		VESmail_imap_token *rsp = VESmail_imap_rsp_new(tag, "OK");
		VESmail_imap_token_push(rsp, VESmail_imap_token_atom("Begin TLS negotiation"));
		int r = VESmail_imap_rsp_send(srv, rsp);
		VESmail_imap_token_free(rsp);
		if (r < 0) return r;
		rs += r;
		r = VESmail_tls_server_start(srv, 1);
		if (r < 0) return r;
		rs += r;
		return rs;
	    }
	    case VESMAIL_IMAP_V_XVES:
		return VESmail_imap_xves(srv, token, tag);
	    case VESMAIL_IMAP_V_LOGOUT: {
		srv->flags |= VESMAIL_SRVF_SHUTDOWN;
		VESmail_imap_token *rsp = VESmail_imap_rsp_new(NULL, "BYE");
		VESmail_imap_token_push(rsp, VESmail_imap_token_atom("Closing the connection"));
		rs = VESmail_imap_rsp_send(srv, rsp);
		VESmail_imap_token_free(rsp);
		break;
	    }
	    default:
		break;
	}
	if (!er && rs < 0) switch (rs) {
	    case VESMAIL_E_UNKNOWN:
		er = "Unsupported IMAP command";
		break;
	    
	    default:
		er = "Unknown error";
		break;
	}
    } else {
	er = "Cannot parse IMAP command";
    }
    VESmail_imap_token *rsp;
    if (!er) {
	rsp = VESmail_imap_rsp_new(tag, "OK");
	VESmail_imap_token_push(rsp, VESmail_imap_token_atom(VESmail_imap_verbs[verb]));
	VESmail_imap_token_push(rsp, VESmail_imap_token_atom("completed"));
    } else {
	rsp = VESmail_imap_rsp_new(tag, "BAD");
	VESmail_imap_token_push(rsp, VESmail_imap_token_atom(er));
    }
    int r = VESmail_imap_rsp_send(srv, rsp);
    VESmail_imap_req_abort(srv);
    VESmail_imap_token_free(rsp);
    return r;
}

