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
    VESmail_imap_token *rsp = VESmail_imap_rsp_new(NULL, "OK");
    VESmail_imap_token_splice(rsp, -1, 0, 2,
	VESmail_imap_token_lset(VESmail_imap_caps(srv, VESmail_imap_token_index(1, VESmail_imap_token_atom("CAPABILITY")), 1)),
	VESmail_imap_token_atom(VESMAIL_SHORT_NAME " ready.")
    );
    int rs = VESmail_imap_rsp_send(srv, rsp);
    VESmail_imap_token_free(rsp);
    return rs;
}

int VESmail_imap_start_ready(VESmail_server *srv) {
    if (VESMAIL_IMAP(srv)->state != VESMAIL_IMAP_S_HELLO) return 0;
    VESMAIL_IMAP(srv)->state = VESMAIL_IMAP_S_START;
    return VESmail_imap_rsp_send_hello(srv);
}

int VESmail_imap_fwd_login(VESmail_server *srv) {
    char *user = jVar_getString(jVar_get(VESMAIL_IMAP(srv)->uconf, "login"));
    char *pwd = jVar_getString(jVar_get(VESMAIL_IMAP(srv)->uconf, "password"));
    int rs;
    VESmail_imap_track *trk = VESMAIL_IMAP(srv)->track;
    VESmail_imap_token *tag = VESmail_imap_track_cp_tag(trk);
    VESmail_imap_token *req = VESmail_imap_req_new(tag, "LOGIN");
    VESmail_imap_token_push(req, VESmail_imap_token_astring(user ? user : ""));
    VESmail_imap_token_push(req, VESmail_imap_token_astring(pwd ? pwd : ""));
    rs = VESmail_imap_req_fwd(srv, req);
    free(user);
    free(pwd);
    return rs;
}

int VESmail_imap_start_login_fail(VESmail_server *srv, const char *msg, VESmail_imap_token *relayed) {
    VESmail_imap_token *tag = VESmail_imap_track_cp_tag(VESMAIL_IMAP(srv)->track);
    VESmail_imap_track_done(&VESMAIL_IMAP(srv)->track);
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
    return rs;
}

int VESmail_imap_start_fn_rsp_starttls(int verb, VESmail_imap_token *rsp, VESmail_imap_track *trk) {
    VESmail_server *srv = trk->server;
    VESmail_imap_track_free(trk);
    int r;
    switch (verb) {
	case VESMAIL_IMAP_V_OK:
	    r = VESmail_tls_client_start(srv, 1);
	    if (r < 0) return r;
	    break;
	default:
	    if (VESmail_tls_client_require(srv)) return VESmail_imap_start_login_fail(srv, "tls_error", rsp);
	    break;
    }
    return VESmail_imap_fwd_login(srv);
}

int VESmail_imap_fwd_starttls(VESmail_server *srv) {
    VESmail_imap_token *req = VESmail_imap_req_new(NULL, "STARTTLS");
    VESmail_imap_track *trk = VESmail_imap_track_new_fwd(srv, req);
    trk->rspfn = &VESmail_imap_start_fn_rsp_starttls;
    return VESmail_imap_req_fwd(srv, req);
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
    switch (verb) {
	case VESMAIL_IMAP_V_OK: {
	    int ftls;
	    if (VESmail_tls_client_started(srv)) {
		ftls = 0;
	    } else {
		ftls = VESmail_tls_client_require(srv);
		if (!ftls && !VESmail_tls_client_none(srv)) {
		    ftls = VESmail_imap_start_check_cap(VESmail_imap_start_get_caps(token), VESMAIL_IMAP_V_STARTTLS);
		}
	    }
	    return ftls ? VESmail_imap_fwd_starttls(srv) : VESmail_imap_fwd_login(srv);
	}
	case VESMAIL_IMAP_V_PREAUTH:
	    VESmail_imap_proxy_init(srv);
	    return 0;
	case VESMAIL_IMAP_V_BYE:
	case VESMAIL_IMAP_V_NO:
	case VESMAIL_IMAP_V_BAD:
	    break;
	default:
	    return 0;
    }
    return VESmail_imap_start_login_fail(srv, "[greeting]", token);
}

int VESmail_imap_auth(VESmail_server *srv, const char *user, const char *pwd, int pwlen) {
    if (!VESmail_server_auth(srv, user, pwd, pwlen)) return VESMAIL_E_VES;
    int r = VESmail_server_connect(srv, (VESMAIL_IMAP(srv)->uconf = jVar_get(srv->uconf, "imap")), "imap");
    if (r >= 0) {
	VESMAIL_IMAP(srv)->untaggedfn = &VESmail_imap_start_fn_u_conn;
	VESMAIL_IMAP(srv)->state = VESMAIL_IMAP_S_CONN;
	srv->flags |= VESMAIL_SRVF_OVER;
	srv->req_in->imap->state = VESMAIL_IMAP_X_HOLD;
    }
    return r;
}

int VESmail_imap_start_fn_rsp_login(int verb, VESmail_imap_token *rsp, VESmail_imap_track *trk) {
    switch (verb) {
	case VESMAIL_IMAP_V_OK: {
	    VESmail_imap_token *caps = VESmail_imap_start_get_caps(rsp);
	    if (caps) VESmail_imap_caps(trk->server, caps, 0);
	    VESmail_imap_proxy_init(trk->server);
	}
    }
    int rs = VESmail_imap_rsp_send(trk->server, rsp);
    trk->server->req_in->imap->state = VESMAIL_IMAP_X_INIT;
    VESmail_imap_track_free(trk);
    return rs;
}

int VESmail_imap_start_req_fn_sasl(VESmail_server *srv, VESmail_imap_token *token) {
    if (token->len != 1 || !VESmail_imap_token_isAtom(token->list[0])) {
	return VESmail_imap_start_login_fail(srv, "Invalid SASL response", NULL);
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
	rs = VESmail_imap_start_login_fail(srv, err, NULL);
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
		    rs = VESmail_imap_rsp_send_error(srv, VESmail_imap_cp_tag(token), rs);
		    VESmail_imap_track_done(&VESMAIL_IMAP(srv)->track);
		} else {
		}
		return rs;
	    }
	    case VESMAIL_IMAP_V_AUTHENTICATE: {
		if (token->len >= 3) {
		    VESmail_sasl_free(srv->sasl);
		    srv->sasl = VESmail_sasl_new_server(VESmail_imap_get_verb(token->list[2], VESmail_sasl_mechs));
		    if (srv->sasl) {
			VESmail_imap_token *ir;
			if (token->len > 3) {
			    rs = 0;
			    VESmail_imap_ARG_CHK(rs, srv, token, 3, AString)
			    if (rs < 0) return VESmail_imap_rsp_send_bad(srv, VESmail_imap_cp_tag(token), "Invalid SASL-IR");
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

