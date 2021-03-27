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
#include "../lib/xform.h"
#include "../lib/util.h"
#include "../srv/server.h"
#include "imap_token.h"
#include "imap_track.h"
#include "imap.h"
#include "imap_xform.h"
#include "imap_msg.h"
#include "imap_fetch.h"
#include "imap_result.h"
#include "imap_sect.h"
#include "imap_append.h"
#include "imap_xves.h"
#include "imap_proxy.h"

int VESmail_imap_proxy_fn_rsp_u(int verb, VESmail_imap_token *rsp, VESmail_server *srv) {
    VESmail_imap_debug_token(srv, 2, "<<<<", rsp);
    int rs = 0;
    VESmail_imap *imap = VESMAIL_IMAP(srv);
    if (!(imap->flags & VESMAIL_IMAP_F_RSP)) {
	switch (verb) {
	    case VESMAIL_IMAP_V_BYE:
		imap->flags |= VESMAIL_IMAP_F_BYE;
		break;
	    case VESMAIL_IMAP_V_CAPABILITY:
		VESmail_imap_caps(srv, rsp, 0);
		break;
	    case VESMAIL_IMAP_V_FLAGS:
		VESmail_imap_reset(srv);
		break;
	    default:
		if (rsp->len >= 4 && VESmail_imap_get_verb(rsp->list[2], VESmail_imap_verbs) == VESMAIL_IMAP_V_FETCH
		    && rsp->list[3]->type == VESMAIL_IMAP_T_LSET && rsp->list[3]->len == 1) {
		    imap->results.curr = VESmail_imap_result_new(rsp, srv);
		} else if (rsp->len >= 3 && VESmail_imap_get_verb(rsp->list[2], VESmail_imap_verbs) == VESMAIL_IMAP_V_EXPUNGE) {
		    VESmail_imap_reset(srv);
		}
	}
	imap->flags |= VESMAIL_IMAP_F_RSP;
    }
    if (imap->results.curr) {
	int r = VESmail_imap_result_update(imap->results.curr);
	if (r < 0) return r;
	rs += r;
    }
    if (rsp->state != VESMAIL_IMAP_P_CONT) {
	imap->flags &= ~VESMAIL_IMAP_F_RSP;
	if (imap->results.curr) {
	    int r = VESmail_imap_result_commit(imap->results.curr);
	    imap->results.curr = NULL;
	    if (r < 0) return r;
	    rs += r;
	} else {
	    int r = VESmail_imap_rsp_send(srv, rsp);
	    if (r < 0) return r;
	    rs += r;
	}
    }
    return rs;
}

int VESmail_imap_proxy_fn_rsp_t(int verb, VESmail_imap_token *rsp, VESmail_imap_track *trk) {
    int rs = VESmail_imap_rsp_send(trk->server, rsp);
    VESmail_imap_track_free(trk);
    return rs;
}

int VESmail_imap_proxy_fn_rsp_h(int verb, VESmail_imap_token *rsp, VESmail_imap_track *trk) {
    trk->server->req_in->imap->state = VESMAIL_IMAP_X_INIT;
    return VESmail_imap_proxy_fn_rsp_t(verb, rsp, trk);
}

int VESmail_imap_proxy_fn_rsp_fetch(int verb, VESmail_imap_token *rsp, VESmail_imap_track *trk) {
    VESmail_imap *imap = VESMAIL_IMAP(trk->server);
    if (imap->results.queue) {
	VESmail_imap_rsp_detach(trk->server, rsp);
	VESmail_imap_token_free(trk->token);
	trk->token = rsp;
	trk->chain = imap->results.track;
	imap->results.track = trk;
	return 0;
    }
    return VESmail_imap_proxy_fn_rsp_t(verb, rsp, trk);
}

int VESmail_imap_proxy_fn_rsp_recon(int verb, VESmail_imap_token *rsp, VESmail_imap_track *trk) {
    VESmail_imap_debug_token(trk->server, 1, "recon <<<<", rsp);
    VESmail_imap_track *ftrk = VESmail_imap_track_new_fwd(trk->server, trk->token);
    ftrk->rspfn = &VESmail_imap_proxy_fn_rsp_fetch;
    VESmail_imap_debug_token(trk->server, 1, "recon >>>>", trk->token);
    int r = VESmail_imap_req_fwd(trk->server, (ftrk->token = trk->token), 0);
    trk->token = NULL;
    VESmail_imap_track_free(trk);
    return r;
}

int VESmail_imap_proxy_fn_rsp_p(int verb, VESmail_imap_token *rsp, VESmail_imap_track *trk) {
    VESmail_imap_debug_token(trk->server, 1, "<<<<", rsp);
    VESmail_imap_track_free(trk);
    return 0;
}

struct VESmail_imap_proxy_fetch_ctl {
    VESmail_imap_token *mark;
    char recon;
    char rlarge;
};

void VESmail_imap_proxy_fetch_mark(struct VESmail_imap_proxy_fetch_ctl *ctl, const char *mark) {
    if (!ctl->mark) {
	ctl->mark = VESmail_imap_token_splice(
	    VESmail_imap_token_new(VESMAIL_IMAP_T_LSET, 0), 0, 0, 2,
	    VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, "BODY.PEEK"),
	    VESmail_imap_token_splice(
		VESmail_imap_token_new(VESMAIL_IMAP_T_INDEX, 0), 0, 0, 2,
		    VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, "HEADER.FIELDS"),
		    VESmail_imap_token_splice(
			VESmail_imap_token_new(VESMAIL_IMAP_T_LSET, 0), 0, 0, 1,
			VESmail_imap_token_list(0)
		    )
		)
	    );
    }
    VESmail_imap_token_splice(ctl->mark->list[1]->list[1]->list[0], -1, 0, 1, VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, mark));
}

void VESmail_imap_proxy_fetch_prep(VESmail_imap_fetch *fetch, VESmail_imap_token *token, struct VESmail_imap_proxy_fetch_ctl *ctl) {
    if (!fetch) return;
    char rhdr[64];
    char rstr[32];
    switch (fetch->mode) {
	case VESMAIL_IMAP_FM_NONE:
	    switch (fetch->type) {
		case VESMAIL_IMAP_FV_RFC822_TEXT:
		    ctl->recon = 1;
		case VESMAIL_IMAP_FV_RFC822:
		case VESMAIL_IMAP_FV_RFC822_HEADER:
		    ctl->rlarge = 1;
		    break;
		case VESMAIL_IMAP_FV_BODY:
		case VESMAIL_IMAP_FV_BODYSTRUCTURE:
		case VESMAIL_IMAP_FV_ENVELOPE:
		    ctl->recon = 1;
		default:
		    break;
	    }
	    return;
	case VESMAIL_IMAP_FM_START:
	    sprintf(rhdr, "X-VESMAIL_M_RANGE_%lu-%s", fetch->range[0], VESmail_imap_fetch_rhash(fetch, rstr));
	    if (fetch->range[0]) {
		strcpy(rstr, "<0>");
	    } else {
		*rstr = 0;
	    }
	    break;
	case VESMAIL_IMAP_FM_RANGE: {
	    sprintf(rhdr, "X-VESMAIL_M_RANGE_%lu_%lu-%s", fetch->range[0], fetch->range[1], VESmail_imap_fetch_rhash(fetch, rstr));
	    unsigned long long int rlen = fetch->range[0];
	    switch (fetch->stype) {
		case VESMAIL_IMAP_FS_MIME:
		case VESMAIL_IMAP_FS_HEADER:
		    rlen = 0xffffffff;
		    break;
		default:
		rlen = (rlen + fetch->range[1]) * 41 / 30 + 16384;
	    }
	    if (rlen < 0xffffffff) {
		sprintf(rstr, "<0.%llu>", rlen);
	    } else {
		strcpy(rstr, "<0>");
	    }
	    break;
	}
	default:
	    *rstr = *rhdr = 0;
	    break;
    }
    if (*rstr) VESmail_imap_token_splice(token, 2, 1, 1, VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, rstr));
    if (*rhdr) VESmail_imap_proxy_fetch_mark(ctl, rhdr);
    switch (fetch->stype) {
	case VESMAIL_IMAP_FS_HEADER_FIELDS:
	case VESMAIL_IMAP_FS_HEADER_FIELDS_NOT:
	    VESmail_imap_sect_hdr_escape(fetch, token);
	default:
	    break;
    }
    ctl->rlarge = 1;
    switch (fetch->stype) {
	case VESMAIL_IMAP_FS_NONE:
	case VESMAIL_IMAP_FS_HEADER:
	    if (!*rhdr && !fetch->seclen) break;
	default:
	    ctl->recon = 1;
    }
}

int VESmail_imap_proxy_isSingleSel(VESmail_imap_token *sel) {
    if (!VESmail_imap_token_isAtom(sel) || sel->len < 1) return 0;
    const char *s = VESmail_imap_token_data(sel);
    if (sel->len == 1 && *s == '*') return 1;
    int i;
    for (i = sel->len; i > 0; i--, s++) if (*s < '0' || *s > '9') return 0;
    return 1;
}

int VESmail_imap_proxy_fn_req(VESmail_server *srv, VESmail_imap_token *token) {
    VESmail_imap_track *trk;
    int cdata = (VESMAIL_IMAP(srv)->flags & VESMAIL_IMAP_F_CDATA);
    int verb = (token->len > 1 && !cdata
	? VESmail_imap_get_verb(token->list[1], VESmail_imap_verbs)
	: VESMAIL_E_UNKNOWN);
    int v_uid = (verb == VESMAIL_IMAP_V_UID ? 1 : 0);
    if (v_uid && token->len > 2) verb = VESmail_imap_get_verb(token->list[2], VESmail_imap_verbs);
    int rs = 0;
    int detachd = 0;
    switch (verb) {
	case VESMAIL_IMAP_V_FETCH: {
	    if (token->state == VESMAIL_IMAP_P_CONT) return VESmail_imap_cont(srv, "OK");
	    int lidx = 3 + v_uid;
	    if (token->len > lidx) {
		VESmail_imap_token *lset = token->list[lidx];
		VESmail_imap_token **flst;
		int flen;
		if (VESmail_imap_token_isLSet(lset) && lset->len == 1 && VESmail_imap_token_isList(lset->list[0])) {
		    flst = lset->list[0]->list;
		    flen = lset->list[0]->len;
		} else {
		    flst = token->list + lidx;
		    flen = 1;
		    lset = NULL;
		}
		int i;
		struct VESmail_imap_proxy_fetch_ctl ctl = {
		    .mark = NULL,
		    .recon = 0,
		    .rlarge = 0
		};
		for (i = 0; i < flen; i++) {
		    VESmail_imap_debug_token(srv, 2, "fetch", flst[i]);
		    VESmail_imap_fetch *fetch = VESmail_imap_fetch_parse(flst[i]);
		    VESmail_imap_proxy_fetch_prep(fetch, flst[i], &ctl);
		    VESmail_imap_fetch_free(fetch);
		}
		if (ctl.mark) {
		    if (!lset) {
			lset = VESmail_imap_token_new(VESMAIL_IMAP_T_LSET, 0);
			token->list[lidx] = VESmail_imap_token_splice(lset, 0, 0, 1, VESmail_imap_token_list(1, token->list[lidx]));
		    }
		    VESmail_imap_token_splice(lset->list[0], 0, 0, 1, ctl.mark);
		}
		VESmail_imap_debug_token(srv, 2, "proxy", token);
		if (ctl.recon && ctl.rlarge) {
		    VESmail_imap_token *sel = token->list[lidx - 1];
		    if (!VESmail_imap_proxy_isSingleSel(sel)) {
			VESmail_imap_token *rreq = VESmail_imap_req_new(NULL, (v_uid ? "UID FETCH" : "FETCH"));
			VESmail_imap_token_splice(rreq, -1, 0, 2,
			    VESmail_imap_token_clone(sel),
			    VESmail_imap_token_splice(
				VESmail_imap_token_new(VESMAIL_IMAP_T_LSET, 0),
				0, 0, 1,
				VESmail_imap_token_list(2,
				    VESmail_imap_token_splice(
					VESmail_imap_token_new(VESMAIL_IMAP_T_LSET, 0),
					0, 0, 2,
					VESmail_imap_token_atom("BODY.PEEK"),
					VESmail_imap_token_splice(
					    VESmail_imap_token_new(VESMAIL_IMAP_T_INDEX, 0),
					    0, 0, 2,
					    VESmail_imap_token_atom("HEADER.FIELDS"),
					    VESmail_imap_token_splice(
						VESmail_imap_token_new(VESMAIL_IMAP_T_LSET, 0),
						0, 0, 1,
						VESmail_imap_token_splice(
						    VESmail_imap_token_new(VESMAIL_IMAP_T_LIST, 0),
						    0, 0, 1,
						    VESmail_imap_token_atom("X-VESMAIL_M_RECON")
						)
					    )
					)
				    ),
				    VESmail_imap_token_atom("BODYSTRUCTURE")
				)
			    )
			);
			VESmail_imap_debug_token(srv, 1, "recon", rreq);
			trk = VESmail_imap_track_new_fwd(srv, rreq);
			trk->rspfn = &VESmail_imap_proxy_fn_rsp_recon;
			VESmail_imap_req_detach(srv, token);
			trk->token = token;
			token = rreq;
			detachd = VESMAIL_IMAP_F_DETACHD;
			break;
		    }
		}
	    }
	    trk = VESmail_imap_track_new_fwd(srv, token);
	    trk->rspfn = &VESmail_imap_proxy_fn_rsp_fetch;
	    break;
	}
	case VESMAIL_IMAP_V_XVES:
	    return VESmail_imap_xves(srv, token, NULL);
	case VESMAIL_IMAP_V_COMPRESS: {
	    VESmail_imap_token *rsp = VESmail_imap_rsp_new(VESmail_imap_cp_tag(token), "NO");
	    VESmail_imap_token_push(rsp, VESmail_imap_token_atom("Rejected by VESmail proxy"));
	    int rs = VESmail_imap_rsp_send(srv, rsp);
	    VESmail_imap_token_free(rsp);
	    return rs;
	}
	case VESMAIL_IMAP_V_APPEND: {
	    int r = VESmail_imap_token_error(token);
	    if (r) {
		VESmail_imap_req_abort(srv);
		return VESmail_imap_rsp_send_error(srv, VESmail_imap_cp_tag(token), r);
	    }
	    if (token->state == VESMAIL_IMAP_P_CONT) {
		VESmail_imap_token *body = token->list[token->len - 1];
		if (!VESmail_imap_token_isLiteral(body) || body->len == 0) {
		    return VESmail_imap_rsp_send_error(srv, VESmail_imap_cp_tag(token), VESMAIL_E_PARAM);
		}
		VESmail_xform *sync;
		if (body->len > VESMAIL_IMAP(srv)->maxBufd) {
		    if (!token->hold) {
			trk = VESmail_imap_track_new_fwd(srv, token);
			trk->rspfn = &VESmail_imap_proxy_fn_rsp_h;
		    }
		    sync = srv->req_out;
		    long long int l = VESmail_imap_append_syncl(body->len);
		    body->len = l > 0xffffffff ? 0xffffffff : l;
		} else sync = NULL;
		int r = VESmail_imap_append_encrypt(srv, body, sync);
		if (r >= 0) {
		    int r2 = 0;
		    if (sync || token->hold) {
			while (token->hold != body) {
			    int r3 = VESmail_imap_req_fwd(srv, token, 0);
			    if (r3 < 0) return r3;
			    if (!token->hold) return VESMAIL_E_BUF;
			    r2 += r3;
			}
		    } else {
			r2 = VESmail_imap_cont(srv, "OK");
		    }
		    if (r2 < 0) return r2;
		    return r + r2;
		} else {
		    return token->hold ? r : VESmail_imap_rsp_send_error(srv, VESmail_imap_cp_tag(token), r);
		}
	    } else {
		if (token->hold) {
		    trk = VESMAIL_IMAP(srv)->track;
		    if (!trk || trk->token) return VESMAIL_E_INTERNAL;
		} else {
		    trk = VESmail_imap_track_new_fwd(srv, token);
		    trk->rspfn = &VESmail_imap_proxy_fn_rsp_h;
		}
		VESmail_imap_req_detach(srv, token);
		trk->token = token;
		srv->req_in->imap->state = VESMAIL_IMAP_X_HOLD;
		break;
	    }
	}
	default:
	    if (!token->hold && !cdata) {
		trk = VESmail_imap_track_new_fwd(srv, token);
		trk->rspfn = &VESmail_imap_proxy_fn_rsp_t;
	    }
	    break;
    }
    rs = VESmail_imap_req_fwd(srv, token, detachd);
    srv->flags |= VESMAIL_SRVF_OVER;
    VESMAIL_IMAP(srv)->flags &= ~VESMAIL_IMAP_F_CDATA;
    return rs;
}

int VESmail_imap_proxy_req_send(VESmail_server *srv, VESmail_imap_token *req) {
    VESmail_imap_track *trk = VESmail_imap_track_new_queue(srv, req);
    trk->rspfn = &VESmail_imap_proxy_fn_rsp_p;
    if (VESmail_imap_req_ready(srv)) return VESmail_imap_track_out(&VESMAIL_IMAP(srv)->reqq);
    return 0;
}

int VESmail_imap_proxy_init(VESmail_server *srv) {
    srv->req_in->imap->procfn = &VESmail_imap_proxy_fn_req;
    VESMAIL_IMAP(srv)->untaggedfn = &VESmail_imap_proxy_fn_rsp_u;
    srv->req_in->imap->state = VESMAIL_IMAP_X_INIT;
    VESMAIL_IMAP(srv)->state = VESMAIL_IMAP_S_PROXY;
    return VESmail_server_logauth(srv, 0, 0);
}
