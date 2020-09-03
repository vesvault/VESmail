/***************************************************************************
 *  _____
 * |\    | >                   VESmail Project
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
#include "../lib/optns.h"
#include "../srv/server.h"
#include "../srv/tls.h"
#include "../srv/sasl.h"
#include "imap_token.h"
#include "imap_track.h"
#include "imap_start.h"
#include "imap_xform.h"
#include "imap_msg.h"
#include "imap_result.h"
#include "imap.h"

int VESmail_imap_rsp_send(VESmail_server *srv, VESmail_imap_token *rsp) {
    return VESmail_imap_token_render(rsp, srv->rsp_out, NULL);
}

int VESmail_imap_req_next(VESmail_server *srv) {
    VESMAIL_IMAP(srv)->cont = NULL;
    return VESmail_imap_track_out(&VESMAIL_IMAP(srv)->reqq);
}

int VESmail_imap_req_fwd(VESmail_server *srv, VESmail_imap_token *req) {
    if (req) {
	if (VESMAIL_IMAP(srv)->cont && VESMAIL_IMAP(srv)->cont != req) return VESMAIL_E_PARAM;
	VESMAIL_IMAP(srv)->cont = req;
    }
    if (!VESMAIL_IMAP(srv)->cont) return 0;
    int r = VESmail_imap_token_render(VESMAIL_IMAP(srv)->cont, srv->req_out, &VESMAIL_IMAP(srv)->cont->hold);
    if (!VESMAIL_IMAP(srv)->cont->hold) {
	int r2 = VESmail_imap_req_next(srv);
	if (r2 < 0) return r2;
	r += r2;
    }
    return r;
}

int VESmail_imap_req_abort(VESmail_server *srv) {
    if (srv->req_in->imap->line && srv->req_in->imap->line->state == VESMAIL_IMAP_P_CONT) {
	srv->req_in->imap->state = srv->req_in->imap->state == VESMAIL_IMAP_X_HOLD ? VESMAIL_IMAP_X_ABORT : VESMAIL_IMAP_X_FFWD;
	if (VESMAIL_IMAP(srv)->cont == srv->req_in->imap->line) return VESmail_imap_req_next(srv);
    }
    return 0;
}

int VESmail_imap_rsp_send_bad(VESmail_server *srv, VESmail_imap_token *tag, const char *msg) {
    VESmail_imap_token *rsp = VESmail_imap_rsp_new(tag, "BAD");
    if (msg) VESmail_imap_token_push(rsp, VESmail_imap_token_atom(msg));
    int r = VESmail_imap_rsp_send(srv, rsp);
    VESmail_imap_token_free(rsp);
    return r;
}

int VESmail_imap_rsp_send_error(VESmail_server *srv, VESmail_imap_token *tag, int err) {
    VESmail_imap_token *rsp = VESmail_imap_rsp_new(tag, "NO");
    char *str = VESmail_server_errorStr(srv, err);
    if (str) VESmail_imap_token_push(rsp, VESmail_imap_token_atom(str));
    free(str);
    int r = VESmail_imap_rsp_send(srv, rsp);
    VESmail_imap_token_free(rsp);
    return r;
}

VESmail_imap_token *VESmail_imap_req_detach(VESmail_server *srv, VESmail_imap_token *token) {
    return VESmail_imap_xform_detach(srv->req_in, token);
}

VESmail_imap_token *VESmail_imap_rsp_detach(VESmail_server *srv, VESmail_imap_token *token) {
    return VESmail_imap_xform_detach(srv->rsp_in, token);
}

int VESmail_imap_cont(VESmail_server *srv, const char *msg) {
    if (srv->req_in->imap->state != VESMAIL_IMAP_X_HOLD) return 0;
    VESmail_imap_token *rsp = VESmail_imap_rsp_new(VESmail_imap_token_atom("+"), msg);
    int r = VESmail_imap_rsp_send(srv, rsp);
    VESmail_imap_token_free(rsp);
    srv->req_in->imap->state = VESMAIL_IMAP_X_INIT;
    return r;
}

VESmail_imap_token *VESmail_imap_cp_tag(VESmail_imap_token *cmd) {
    if (cmd && cmd->type == VESMAIL_IMAP_T_LINE && cmd->len > 0) {
	VESmail_imap_token *tg = cmd->list[0];
	if (tg->type == VESMAIL_IMAP_T_ATOM && tg->len > 0 && tg->data[0] != '+') {
	    VESmail_imap_token *rtg = VESmail_imap_token_new(VESMAIL_IMAP_T_ATOM, tg->len);
	    memcpy(rtg->data, tg->data, (rtg->len = tg->len));
	    return rtg;
	}
    }
    return NULL;
}

VESmail_imap_token *VESmail_imap_req_new(VESmail_imap_token *tag, const char *verb) {
    static unsigned int tagno = 0;
    if (!tag) {
	char tagstr[16];
	sprintf(tagstr, "ves%03d", ++tagno);
	tag = VESmail_imap_token_atom(tagstr);
    }
    VESmail_imap_token *req = VESmail_imap_token_line();
    VESmail_imap_token_push(req, tag);
    VESmail_imap_token_push(req, VESmail_imap_token_atom(verb));
    return req;
}

VESmail_imap_token *VESmail_imap_rsp_new(VESmail_imap_token *tag, const char *verb) {
    VESmail_imap_token *rsp = VESmail_imap_token_line();
    VESmail_imap_token_push(rsp, tag ? tag : VESmail_imap_token_atom("*"));
    if (verb) VESmail_imap_token_push(rsp, VESmail_imap_token_atom(verb));
    return rsp;
}

#define VESMAIL_VERB(verb)	#verb,
const char *VESmail_imap_verbs[] = { VESMAIL_IMAP_VERBS() NULL };
#undef VESMAIL_VERB

int VESmail_imap_get_verb(VESmail_imap_token *token, const char **verbs) {
    char ucbuf[128];
    if (token && token->type == VESMAIL_IMAP_T_ATOM && token->len > 0 && token->len < sizeof(ucbuf)) {
	const char *s = token->data;
	const char *tail = s + token->len;
	char *d = ucbuf;
	while (s < tail) {
	    char c = *s++;
	    *d++ = c >= 'a' && c <= 'z' ? c - 0x20 : c;
	}
	*d = 0;
	const char **v;
	for (v = verbs; *v; v++) if (!strcmp(*v, ucbuf)) return v - verbs;
    }
    return VESMAIL_E_UNKNOWN;
}

VESmail_imap_token *VESmail_imap_caps(VESmail_server *srv, VESmail_imap_token *token, int start) {
    if (!token) token = VESmail_imap_token_list(0);
    if (start) {
	VESmail_imap_token_splice(token, -1, 0, 4,
	    VESmail_imap_token_atom("IMAP4rev1"),
	    VESmail_imap_token_atom("LITERAL+"),
	    VESmail_imap_token_atom("SASL-IR"),
	    VESmail_imap_token_atom("ID")
	);
	if (VESmail_tls_server_allow_starttls(srv)) {
	    VESmail_imap_token_splice(token, -1, 0, 1, VESmail_imap_token_atom("STARTTLS"));
	}
	if (VESmail_tls_server_allow_plain(srv)) {
	    int i;
	    char buf[48];
	    for (i = 0; i <= VESMAIL_SASL_SRV_LAST; i++) {
		sprintf(buf, "AUTH=%.42s", VESmail_sasl_mechs[i]);
		VESmail_imap_token_splice(token, -1, 0, 1, VESmail_imap_token_atom(buf));
	    }
	}
    }
    VESmail_imap_token_splice(token, -1, 0, 1, VESmail_imap_token_atom("XVES"));
    return token;
}

void VESmail_imap_debug(VESmail_server *srv, const char *msg) {
    VESmail_imap_token *rsp = VESmail_imap_rsp_new(NULL, "XDEBUG");
    VESmail_imap_token_push(rsp, VESmail_imap_token_atom(msg));
    VESmail_imap_rsp_send(srv, rsp);
    VESmail_imap_token_free(rsp);
}

void VESmail_imap_debug_token(VESmail_server *srv, int lvl, const char *label, VESmail_imap_token *token) {
    if (srv->debug < lvl || token->state == VESMAIL_IMAP_P_CONT) return;
    VESmail_imap_token *rsp = VESmail_imap_rsp_new(NULL, "XDEBUG");
    if (label) VESmail_imap_token_push(rsp, VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, label));
    VESmail_imap_token *t = VESmail_imap_token_clone(token);
    if (t) {
	if (t->type == VESMAIL_IMAP_T_LINE) t->type = VESMAIL_IMAP_T_INDEX;
	VESmail_imap_token_push(rsp, t);
    }
    VESmail_imap_rsp_send(srv, rsp);
    VESmail_imap_token_free(rsp);
}

int VESmail_imap_rsp_fn(VESmail_server *srv, VESmail_imap_token *token) {
    VESmail_imap *imap = VESMAIL_IMAP(srv);
    srv->rsp_in->imap->state = VESMAIL_IMAP_X_INIT;
    int verb = VESMAIL_E_UNKNOWN;
    VESmail_imap_track **trkptr = NULL;
    if (token->len > 0) {
	if (token->len > 1) verb = VESmail_imap_get_verb(token->list[1], VESmail_imap_verbs);
	if (token->list[0]->type == VESMAIL_IMAP_T_ATOM) {
	    int l = token->list[0]->len;
	    if (l) {
		switch (l == 1 ? token->list[0]->data[0] : 0) {
		    case '*':
			switch (verb) {
			    case VESMAIL_IMAP_V_OK:
			    case VESMAIL_IMAP_V_NO:
			    case VESMAIL_IMAP_V_BAD:
				trkptr = VESmail_imap_track_match(&imap->track, "*", 1);
			    default:
				break;
			}
			if (!trkptr && verb == VESMAIL_IMAP_V_BAD) imap->ctBad++;
			break;
		    case '+': {
			if (srv->sasl) return VESmail_imap_start_sasl_cont(srv, (token->len == 2 ? token->list[1] : NULL));
			int hld = imap->cont && imap->cont->hold;
			if (hld && imap->cont->hold->literal) return VESmail_imap_req_fwd(srv, NULL);
			srv->flags &= ~VESMAIL_SRVF_OVER;
			if (!hld) VESMAIL_IMAP(srv)->flags |= VESMAIL_IMAP_F_CDATA;
			else if (srv->req_in->imap->state != VESMAIL_IMAP_X_HOLD) return 0;
			srv->req_in->imap->state = VESMAIL_IMAP_X_INIT;
			break;
		    }
		    default:
			trkptr = VESmail_imap_track_match(&imap->track, token->list[0]->data, l);
			break;
		}
	    }
	}
    }
    int rs;
    if (trkptr) {
	int curr = !(*trkptr)->chain && VESMAIL_IMAP(srv)->cont;
	VESmail_imap_track *trk = VESmail_imap_track_unlink(trkptr);
	rs = trk->rspfn(verb, token, trk);
	if (curr && rs >= 0) {
	    int r = VESmail_imap_req_abort(srv);
	    if (r >= 0) rs += r;
	    else rs = r;
	}
    } else {
	rs = imap->untaggedfn(verb, token, srv);
    }
    if (imap->ctBad > 0) {
	int ct = imap->ctBad;
	VESmail_imap_track *t = imap->track;
	while (t && ct-- > 0) t = t->chain;
	if (ct >= 0) {
	    while (imap->track) VESmail_imap_track_done(&imap->track);
	    imap->ctBad = 0;
	}
    }
    if (!imap->track && !(imap->flags & VESMAIL_IMAP_F_BYE)) srv->flags &= ~VESMAIL_SRVF_OVER;
    return rs;
}

void VESmail_imap_reset(VESmail_server *srv) {
    VESmail_imap *imap = VESMAIL_IMAP(srv);
    VESMAIL_SRV_DEBUG(srv, 2, sprintf(debug, "[reset] msgs.page.depth=%d", imap->msgs.depth))
    VESmail_imap_msg_page_free(&imap->msgs.page, imap->msgs.depth, imap->msgs.pagesize);
    imap->msgs.page.ptr = NULL;
    imap->msgs.depth = 0;
}

void VESmail_imap_fn_free(VESmail_server *srv) {
    VESmail_imap *imap = VESMAIL_IMAP(srv);
    VESmail_imap_reset(srv);
    while (imap->track) VESmail_imap_track_done(&imap->track);
    while (imap->results.track) VESmail_imap_track_done(&imap->results.track);
    VESmail_imap_result_free(imap->results.curr);
    VESmail_imap_msg_free(imap->results.pass);
    VESmail_imap_token_free(imap->results.query);
}

VESmail_server *VESmail_server_new_imap(VESmail_optns *optns) {
    VESmail_server *srv = VESmail_server_init(malloc(sizeof(VESmail_server) + sizeof(VESmail_imap)), optns);
    VESmail_imap *imap = VESMAIL_IMAP(srv);
    srv->debugfn = &VESmail_imap_debug;
    srv->freefn = &VESmail_imap_fn_free;
    imap->untaggedfn = NULL;
    imap->state = VESMAIL_IMAP_S_HELLO;
    imap->flags = VESMAIL_IMAP_F_INIT;
    imap->cont = NULL;
    imap->track = NULL;
    imap->reqq = NULL;
    imap->ctBad = 0;
    imap->ctOOR = -(VESMAIL_IMAP_OOR_SENSE);

    imap->msgs.page.ptr = NULL;
    imap->msgs.depth = 0;
    imap->msgs.pagesize = 256;

    imap->results.queue = NULL;
    imap->results.tail = &imap->results.queue;
    imap->results.track = NULL;
    imap->results.curr = NULL;
    imap->results.filter = NULL;
    imap->results.pass = NULL;
    imap->results.query = NULL;

    srv->req_in = VESmail_xform_new_imap(srv, &VESmail_imap_start_req_fn);

    srv->rsp_in = VESmail_xform_new_imap(srv, &VESmail_imap_rsp_fn);

    srv->rsp_out = NULL;
    return srv;
}
