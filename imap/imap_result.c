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
#include "../VESmail.h"
#include "../srv/server.h"
#include "../lib/mail.h"
#include "../lib/xform.h"
#include "imap.h"
#include "imap_token.h"
#include "imap_msg.h"
#include "imap_fetch.h"
#include "imap_track.h"
#include "imap_proxy.h"
#include "imap_xform.h"
#include "imap_result.h"

VESmail_imap_result *VESmail_imap_result_link(VESmail_imap_result *rslt) {
    if (*(rslt->msgptr) && *(rslt->msgptr) != &VESmail_imap_msg_PASS) {
	rslt->mchain = (*(rslt->msgptr))->result;
	(*(rslt->msgptr))->result = rslt;
    }
    return rslt;
}

int VESmail_imap_result_chkbug(void *rslt, VESmail_imap_msg *msg, VESmail_imap_fetch *fetch) {
    if (msg->flags & VESMAIL_IMAP_MF_CHKBUG) {
	msg->flags = (msg->flags & ~(VESMAIL_IMAP_MF_CHKBUG | VESMAIL_IMAP_MF_HDR)) | VESMAIL_IMAP_MF_CFMBUG;
	return 1;
    }
    return 0;
}

void VESmail_imap_result_entry_free(struct VESmail_imap_result_entry *entry) {
    if (entry) VESmail_imap_fetch_free(entry->fetch);
    free(entry);
}

int VESmail_imap_result_update(VESmail_imap_result *rslt) {
    struct VESmail_imap_result_entry **entp = &rslt->entry;
    VESmail_imap_token *lst = rslt->token->list[3]->list[0];
    int st = VESMAIL_IMAP_RE_OK;
    rslt->fdrop = 0;
    int idx;
    int rs = 0;
    for (idx = 0; idx + 1 < lst->len; ) {
	struct VESmail_imap_result_entry *ent;
	while (1) {
	    ent = *entp;
	    if (!ent || ent->state != VESMAIL_IMAP_RE_DROPD) break;
	    entp = &ent->chain;
	}
	if (!ent) {
	    *entp = ent = malloc(sizeof(**entp));
	    ent->chain = NULL;
	    ent->fetch = VESmail_imap_fetch_parse(lst->list[idx]);
	    ent->state = VESMAIL_IMAP_RE_UNDEF;
	}
	int cpl = rslt->token->state != VESMAIL_IMAP_P_CONT || idx + 2 < lst->len;
	VESmail_imap_token *val = lst->list[idx + 1];
	if (val->state == VESMAIL_IMAP_P_ERROR) {
	    ent->state = VESMAIL_IMAP_RE_DROP;
	    VESmail_imap_msg *msg;
	    if ((msg = *rslt->msgptr) && msg != &VESmail_imap_msg_PASS) msg->flags |= VESMAIL_IMAP_MF_ERROR;
	    VESMAIL_SRV_DEBUG(rslt->server, 1, {
		char *er = VESmail_server_errorStr(rslt->server, VESmail_imap_token_error(val));
		sprintf(debug, "[xform error] %.160s", er);
		free(er);
	    })
	}
	switch (ent->state) {
	    case VESMAIL_IMAP_RE_UNDEF:
	    case VESMAIL_IMAP_RE_REQ:
		ent->state = VESmail_imap_result_process(rslt, ent->fetch, lst->list[idx], val, cpl);
	    default:
		break;
	}
	switch (ent->state) {
	    case VESMAIL_IMAP_RE_SYNC:
		if (st == VESMAIL_IMAP_RE_OK) {
		    VESmail_imap_xform_sync(rslt->server->rsp_in)->chain = rslt->server->rsp_out;
		    rs = VESmail_imap_rsp_sync(rslt->server, rslt->token);
		    ent->state = VESMAIL_IMAP_RE_SYNCD;
		} else {
		    VESmail_imap_xform_sync(rslt->server->rsp_in)->chain = NULL;
		    ent->state = VESMAIL_IMAP_RE_RESYNC;
		}
	    default:
		break;
	}
	switch (ent->state) {
	    case VESMAIL_IMAP_RE_CDROP:
		if (!rslt->fdrop) {
		    ent->state = cpl ? VESMAIL_IMAP_RE_OK : VESMAIL_IMAP_RE_UNDEF;
		    break;
		}
		ent->state = VESMAIL_IMAP_RE_DROP;
	    case VESMAIL_IMAP_RE_DROP:
		rslt->fdrop = 1;
		if (!cpl) break;
		ent->state = VESMAIL_IMAP_RE_DROPD;
		VESmail_imap_token_splice(lst, idx, 2, 0);
		continue;
	    case VESMAIL_IMAP_RE_RESYNC:
	    case VESMAIL_IMAP_RE_SILENT:
		if (st == VESMAIL_IMAP_RE_UNDEF) break;
	    case VESMAIL_IMAP_RE_UNDEF:
		if (st == VESMAIL_IMAP_RE_REQ) break;
	    case VESMAIL_IMAP_RE_REQ:
		st = ent->state;
	    case VESMAIL_IMAP_RE_OK:
	    case VESMAIL_IMAP_RE_SYNCD:
		break;
	    default:
		rslt->state = ent->state;
		return 0;
	}
	entp = &ent->chain;
	idx += 2;
    }
    if (rslt->token->state != VESMAIL_IMAP_P_CONT) {
	rslt->state = st;
    }
    return rs;
}

void VESmail_imap_result_chkreq(VESmail_imap_result *rslt) {
    VESmail_imap *imap = VESMAIL_IMAP(rslt->server);
    if (rslt->state == VESMAIL_IMAP_RE_REQ && !imap->results.query) {
	imap->results.query = VESmail_imap_token_list(0);
	VESmail_imap_result_update(rslt);
    }
}

int VESmail_imap_result_sendreq(VESmail_imap_result *rslt) {
    int rs = 0;
    VESmail_imap *imap = VESMAIL_IMAP(rslt->server);
    if (imap->results.query && imap->results.query->len > 0) {
	VESmail_imap_token *req = VESmail_imap_req_new(NULL, "FETCH");
	VESmail_imap_token_splice(req, -1, 0, 2,
	    VESmail_imap_token_clone(rslt->token->list[1]),
	    VESmail_imap_token_splice(VESmail_imap_token_new(VESMAIL_IMAP_T_LSET, 0), 0, 0, 1, imap->results.query)
	);
	VESmail_imap_debug_token(rslt->server, 1, ">>>>", req);
	rs = VESmail_imap_proxy_req_send(rslt->server, req);
    } else {
	VESmail_imap_token_free(imap->results.query);
    }
    imap->results.query = NULL;
    return rs;
}

int VESmail_imap_result_fn_rsp_resync(int verb, VESmail_imap_token *rsp, VESmail_imap_track *trk) {
    VESmail_server *srv = trk->server;
    VESmail_imap_debug_token(srv, 1, "<<<<", rsp);
    VESmail_imap_result *rslt = trk->ref;
    rslt->state = VESMAIL_IMAP_RE_DROP;
    VESmail_imap_track_free(trk);
    if (rslt->msgptr && *rslt->msgptr != &VESmail_imap_msg_PASS) {
	VESmail_imap_result **ptr;
	for (ptr = &(*(rslt->msgptr))->result; *ptr; ptr = &(*ptr)->mchain) {
	    if (*ptr == rslt) {
		*ptr = rslt->mchain;
		break;
	    }
	}
    }
    return VESmail_imap_result_flush(VESMAIL_IMAP(srv));
}

int VESmail_imap_result_commit(VESmail_imap_result *rslt) {
    if (!rslt) return VESMAIL_E_PARAM;
    VESmail_imap_rsp_detach(rslt->server, rslt->token);
    VESmail_imap *imap = VESMAIL_IMAP(rslt->server);
    int rs = 0;
    VESmail_imap_result_chkreq(rslt);
    VESmail_imap_result **ptr;
    VESmail_imap_msg *msg;
    if (rslt->msgptr && (msg = *(rslt->msgptr)) && msg != &VESmail_imap_msg_PASS) {
	if (msg->rcount >= VESMAIL_IMAP_MSG_RESULTBUF && rslt->state != VESMAIL_IMAP_RE_OK) {
	    VESmail_imap_debug_token(rslt->server, 1, "[overflow] dropping a result", rslt->token);
	    rslt->state = VESMAIL_IMAP_RE_DROP;
	    msg->rcount--;
	}
	rslt->mchain = *(ptr = &msg->result);
    } else {
	rslt->mchain = NULL;
	ptr = NULL;
	msg = NULL;
    }
    VESmail_imap_result *rr = rslt;
    VESmail_imap_result *rq = NULL;
    int ct = 0;
    while (1) {
	VESmail_imap_result *next = rr->mchain;
	switch (rr->state) {
	    case VESMAIL_IMAP_RE_RESYNC: {
		struct VESmail_imap_result_entry *re;
		VESmail_imap_token *lst = VESmail_imap_token_list(0);
		VESmail_imap_fetch *f = NULL;
		int idx = 0;
		int sidx = 0;
		for (re = rr->entry; re; re = re->chain) {
		    f = re->fetch;
		    switch (re->state) {
			case VESMAIL_IMAP_RE_DROPD:
			    if (!f || f->stype != VESMAIL_IMAP_FS_HEADER_FIELDS) continue;
			    break;
			case VESMAIL_IMAP_RE_SYNCD:
			    sidx = idx + 2;
			default:
			    idx += 2;
			    break;
		    }
		    if (!f) break;
		    if (f->type == VESMAIL_IMAP_FV_BODY && f->mode != VESMAIL_IMAP_FM_NONE) f->type = VESMAIL_IMAP_FV_BODY_PEEK;
		    VESmail_imap_token_splice(lst, -1, 0, 1, VESmail_imap_fetch_render(f));
		}
		if (f && rr->token) {
		    VESmail_imap_token *req = VESmail_imap_req_new(NULL, "FETCH");
		    VESmail_imap_token_splice(req, -1, 0, 2,
			VESmail_imap_token_clone(rr->token->list[1]),
			lst
		    );
		    VESmail_imap_debug_token(rr->server, 1, "resync >>>>", req);
		    VESmail_imap_track *trk = VESmail_imap_track_new_queue(rr->server, req);
		    trk->ref = rr;
		    trk->rspfn = &VESmail_imap_result_fn_rsp_resync;
		    if (VESmail_imap_req_ready(rr->server)) {
			int r = VESmail_imap_track_out(&imap->reqq);
			if (r < 0) rs = r;
			else rs += r;
		    }
		    rr->state = VESMAIL_IMAP_RE_RESYNCD;
		} else {
		    VESmail_imap_token_free(lst);
		    VESmail_imap_result_free(rr);
		    break;
		}
		if (sidx && rs >= 0) {
		    VESmail_imap_token *lst = rr->token->list[3];
		    if (VESmail_imap_token_isLSet(lst)) {
			lst = lst->list[0];
			VESmail_imap_token_splice(lst, sidx, lst->len - sidx, 0);
			int r = VESmail_imap_result_send(rr);
			if (r < 0) rs = r;
			rs += r;
		    }
		}
		if (rs < 0) return rs;
	    }
	    case VESMAIL_IMAP_RE_REQ:
	    case VESMAIL_IMAP_RE_UNDEF:
	    case VESMAIL_IMAP_RE_RESYNCD:
		if (rr->state == VESMAIL_IMAP_RE_REQ) rq = rr;
		if (ptr) {
		    *ptr = rr;
		    ptr = &rr->mchain;
		    ct++;
		}
		break;
	    case VESMAIL_IMAP_RE_SYNCD:
	    case VESMAIL_IMAP_RE_OK: {
		if (imap->flags & VESMAIL_IMAP_F_ORDER) break;
		int r = VESmail_imap_result_send(rr);
		if (r < 0) return r;
		rs += r;
	    }
	    default:
		VESmail_imap_result_free(rr);
		break;
	}
	if ((rr = next)) {
	    switch (rr->state) {
		case VESMAIL_IMAP_RE_OK:
		case VESMAIL_IMAP_RE_SYNCD:
		case VESMAIL_IMAP_RE_RESYNCD:
		case VESMAIL_IMAP_RE_DROP:
		    break;
		default:
		    VESmail_imap_result_update(rr);
		    VESmail_imap_result_chkreq(rr);
		    break;
	    }
	} else {
	    if (ptr) *ptr = NULL;
	    break;
	}
    }
    int r = rq ? VESmail_imap_result_sendreq(rq) : 0;
    if (r < 0) return r;
    rs += r;
    if (msg) {
	if (ct) msg->rcount++;
	else msg->rcount = 0;
    }
    while (ct > VESMAIL_IMAP_MSG_RESULTBUF) {
	ptr = &(*(rslt->msgptr))->result;
	VESmail_imap_result *next = (*ptr)->mchain;
	VESmail_imap_result_free(*ptr);
	*ptr = next;
	ct--;
    }
    r = VESmail_imap_result_flush(imap);
    if (r < 0) return r;
    rs += r;
    return rs;
}

int VESmail_imap_result_send(VESmail_imap_result *rslt) {
    if (rslt->token && rslt->token->list[3]->list[0]->len) {
	int r = VESmail_imap_rsp_sync(rslt->server, rslt->token);
	VESmail_imap_token_free(rslt->token);
	rslt->token = NULL;
	return r;
    } else return 0;
}

int VESmail_imap_result_flush(VESmail_imap *imap) {
    int rs = 0;
    VESmail_imap_result *rslt;
    while ((rslt = imap->results.queue)) {
	switch (rslt->state) {
	    case VESMAIL_IMAP_RE_REQ:
	    case VESMAIL_IMAP_RE_UNDEF:
	    case VESMAIL_IMAP_RE_RESYNCD:
		return rs;
	    case VESMAIL_IMAP_RE_OK: {
		int r = VESmail_imap_result_send(rslt);
		if (r < 0) return r;
		rs += r;
	    }
	    default: 
		break;
	}
	VESmail_imap_result_free(rslt);
    }
    VESmail_imap_track *trk;
    while ((trk = imap->results.track)) {
	int r = VESmail_imap_track_send_rsp(trk);
	if (r < 0) return r;
	rs += r;
	imap->results.track = trk->chain;
	VESmail_imap_track_free(trk);
    }
    return rs;
}

void VESmail_imap_result_free(VESmail_imap_result *rslt) {
    if (rslt) {
	struct VESmail_imap_result_entry *entry, *next;
	for (entry = rslt->entry; entry; entry = next) {
	    next = entry->chain;
	    VESmail_imap_result_entry_free(entry);
	}
	VESmail_imap_token_free(rslt->token);
	while (rslt->range) VESmail_imap_fetch_free(VESmail_imap_fetch_unqueue(&rslt->range));
	if ((*(rslt->sprev) = rslt->schain)) {
	    rslt->schain->sprev = rslt->sprev;
	} else {
	    VESMAIL_IMAP(rslt->server)->results.tail = rslt->sprev;
	}
	VESMAIL_IMAP(rslt->server)->results.qbytes -= rslt->qbytes;
    }
    free(rslt);
}

VESmail_imap_result *VESmail_imap_result_new(VESmail_imap_token *rsp, VESmail_server *srv) {
    unsigned int seq;
    if (VESmail_imap_token_getuint(rsp->list[1], &seq) >= 0) {
	VESmail_imap_msg **msgptr = VESmail_imap_msg_ptr(VESMAIL_IMAP(srv), seq);
	if (msgptr) {
	    VESmail_imap_result *rslt = malloc(sizeof(VESmail_imap_result));
	    rslt->server = srv;
	    rslt->token = rsp;
	    rslt->schain = NULL;
	    *(rslt->sprev = VESMAIL_IMAP(srv)->results.tail) = rslt;
	    VESMAIL_IMAP(srv)->results.tail = &rslt->schain;
	    rslt->mchain = NULL;
	    rslt->entry = NULL;
	    rslt->msgptr = msgptr;
	    rslt->state = VESMAIL_IMAP_RE_UNDEF;
	    rslt->range = NULL;
	    rslt->qbytes = 0;
	    return rslt;
	}
    }
    return NULL;
}

