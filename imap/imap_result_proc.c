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
#include "imap_sect.h"
#include "imap_xform.h"
#include "imap_result.h"

#define VESmail_imap_result_QUERY(rslt, key, msg, flg)	\
if (VESMAIL_IMAP((rslt)->server)->results.query && !((msg)->flags & (flg))) {\
    VESmail_imap_result_addqry(VESMAIL_IMAP((rslt)->server)->results.query, key);\
    (msg)->flags |= (flg);\
}

#define VESmail_imap_result_QUERYR(rslt, key, msg, flg, rs)	VESmail_imap_result_QUERY(rslt, key, msg, flg)\
rs = VESMAIL_IMAP_RE_REQ;

#define VESmail_imap_result_QUERYRS(rslt, sub, seclen, secp, msg, flg, rs)	VESmail_imap_result_QUERYR(\
    rslt,\
    VESmail_imap_fetch_new_body(VESMAIL_IMAP_FV_BODY_PEEK, VESMAIL_IMAP_FM_SECTION, sub, seclen, secp),\
    msg, flg, rs\
)


#define VESmail_imap_result_DROP(msg, flg)	\
if ((msg)->flags & (flg)) {\
    (msg)->flags &= ~(flg);\
    return VESMAIL_IMAP_RE_DROP;\
}

#define VESmail_imap_result_DECRYPT(rs, ...)	(VESmail_imap_msg_decrypt(__VA_ARGS__) >= 0 || ((rs = VESMAIL_IMAP_RE_RESYNC), 0))

void VESmail_imap_result_addqry(VESmail_imap_token *qry, VESmail_imap_fetch *key) {
    VESmail_imap_token *tk = VESmail_imap_fetch_render(key);
    int i;
    for (i = 0; tk && i < qry->len; i++) {
	if (VESmail_imap_token_eq(qry->list[i], tk)) {
	    VESmail_imap_token_free(tk);
	    tk = NULL;
	}
    }
    if (tk) VESmail_imap_token_splice(qry, -1, 0, 1, tk);
    VESmail_imap_fetch_free(key);
}

int VESmail_imap_result_addqry_sect(void *rslt, VESmail_imap_msg *msg, VESmail_imap_fetch *fetch) {
    if (msg->flags & VESMAIL_IMAP_MF_HDR) return 0;
    if (!(msg->flags & VESMAIL_IMAP_MF_ROOT)) {
	VESmail_imap_result_QUERY((VESmail_imap_result *) rslt,
	    VESmail_imap_fetch_new_body(VESMAIL_IMAP_FV_BODY_PEEK, VESMAIL_IMAP_FM_SECTION, VESMAIL_IMAP_FS_MIME, fetch->seclen, fetch->section),
	    msg, VESMAIL_IMAP_MF_QHDR
	)
	msg = (msg->flags & VESMAIL_IMAP_MF_RFC822) ? msg->rfc822 : NULL;
    }
    if (msg) VESmail_imap_result_QUERY((VESmail_imap_result *) rslt,
	VESmail_imap_fetch_new_body(VESMAIL_IMAP_FV_BODY_PEEK, VESMAIL_IMAP_FM_SECTION, VESMAIL_IMAP_FS_HEADER, fetch->seclen, fetch->section),
	msg, VESMAIL_IMAP_MF_QHDR
    )
    return 1;
}

int VESmail_imap_result_process(VESmail_imap_result *rslt, VESmail_imap_fetch *fetch, VESmail_imap_token *key, VESmail_imap_token *val, int final) {
    VESmail_imap_msg *msg = *rslt->msgptr;
    int rs = VESMAIL_IMAP_RE_OK;
    if (!fetch) return rs;
    switch (fetch->type) {
	case VESMAIL_IMAP_FV_BODY:
	case VESMAIL_IMAP_FV_BODY_PEEK:
	    break;
	case VESMAIL_IMAP_FV_BODYSTRUCTURE:
	    if (msg == &VESmail_imap_msg_PASS) return VESMAIL_IMAP_RE_OK;
	    break;
	default:
	    if (VESmail_imap_msg_pass(msg)) return VESMAIL_IMAP_RE_OK;
	    break;
    }
    switch (fetch->type) {
	case VESMAIL_IMAP_FV_BODYSTRUCTURE:
	case VESMAIL_IMAP_FV_ENVELOPE:
	    if (!final) return VESMAIL_IMAP_RE_UNDEF;
	case VESMAIL_IMAP_FV_RFC822_HEADER:
	case VESMAIL_IMAP_FV_RFC822_TEXT:
	case VESMAIL_IMAP_FV_RFC822:
	case VESMAIL_IMAP_FV_BODY:
	case VESMAIL_IMAP_FV_BODY_PEEK:
	    break;
	case VESMAIL_IMAP_FV_RFC822_SIZE:
	    if (VESMAIL_IMAP(rslt->server)->flags & VESMAIL_IMAP_F_CALC) break;
	    if (msg && (msg->flags & VESMAIL_IMAP_MF_BODY)) break;
	default:
	    return VESMAIL_IMAP_RE_OK;
    }
    if (!msg) msg = *rslt->msgptr = VESmail_imap_msg_new(rslt->server);
    else if (msg != &VESmail_imap_msg_PASS && (msg->flags & VESMAIL_IMAP_MF_ERROR)) return VESMAIL_IMAP_RE_DROP;
    int ffull = -1;
    switch (fetch->type) {
	case VESMAIL_IMAP_FV_RFC822_HEADER:
	case VESMAIL_IMAP_FV_RFC822: {
	    VESmail_imap_result_DECRYPT(rs, msg, msg,
		(fetch->type == VESMAIL_IMAP_FV_RFC822 ? VESMAIL_IMAP_MF_PHDR | VESMAIL_IMAP_MF_PBODY : VESMAIL_IMAP_MF_PHDR),
		val, NULL);
	    break;
	}
	case VESMAIL_IMAP_FV_RFC822_TEXT: {
	    if (msg->flags & VESMAIL_IMAP_MF_HDR) {
		VESmail_imap_result_DECRYPT(rs, msg, msg, VESMAIL_IMAP_MF_HDR | VESMAIL_IMAP_MF_PBODY, val, NULL);
	    } else {
		VESmail_imap_result_QUERYRS(rslt, VESMAIL_IMAP_FS_HEADER, 0, NULL, msg, VESMAIL_IMAP_MF_QHDR, rs)
	    }
	    break;
	}
	case VESMAIL_IMAP_FV_RFC822_SIZE:
	    if (msg->flags & VESMAIL_IMAP_MF_BODY) {
		char buf[16];
		sprintf(buf, "%lu", msg->hbytes + msg->bbytes);
		int l = strlen(buf);
		if (l <= val->len) {
		    memcpy(VESmail_imap_token_data(val), buf, (val->len = l));
		}
	    } else {
		VESmail_imap_result_QUERYRS(rslt, VESMAIL_IMAP_FS_NONE, 0, NULL, msg, VESMAIL_IMAP_MF_QBODY, rs)
	    }
	    break;
	case VESMAIL_IMAP_FV_BODYSTRUCTURE:
	    if (!(msg->flags & VESMAIL_IMAP_MF_STRUCT)) {
		msg->flags |= VESMAIL_IMAP_MF_STRUCT;
		VESmail_imap_sect_learn(val, msg);
	    }
	    VESmail_imap_result_DROP(msg, VESMAIL_IMAP_MF_QSTRUCT)
	case VESMAIL_IMAP_FV_BODY:
	case VESMAIL_IMAP_FV_BODY_PEEK:
	    if ((VESMAIL_IMAP(rslt->server)->flags & VESMAIL_IMAP_F_MIMEBUG)
		&& fetch->seclen
		&& !VESmail_imap_msg_pass(msg)
		&& !(msg->flags & VESMAIL_IMAP_MF_BODY)
	    ) {
		VESmail_imap_result_QUERYRS(rslt, VESMAIL_IMAP_FS_NONE, 0, NULL, msg, VESMAIL_IMAP_MF_QBODY, rs)
		break;
	    }
	    switch (fetch->mode) {
		case VESMAIL_IMAP_FM_NONE: {
		    if (VESmail_imap_msg_pass(msg)) return VESMAIL_IMAP_RE_OK;
		    if (!final) return VESMAIL_IMAP_RE_UNDEF;
		    if (fetch->type != VESMAIL_IMAP_FV_BODYSTRUCTURE) {
			if (!(msg->flags & (VESMAIL_IMAP_MF_STRUCT | VESMAIL_IMAP_MF_PASS))) {
			    VESmail_imap_sect_learn(val, msg);
			}
			if (!(msg->flags & VESMAIL_IMAP_MF_STRUCT)) {
			    VESmail_imap_result_QUERYR(rslt, VESmail_imap_fetch_new(VESMAIL_IMAP_FV_BODYSTRUCTURE), msg, VESMAIL_IMAP_MF_QSTRUCT, rs)
			}
		    }
		    if (VESmail_imap_msg_pass(msg)) return VESMAIL_IMAP_RE_OK;
		    if ((VESMAIL_IMAP(rslt->server)->flags & (VESMAIL_IMAP_F_CALC | VESMAIL_IMAP_F_MIMEBUG)) && !(msg->flags & VESMAIL_IMAP_MF_BODY)) {
			VESmail_imap_result_QUERYRS(rslt, VESMAIL_IMAP_FS_NONE, 0, NULL, msg, VESMAIL_IMAP_MF_QBODY, rs)
			return rs;
		    }
		    int r = VESmail_imap_sect_traverse(msg, &VESmail_imap_result_addqry_sect, rslt);
		    if (r > 0) return VESMAIL_IMAP_RE_REQ;
		    if (msg->flags & VESMAIL_IMAP_MF_STRUCT) VESmail_imap_sect_apply(val, msg);
		    break;
		}
		case VESMAIL_IMAP_FM_START:
		case VESMAIL_IMAP_FM_RANGE:
		    ffull = 0;
		default: {
		    VESmail_imap_msg *secm, *sech;
		    if (VESmail_imap_msg_pass(msg)) {
			secm = sech = NULL;
		    } else if (fetch->seclen) {
			if (msg->flags & VESMAIL_IMAP_MF_STRUCT) {
			    secm = VESmail_imap_msg_section(msg, fetch->seclen, fetch->section);
			    if (!secm) {
				if (final) val->len = 0;
				switch (fetch->stype) {
				    case VESMAIL_IMAP_FS_HEADER:
				    case VESMAIL_IMAP_FS_MIME:
					return VESMAIL_IMAP_RE_CDROP;
				    default:
					if (!final) return VESMAIL_IMAP_RE_UNDEF;
				}
				break;
			    }
			    sech = VESmail_imap_msg_isRFC822(secm) ? secm->sections : NULL;
			} else {
			    secm = sech = NULL;
			    VESmail_imap_result_QUERYR(rslt, VESmail_imap_fetch_new(VESMAIL_IMAP_FV_BODYSTRUCTURE), msg, VESMAIL_IMAP_MF_QSTRUCT, rs)
			    switch (fetch->stype) {
				case VESMAIL_IMAP_FS_NONE:
				case VESMAIL_IMAP_FS_TEXT:
				    VESmail_imap_result_QUERYR(
					rslt,
					VESmail_imap_sect_regqry(
					    VESmail_imap_fetch_new_body(
						VESMAIL_IMAP_FV_BODY_PEEK,
						VESMAIL_IMAP_FM_SECTION,
						(fetch->stype == VESMAIL_IMAP_FS_TEXT
						    ? VESMAIL_IMAP_FS_HEADER
						    : VESMAIL_IMAP_FS_MIME
						),
						fetch->seclen,
						fetch->section
					    ), msg
					), msg, 0, rs
				    )
				default:
				    break;
			    }
			}
			switch (fetch->stype) {
			    case VESMAIL_IMAP_FS_TEXT:
				if (sech && !(sech->flags & VESMAIL_IMAP_MF_HDR)) {
				    VESmail_imap_result_QUERYRS(rslt, VESMAIL_IMAP_FS_HEADER, fetch->seclen, fetch->section, sech, VESMAIL_IMAP_MF_QHDR, rs)
				}
				break;
			    case VESMAIL_IMAP_FS_NONE:
				if (!sech && secm && !(secm->flags & VESMAIL_IMAP_MF_HDR)) {
				    VESmail_imap_result_QUERYRS(rslt, VESMAIL_IMAP_FS_MIME, fetch->seclen, fetch->section, secm, VESMAIL_IMAP_MF_QHDR, rs)
				}
			    default:
				break;
			}
			if (!(msg->flags & (VESMAIL_IMAP_MF_ENCD | VESMAIL_IMAP_MF_PASS)) || !VESmail_imap_msg_get_msgid(msg)) {
			    VESmail_imap_result_QUERYRS(rslt, VESMAIL_IMAP_FS_HEADER, 0, NULL, msg, VESMAIL_IMAP_MF_QHDR, rs)
			    break;
			}
		    } else {
			secm = NULL;
			sech = msg;
		    }
		    switch (fetch->stype) {
			case VESMAIL_IMAP_FS_HEADER_FIELDS:
			case VESMAIL_IMAP_FS_HEADER_FIELDS_NOT: {
			    if (rs != VESMAIL_IMAP_RE_OK) break;
			    VESmail_imap_fetch *f = VESmail_imap_fetch_parse(key);
			    if (VESmail_imap_sect_hdr_unescape(f, key, &rslt->range) > 0) {
				rs = VESMAIL_IMAP_RE_SILENT;
				VESmail_imap_fetch_free(f);
			    } else if (!*f->fields) {
				rs = VESMAIL_IMAP_RE_DROP;
				VESmail_imap_fetch_free(f);
			    } else if (sech) {
				VESmail_imap_result_DECRYPT(rs, sech, msg, 0, val, f);
			    } else {
				VESmail_imap_msg *m = VESMAIL_IMAP(rslt->server)->results.pass;
				if (!m) {
				    m = VESMAIL_IMAP(rslt->server)->results.pass = VESmail_imap_msg_new(rslt->server);
				    m->flags |= VESMAIL_IMAP_MF_PASS;
				    VESMAIL_IMAP_MAIL(m)->flags |= VESMAIL_F_PASS;
				}
				VESmail_imap_result_DECRYPT(rs, m, m, 0, val, f);
			    }
			}
			default:
			    break;
		    }
		    if (sech) switch (fetch->stype) {
			case VESMAIL_IMAP_FS_HEADER:
			    VESmail_imap_result_DECRYPT(rs, sech, msg, (VESMAIL_IMAP_MF_PHDR & ffull), val, NULL);
			    break;
			case VESMAIL_IMAP_FS_TEXT:
			    if (sech->flags & VESMAIL_IMAP_MF_HDR) {
				VESmail_imap_result_DECRYPT(rs, sech, msg, VESMAIL_IMAP_MF_HDR | (VESMAIL_IMAP_MF_PBODY & ffull), val, NULL);
			    } else {
				VESmail_imap_result_QUERYRS(rslt, VESMAIL_IMAP_FS_HEADER, fetch->seclen, fetch->section, sech, VESMAIL_IMAP_MF_QHDR, rs)
			    }
			    break;
			case VESMAIL_IMAP_FS_NONE:
			    VESmail_imap_result_DECRYPT(rs, sech, msg, ((VESMAIL_IMAP_MF_PHDR | VESMAIL_IMAP_MF_PBODY) & ffull), val, NULL);
			    secm = NULL;
			default:
			    break;
		    }
		    if (secm) switch (fetch->stype) {
			case VESMAIL_IMAP_FS_MIME:
			    if (!VESmail_imap_result_DECRYPT(rs, secm, msg, (VESMAIL_IMAP_MF_PHDR & ffull) | VESMAIL_IMAP_MF_CHKBUG, val, NULL)) {
				break;
			    }
			    if (!(VESMAIL_IMAP(rslt->server)->flags & (VESMAIL_IMAP_F_MIMEBUG | VESMAIL_IMAP_F_MIMEOK))) {
				if (secm->flags & VESMAIL_IMAP_MF_CFMBUG) {
				    if (!(msg->flags & VESMAIL_IMAP_MF_BODY)) {
					secm->flags &= ~VESMAIL_IMAP_MF_HDR;
					VESmail_imap_result_QUERYRS(rslt, VESMAIL_IMAP_FS_NONE, 0, NULL, msg, VESMAIL_IMAP_MF_QBODY, rs)
					break;
				    }
				} else if ((secm->flags & VESMAIL_IMAP_MF_VES) && !(msg->flags & VESMAIL_IMAP_MF_BODY)) {
				    rs = VESMAIL_IMAP_RE_UNDEF;
				}
			    }
			    break;
			case VESMAIL_IMAP_FS_NONE:
			    if (secm->flags & VESMAIL_IMAP_MF_HDR) {
				VESmail_imap_result_DECRYPT(rs, secm, msg, VESMAIL_IMAP_MF_HDR | (VESMAIL_IMAP_MF_PBODY & ffull), val, NULL);
			    }
			default:
			    break;
		    }
		    if (rs == VESMAIL_IMAP_RE_OK) switch (fetch->stype) {
			case VESMAIL_IMAP_FS_NONE:
			    if (sech || secm) {
				VESmail_imap_result_DROP((secm ? secm : sech), VESMAIL_IMAP_MF_QBODY)
			    }
			    break;
			case VESMAIL_IMAP_FS_HEADER:
			    if (sech) {
				VESmail_imap_result_DROP(sech, VESMAIL_IMAP_MF_QHDR)
			    } else if (msg != &VESmail_imap_msg_PASS && rslt->fdrop) rs = VESMAIL_IMAP_RE_DROP;
			    break;
			case VESMAIL_IMAP_FS_MIME:
			    if (secm) {
				VESmail_imap_result_DROP(secm, VESMAIL_IMAP_MF_QHDR)
			    } else if (msg != &VESmail_imap_msg_PASS && rslt->fdrop) rs = VESMAIL_IMAP_RE_DROP;
			default:
			    break;
		    }
		    break;
		}
	    }
	    if (VESmail_imap_token_isLiteral(val)) {
		switch (val->state) {
		    case VESMAIL_IMAP_P_SYNC:
		    case VESMAIL_IMAP_P_RESYNC:
			break;
		    default:
			if (val->len > VESMAIL_IMAP(rslt->server)->maxBufd || val->len > VESMAIL_IMAP(rslt->server)->maxQueue) {
			    if (!final && !val->xform) {
				VESmail_xform *out = VESmail_imap_token_xform_new(val);
				(out->chain = VESmail_imap_xform_sync(rslt->server->rsp_in))->chain = NULL;
				out->chain->obj = out;
				VESmail_imap_token_xform_apply(val, out);
				val->state = VESMAIL_IMAP_P_SYNC;
			    } else {
				val->state = VESMAIL_IMAP_P_RESYNC;
			    }
			}
			break;
		}
	    }
	    if (!ffull && !rslt->range) {
		if (rslt->token->state == VESMAIL_IMAP_P_CONT) {
		    rs = VESMAIL_IMAP_RE_UNDEF;
		} else if (final && val->literal) {
		    int oor = ++(VESMAIL_IMAP(rslt->server)->ctOOR);
		    VESMAIL_SRV_DEBUG(rslt->server, 1, sprintf(debug, "Unlinked range, oor=%d", oor))
		    if (oor > VESMAIL_IMAP_OOR_MAXBYTES) oor = VESMAIL_IMAP_OOR_MAXBYTES;
		    if (oor > 0) {
			char *oors = malloc(oor + 1);
			memset(oors, ' ', oor);
			oors[oor] = 0;
			VESmail_imap_token_memsplice(val, val->len, 0, oors);
			free(oors);
		    }
		}
	    }
	    if (!ffull && rs == VESMAIL_IMAP_RE_OK && rslt->range) {
		if (!final && val->state != VESMAIL_IMAP_P_SYNC) return val->state == VESMAIL_IMAP_P_RESYNC ? VESMAIL_IMAP_RE_RESYNC : VESMAIL_IMAP_RE_UNDEF;
		int bufd = !VESmail_imap_token_isLiteral(val) || val->literal;
		char rhash[16];
		VESmail_imap_fetch_rhash(fetch, rhash);
		VESmail_imap_fetch **rngp;
		for (rngp = &rslt->range; *rngp && !VESmail_imap_fetch_check_rhash(*rngp, rhash); rngp = &((*rngp)->qchain));
		VESmail_imap_fetch *rng = VESmail_imap_fetch_unqueue(*rngp ? rngp : &rslt->range);
		unsigned int len0 = val->len;
		if (rng->range[0] > 0) {
		    if (bufd) VESmail_imap_token_memsplice(val, 0, rng->range[0], NULL);
		    else if (!final) {
			VESmail_xform *sync = VESmail_imap_xform_sync(rslt->server->rsp_in);
			if (sync && sync->obj) ((VESmail_xform *) sync->obj)->offset = -rng->range[0];
		    }
		}
/**********************************
* Auto-sense excessive Out-Of-Range requests
* Native iOS email clients are notorious for falling into an infinite loop of OOR requests
* if the actual body size doesn't match the number returned by BODYSRUCTURE
***********************************/
		if (rng->range[0] == len0) {
		    VESMAIL_SRV_DEBUG(rslt->server, 1, sprintf(debug, (rng->mode == VESMAIL_IMAP_FM_RANGE ? "<%lu.%lu>" : "<%lu>"), rng->range[0], rng->range[1]))
		    if (VESmail_imap_token_isLiteral(val) && ++(VESMAIL_IMAP(rslt->server)->ctOOR) > 0) {
			VESMAIL_IMAP(rslt->server)->flags |= VESMAIL_IMAP_F_CALC;
			unsigned int l = rng->mode == VESMAIL_IMAP_FM_RANGE ? rng->range[1] : VESMAIL_IMAP(rslt->server)->ctOOR;
			if (l > VESMAIL_IMAP_OOR_MAXBYTES) l = VESMAIL_IMAP_OOR_MAXBYTES;
			free(val->literal);
			val->literal = malloc(val->len = l);
			memset(val->literal, ' ', l);
		    }
		}
		if (rng->mode == VESMAIL_IMAP_FM_RANGE) {
		    if (bufd) VESmail_imap_token_memsplice(val, rng->range[1], val->len, NULL);
		    else if (val->len > rng->range[1]) val->len = rng->range[1];
		}
		char buf[16];
		sprintf(buf, "<%lu>", rng->range[0]);
		VESmail_imap_token_splice(key, 2, 1, 1, VESmail_imap_token_atom(buf));
		VESmail_imap_fetch_free(rng);
	    }
	    break;
	case VESMAIL_IMAP_FV_ENVELOPE: {
	    VESmail_imap_token *lst;
	    if (!VESmail_imap_token_isLSet(val) || val->len != 1 || !VESmail_imap_token_isList(lst = val->list[0]) || lst->len < 10) {
		return VESMAIL_IMAP_RE_BAD;
	    }
	    if (!(msg->flags & (VESMAIL_IMAP_MF_ENCD | VESMAIL_IMAP_MF_PASS))) {
		VESmail_imap_token *t = lst->list[9];
		VESmail_imap_msg_set_msgid(msg, VESmail_imap_token_data(t), (VESmail_imap_token_isAtom(t) ? 0 : t->len));
		if (VESmail_imap_msg_pass(msg)) return VESMAIL_IMAP_RE_OK;
	    }
	    if (!(msg->flags & VESMAIL_IMAP_MF_HDR)) {
		VESmail_imap_result_QUERYR(rslt, VESmail_imap_fetch_new_body(VESMAIL_IMAP_FV_BODY_PEEK, VESMAIL_IMAP_FM_SECTION, VESMAIL_IMAP_FS_HEADER, 0, NULL), msg, VESMAIL_IMAP_MF_QHDR, rs)
		break;
	    }
	    VESmail_imap_token_splice(lst, 1, 1, 1, VESmail_imap_token_nstring(VESmail_imap_msg_header(msg, VESMAIL_IMAP_H_SUBJECT, NULL, NULL)));
	    VESmail_imap_token_splice(lst, 8, 1, 1, VESmail_imap_token_nstring(VESmail_imap_msg_header(msg, VESMAIL_IMAP_H_IN_REPLY_TO, NULL, NULL)));
	    VESmail_imap_token_splice(lst, 9, 1, 1, VESmail_imap_token_nstring(VESmail_imap_msg_header(msg, VESMAIL_IMAP_H_MESSAGE_ID, NULL, NULL)));
	    break;
	}
	default:
	    break;
    }
    if (rs == VESMAIL_IMAP_RE_OK) switch (val->state) {
	case VESMAIL_IMAP_P_SYNC:
	    rs = VESMAIL_IMAP_RE_SYNC;
	    break;
	case VESMAIL_IMAP_P_RESYNC:
	    rs = VESMAIL_IMAP_RE_RESYNC;
	    break;
	default:
	    break;
    }
    return rs;
}
