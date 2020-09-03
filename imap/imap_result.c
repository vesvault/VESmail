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
#include "../VESmail.h"
#include "../srv/server.h"
#include "imap.h"
#include "imap_token.h"
#include "imap_msg.h"
#include "imap_fetch.h"
#include "imap_track.h"
#include "imap_proxy.h"
#include "imap_sect.h"
#include "imap_result.h"

VESmail_imap_result *VESmail_imap_result_link(VESmail_imap_result *rslt) {
    if (*(rslt->msgptr) && *(rslt->msgptr) != &VESmail_imap_msg_PASS) {
	rslt->mchain = (*(rslt->msgptr))->result;
	(*(rslt->msgptr))->result = rslt;
    }
    return rslt;
}

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

int VESmail_imap_result_chkbug(void *rslt, VESmail_imap_msg *msg, VESmail_imap_fetch *fetch) {
    if (msg->flags & VESMAIL_IMAP_MF_CHKBUG) {
	msg->flags = (msg->flags & ~(VESMAIL_IMAP_MF_CHKBUG | VESMAIL_IMAP_MF_HDR)) | VESMAIL_IMAP_MF_CFMBUG;
	return 1;
    }
    return 0;
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
	    VESmail_imap_msg_decrypt(msg, msg,
		(fetch->type == VESMAIL_IMAP_FV_RFC822 ? VESMAIL_IMAP_MF_PHDR | VESMAIL_IMAP_MF_PBODY : VESMAIL_IMAP_MF_PHDR),
		val, NULL);
	    msg->flags |= (fetch->type == VESMAIL_IMAP_FV_RFC822 ? VESMAIL_IMAP_MF_BODY : VESMAIL_IMAP_MF_HDR);
	    break;
	}
	case VESMAIL_IMAP_FV_RFC822_TEXT: {
	    if (msg->flags & VESMAIL_IMAP_MF_HDR) {
		VESmail_imap_msg_decrypt(msg, msg, VESMAIL_IMAP_MF_HDR | VESMAIL_IMAP_MF_PBODY, val, NULL);
	    } else {
		VESmail_imap_result_QUERYRS(rslt, VESMAIL_IMAP_FS_HEADER, 0, NULL, msg, VESMAIL_IMAP_MF_QHDR, rs)
	    }
	    break;
	}
	case VESMAIL_IMAP_FV_RFC822_SIZE:
	    if (msg->flags & VESMAIL_IMAP_MF_BODY) {
		char buf[16];
		sprintf(buf, "%lu", msg->totalBytes);
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
			    if (VESmail_imap_sect_hdr_unescape(fetch, key, &rslt->range) > 0) return VESMAIL_IMAP_RE_SILENT;
			    if (!*fetch->fields) return VESMAIL_IMAP_RE_DROP;
			    if (sech) {
				VESmail_imap_msg_decrypt(sech, msg, (VESMAIL_IMAP_MF_PHDR & ffull), val, fetch);
			    } else {
				VESmail_imap_msg *m = VESMAIL_IMAP(rslt->server)->results.pass;
				if (!m) (m = VESMAIL_IMAP(rslt->server)->results.pass = VESmail_imap_msg_new(rslt->server))->flags |= VESMAIL_IMAP_MF_PASS;
				VESmail_imap_msg_decrypt(m, m, 0, val, fetch);
			    }
			}
			default:
			    break;
		    }
		    if (sech) switch (fetch->stype) {
			case VESMAIL_IMAP_FS_HEADER:
			    VESmail_imap_msg_decrypt(sech, msg, (VESMAIL_IMAP_MF_PHDR & ffull), val, NULL);
			    sech->flags |= (VESMAIL_IMAP_MF_HDR & ffull);
			    break;
			case VESMAIL_IMAP_FS_TEXT:
			    if (sech->flags & VESMAIL_IMAP_MF_HDR) {
				VESmail_imap_msg_decrypt(sech, msg, VESMAIL_IMAP_MF_HDR | (VESMAIL_IMAP_MF_PBODY & ffull), val, NULL);
			    } else {
				VESmail_imap_result_QUERYRS(rslt, VESMAIL_IMAP_FS_HEADER, fetch->seclen, fetch->section, sech, VESMAIL_IMAP_MF_QHDR, rs)
			    }
			    break;
			case VESMAIL_IMAP_FS_NONE:
			    VESmail_imap_msg_decrypt(sech, msg, ((VESMAIL_IMAP_MF_PHDR | VESMAIL_IMAP_MF_PBODY) & ffull), val, NULL);
			    secm = NULL;
			default:
			    break;
		    }
		    if (secm) switch (fetch->stype) {
			case VESMAIL_IMAP_FS_MIME:
			    VESmail_imap_msg_decrypt(secm, msg, (VESMAIL_IMAP_MF_PHDR & ffull) | VESMAIL_IMAP_MF_CHKBUG, val, NULL);
			    if (!(VESMAIL_IMAP(rslt->server)->flags & (VESMAIL_IMAP_F_MIMEBUG | VESMAIL_IMAP_F_MIMEOK))) {
				if (secm->flags & VESMAIL_IMAP_MF_CFMBUG) {
				    if (!(msg->flags & VESMAIL_IMAP_MF_BODY)) {
					secm->flags &= ~VESMAIL_IMAP_MF_HDR;
					VESmail_imap_result_QUERYRS(rslt, VESMAIL_IMAP_FS_NONE, 0, NULL, msg, VESMAIL_IMAP_MF_QBODY, rs)
					break;
				    }
				} else {
				    rs = VESMAIL_IMAP_RE_UNDEF;
				}
			    }
			    secm->flags |= (ffull & VESMAIL_IMAP_MF_HDR);
			    break;
			case VESMAIL_IMAP_FS_NONE:
			    if (secm->flags & VESMAIL_IMAP_MF_HDR) {
				VESmail_imap_msg_decrypt(secm, msg, VESMAIL_IMAP_MF_HDR | (VESMAIL_IMAP_MF_PBODY & ffull), val, NULL);
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
			    } else return VESMAIL_IMAP_RE_CDROP;
			    break;
			case VESMAIL_IMAP_FS_MIME:
			    if (secm) {
				VESmail_imap_result_DROP(secm, VESMAIL_IMAP_MF_QHDR)
			    } else return VESMAIL_IMAP_RE_CDROP;
			default:
			    break;
		    }
		    break;
		}
	    }
	    if (!ffull && rs == VESMAIL_IMAP_RE_OK && rslt->range) {
		if (!final) return VESMAIL_IMAP_RE_UNDEF;
		VESmail_imap_fetch *rng = VESmail_imap_fetch_unqueue(&rslt->range);
		unsigned int len0 = val->len;
		if (rng->range[0] > 0) VESmail_imap_token_memsplice(val, 0, rng->range[0], NULL);
/**********************************
* Auto-sense excessive Out-Of-Range requests
* Native iOS email clients are notorious for falling into an infinite loop of OOR requests
* if the actual body size doesn't match the number returned by BODYSRUCTURE
***********************************/
		if (rng->range[0] == len0) {
		    if (VESmail_imap_token_isLiteral(val) && ++(VESMAIL_IMAP(rslt->server)->ctOOR) > 0) {
			VESMAIL_IMAP(rslt->server)->flags |= VESMAIL_IMAP_F_CALC;
			unsigned int l = rng->mode == VESMAIL_IMAP_FM_RANGE ? rng->range[1] : VESMAIL_IMAP(rslt->server)->ctOOR;
			free(val->literal);
			val->literal = malloc(val->len = l);
			memset(val->literal, ' ', l);
		    }
		}
		if (rng->mode == VESMAIL_IMAP_FM_RANGE) VESmail_imap_token_memsplice(val, rng->range[1], val->len, NULL);
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
    return rs;
}

void VESmail_imap_result_entry_free(struct VESmail_imap_result_entry *entry) {
    if (entry) VESmail_imap_fetch_free(entry->fetch);
    free(entry);
}

int VESmail_imap_result_update(VESmail_imap_result *rslt) {
    struct VESmail_imap_result_entry **entp = &rslt->entry;
    VESmail_imap_token *lst = rslt->token->list[3]->list[0];
    int st = VESMAIL_IMAP_RE_OK;
    int fdrop = 0;
    int idx;
    for (idx = 0; idx + 1 < lst->len; ) {
	struct VESmail_imap_result_entry *ent = *entp;
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
	    case VESMAIL_IMAP_RE_CDROP:
		if (!fdrop) {
		    ent->state = cpl ? VESMAIL_IMAP_RE_OK : VESMAIL_IMAP_RE_UNDEF;
		    break;
		}
		ent->state = VESMAIL_IMAP_RE_DROP;
	    case VESMAIL_IMAP_RE_DROP:
		fdrop = 1;
		if (!cpl) break;
		*entp = ent->chain;
		VESmail_imap_result_entry_free(ent);
		VESmail_imap_token_splice(lst, idx, 2, 0);
		continue;
	    case VESMAIL_IMAP_RE_SILENT:
		if (st == VESMAIL_IMAP_RE_UNDEF) break;
	    case VESMAIL_IMAP_RE_UNDEF:
		if (st == VESMAIL_IMAP_RE_REQ) break;
	    case VESMAIL_IMAP_RE_REQ:
		st = ent->state;
	    case VESMAIL_IMAP_RE_OK:
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
    return 0;
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

int VESmail_imap_result_commit(VESmail_imap_result *rslt) {
    if (!rslt) return VESMAIL_E_PARAM;
    VESmail_imap_rsp_detach(rslt->server, rslt->token);
    VESmail_imap *imap = VESMAIL_IMAP(rslt->server);
    int rs = 0;
    VESmail_imap_result_chkreq(rslt);
    VESmail_imap_result **ptr;
    if (rslt->msgptr && *(rslt->msgptr) && *(rslt->msgptr) != &VESmail_imap_msg_PASS) {
	rslt->mchain = *(ptr = &(*(rslt->msgptr))->result);
    } else {
	rslt->mchain = NULL;
	ptr = NULL;
    }
    VESmail_imap_result *rr = rslt;
    VESmail_imap_result *rq = NULL;
    while (1) {
	VESmail_imap_result *next = rr->mchain;
	switch (rr->state) {
	    case VESMAIL_IMAP_RE_REQ:
	    case VESMAIL_IMAP_RE_UNDEF:
		rq = rr;
		if (ptr) {
		    *ptr = rr;
		    ptr = &rr->mchain;
		    break;
		}
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
	    VESmail_imap_result_update(rr);
	    VESmail_imap_result_chkreq(rr);
	} else {
	    if (ptr) *ptr = NULL;
	    break;
	}
    }
    int r = rq ? VESmail_imap_result_sendreq(rq) : 0;
    if (r < 0) return r;
    rs += r;
    r = VESmail_imap_result_flush(imap);
    if (r < 0) return r;
    rs += r;
    return rs;
}

int VESmail_imap_result_send(VESmail_imap_result *rslt) {
    if (rslt->token && rslt->token->list[3]->list[0]->len) {
	int r = VESmail_imap_rsp_send(rslt->server, rslt->token);
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
	    return rslt;
	}
    }
    return NULL;
}

