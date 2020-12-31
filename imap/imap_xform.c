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
#include "../lib/xform.h"
#include "../srv/server.h"
#include "imap.h"
#include "imap_token.h"
#include "imap_start.h"
#include "imap_xform.h"


void VESmail_imap_xform_pdone(VESmail_imap_token *token) {
    if (token && token->state != VESMAIL_IMAP_P_ERROR) token->state = VESMAIL_IMAP_P_DONE;
}

int VESmail_imap_xform_fn(VESmail_xform *xform, int final, const char *src, int *srclen) {
    if (!src) return 0;
    VESmail_server *srv = xform->server;
    const char *s = src;
    const char *tail = src + *srclen;
    int rs = VESmail_imap_start_ready(srv);
    if (rs < 0) return rs;
    while (s < tail && xform->imap->state != VESMAIL_IMAP_X_HOLD) {
	if (xform->imap->state == VESMAIL_IMAP_X_ABORT) {
	    xform->imap->skip = 0;
	    VESmail_imap_token_free(xform->imap->line);
	    xform->imap->line = NULL;
	    xform->imap->state = VESMAIL_IMAP_X_INIT;
	}
	VESmail_imap_token *curr = NULL;
	VESmail_imap_token *line = xform->imap->line;
	if (!line) line = xform->imap->line = xform->imap->list = VESmail_imap_token_line();
	if (xform->imap->list->len > 0) {
	    VESmail_imap_token *lit = xform->imap->list->list[xform->imap->list->len - 1];
	    if (VESmail_imap_token_isLiteral(lit)) curr = lit;
	}
	if (xform->imap->skip > 0) {
	    unsigned int len = xform->imap->skip;
	    if (s + len > tail) len = tail - s;
	    if (xform->imap->state != VESMAIL_IMAP_X_FFWD) {
		if (curr->xform) {
		    int eof = (len >= xform->imap->skip);
		    int r = VESmail_xform_process(curr->xform, eof, s, len);
//		    if (eof && !curr->literal) r = VESMAIL_E_INTERNAL;
		    if (r < 0) {
			curr->len = 0;
			curr->state = VESMAIL_IMAP_P_ERROR;
		    } else {
			rs += r;
		    }
		} else {
		    if (!curr->literal && VESmail_imap_token_chkbytes(line) + curr->len > VESMAIL_IMAP_TOKEN_SAFEBYTES) return VESMAIL_E_BUF;
		    memcpy(VESmail_imap_token_data(curr) + curr->len - xform->imap->skip, s, len);
		}
	    }
	    xform->imap->skip -= len;
	    s += len;
	}
	const char *eol = memchr(s, '\n', tail - s);
	if (!eol) {
	    if (VESmail_imap_token_chkbytes(line) + (tail - s) > VESMAIL_IMAP_TOKEN_SAFEBYTES) return VESMAIL_E_BUF;
	    break;
	}
	const char *nextl = eol + 1;
	const char *lthdr = NULL;
	unsigned int ltlen;
	const char *e = eol - 1;
	int lplus = 0;
	if (e >= s && *e == '\r') eol = e--;
	if (e > s && *e == '}') {
	    const char *b = e - 1;
	    if (b > s && *b == '+') lplus = (b--, 1);
	    while (b >= s && *b >= '0' && *b <= '9') b--;
	    if (*b == '{' && e - b <= 11) {
		long long int ltl;
		sscanf(b + 1, "%lld", &ltl);
		if (ltl <= 0xffffffff) {
		    lthdr = b;
		    ltlen = ltl;
		}
	    }
	}
	char q = 0;
	const char *endl = lthdr ? lthdr : eol;
	VESmail_imap_token *lvl = xform->imap->list;
	const char *s0 = s;
	while (s < endl) {
	    char c = *s++;
	    if (q) switch (c) {
		case '"':
		    q = 0;
		    break;
		case '\\':
		    if (s < endl) VESmail_imap_token_putc(curr, *s++);
		    else line->flags |= VESMAIL_IMAP_PE_QUOTE;
		    break;
		default:
		    VESmail_imap_token_putc(curr, c);
		    break;
	    } else switch (c) {
		case ' ': {
		    if (curr) {
			VESmail_imap_xform_pdone(curr);
			curr = NULL;
		    } else {
			VESmail_imap_token_push(xform->imap->list, VESmail_imap_token_new(VESMAIL_IMAP_T_ATOM, 0));
		    }
		    if (lvl == xform->imap->list) s0 = s;
		    break;
		}
		case '"': {
		    q = 1;
		    if (!curr) curr = VESmail_imap_token_push(xform->imap->list, VESmail_imap_token_new(VESMAIL_IMAP_T_QUOTED, endl - s + 1));
		    else line->flags |= VESMAIL_IMAP_PE_ATOM;
		    break;
		}
		case '(': {
		    if (!curr || curr->type == VESMAIL_IMAP_T_LSET) {
			if (!curr) (curr = VESmail_imap_token_push(xform->imap->list, VESmail_imap_token_new(VESMAIL_IMAP_T_LSET, 0)))->parent = xform->imap->list;
			if (curr->len == 0 || curr->list[curr->len - 1]->type == VESMAIL_IMAP_T_LIST) {
			    xform->imap->list = VESmail_imap_token_push(curr, VESmail_imap_token_new(VESMAIL_IMAP_T_LIST, 0));
			    curr = NULL;
			    break;
			}
		    }
		    line->flags |= VESMAIL_IMAP_PE_LIST;
		    break;
		}
		case ')': {
		    if (xform->imap->list->type == VESMAIL_IMAP_T_LIST) {
			VESmail_imap_xform_pdone(xform->imap->list);
			VESmail_imap_xform_pdone(curr);
			curr = xform->imap->list->parent;
			if (xform->imap->list == lvl) lvl = curr->parent;
			xform->imap->list = curr->parent;
		    } else {
			line->flags |= VESMAIL_IMAP_PE_LIST;
			curr = NULL;
		    }
		    break;
		}
		case '{': {
		    line->flags |= VESMAIL_IMAP_PE_LITERAL;
		    break;
		}
		case '[': {
		    if (!curr) (curr = VESmail_imap_token_push(xform->imap->list, VESmail_imap_token_new(VESMAIL_IMAP_T_LSET, 0)))->parent = xform->imap->list;
		    switch (curr->type) {
			case VESMAIL_IMAP_T_ATOM: {
			    VESmail_imap_token *ls = xform->imap->list->list[xform->imap->list->len - 1] = VESmail_imap_token_new(VESMAIL_IMAP_T_LSET, 0);
			    ls->parent = xform->imap->list;
			    VESmail_imap_token_push(ls, curr);
			    curr = ls;
			}
			case VESMAIL_IMAP_T_LSET: {
			    int t;
			    if (curr->len == 0 || ((t = curr->list[curr->len - 1]->type) == VESMAIL_IMAP_T_INDEX) || t == VESMAIL_IMAP_T_ATOM) {
				xform->imap->list = VESmail_imap_token_push(curr, VESmail_imap_token_new(VESMAIL_IMAP_T_INDEX, 0));
				curr = NULL;
				break;
			    }
			}
			default: {
			    line->flags |= VESMAIL_IMAP_PE_LIST;
			    break;
			}
		    }
		    break;
		}
		case ']': {
		    if (xform->imap->list->type == VESMAIL_IMAP_T_INDEX) {
			VESmail_imap_xform_pdone(xform->imap->list);
			VESmail_imap_xform_pdone(curr);
			curr = xform->imap->list->parent;
			xform->imap->list = curr->parent;
			break;
		    }
		}
		default: {
		    if (!curr) curr = VESmail_imap_token_push(xform->imap->list, VESmail_imap_token_new(VESMAIL_IMAP_T_ATOM, endl - s + 1));
		    else if (curr->type != VESMAIL_IMAP_T_ATOM) {
			VESmail_imap_token *atom;
			if (curr->type == VESMAIL_IMAP_T_LSET) {
			    atom = curr->list[curr->len - 1];
			    if (atom->type != VESMAIL_IMAP_T_ATOM) atom = VESmail_imap_token_push(curr, VESmail_imap_token_new(VESMAIL_IMAP_T_ATOM, endl - s + 1));
			    VESmail_imap_token_putc(atom, c);
			    break;
			}
			line->flags |= VESMAIL_IMAP_PE_ATOM;
			break;
		    }
		    VESmail_imap_token_putc(curr, c);
		    break;
		}
	    }
	    if (line->flags & VESMAIL_IMAP_PE) break;
	}
	if (q) {
	    line->flags |= VESMAIL_IMAP_PE_QUOTE;
	} else if (lthdr) {
	    if (curr) {
		line->flags |= VESMAIL_IMAP_PE_LITERAL;
	    } else {
		line->state = VESMAIL_IMAP_P_CONT;
		curr = VESmail_imap_token_push(xform->imap->list, VESmail_imap_token_new(VESMAIL_IMAP_T_LITERAL, ltlen));
		xform->imap->skip = curr->len = ltlen;
		if (!lplus) xform->imap->state = VESMAIL_IMAP_X_HOLD;
	    }
	} else if (xform->imap->list != xform->imap->line) {
	    line->flags |= VESMAIL_IMAP_PE_LIST;
	} else {
	    if (curr) {
		VESmail_imap_xform_pdone(curr);
	    } else if (line->len > 0) {
		VESmail_imap_token_push(line, VESmail_imap_token_new(VESMAIL_IMAP_T_ATOM, 0));
	    }
	    line->state = VESMAIL_IMAP_P_DONE;
	}
	if (line->flags & VESMAIL_IMAP_PE) {
	    line->state = VESMAIL_IMAP_P_ERROR;
	    if (lvl->len > 0) VESmail_imap_token_splice(lvl, -2, 1, 0);
	    curr = NULL;
	    VESmail_imap_token_push(lvl, VESmail_imap_token_vall(VESMAIL_IMAP_T_ATOM, s0, eol - s0));
	}
	if (xform->imap->state == VESMAIL_IMAP_X_FFWD) {
	    line->state = VESMAIL_IMAP_P_ABORT;
	    xform->imap->state = VESMAIL_IMAP_X_INIT;
	} else {
	    int r = xform->imap->procfn(srv, line);
	    if (r < 0) return r;
	    rs += r;
	}
	s = nextl;
	if (xform->imap->line && xform->imap->line->state != VESMAIL_IMAP_P_CONT) {
	    VESmail_imap_token_free(xform->imap->line);
	    xform->imap->line = xform->imap->list = NULL;
	}
    }
    *srclen = s - src;
    if (final && !(srv->flags & VESMAIL_SRVF_SHUTDOWN)) {
	int r;
	if (!(VESMAIL_IMAP(srv)->flags & VESMAIL_IMAP_F_BYE)) {
	    VESmail_imap_token *rsp = VESmail_imap_rsp_new(NULL, "BYE");
	    VESmail_imap_token_push(rsp, VESmail_imap_token_atom((srv->flags & VESMAIL_SRVF_TMOUT) ? "Timed out" : "Closing the session"));
	    r = VESmail_imap_rsp_send(srv, rsp);
	    VESmail_imap_token_free(rsp);
	} else {
	    r = 0;
	}
	srv->flags |= VESMAIL_SRVF_SHUTDOWN;
	if (r < 0) return r;
	rs += r;
    }
    return rs;
}

VESmail_imap_token *VESmail_imap_xform_detach(VESmail_xform *xform, VESmail_imap_token *token) {
    if (xform->imap->line && xform->imap->line->state != VESMAIL_IMAP_P_CONT && (!token || xform->imap->line == token)) {
	token = xform->imap->line;
	xform->imap->line = xform->imap->list = NULL;
	return token;
    }
    return NULL;
}

VESmail_xform *VESmail_imap_xform_sync(VESmail_xform *xform) {
    if (!xform->imap->sync) xform->imap->sync = VESmail_xform_new_null(NULL);
    return xform->imap->sync;
}

void VESmail_imap_xform_fn_free(VESmail_xform *xform) {
    VESmail_imap_token_free(xform->imap->line);
    VESmail_xform_free(xform->imap->sync);
    free(xform->imap);
}

VESmail_xform *VESmail_xform_new_imap(VESmail_server *srv, int (* procfn)(VESmail_server *srv, VESmail_imap_token *token)) {
    VESmail_imap_xform *imapx = malloc(sizeof(VESmail_imap_xform));
    imapx->skip = 0;
    imapx->state = VESMAIL_IMAP_X_INIT;
    imapx->procfn = procfn;
    imapx->line = imapx->list = NULL;
    imapx->sync = NULL;
    VESmail_xform *xform = VESmail_xform_new(&VESmail_imap_xform_fn, NULL, srv);
    xform->imap = imapx;
    xform->freefn = &VESmail_imap_xform_fn_free;
    return xform;
}
