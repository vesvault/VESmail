/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         libVES:                      VESvault API library
 *    \__ /     \ __/
 *       \\     //            VES Utility:   A command line interface to libVES
 *        \\   //
 *         \\_//              - Key Management and Exchange
 *         /   \              - Item Encryption and Sharing
 *         \___/              - Stream Encryption
 *
 *
 * (c) 2018 VESvault Corp
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
 * jTree.c                    jTree: A binary tree
 *
 ***************************************************************************/
#include <stddef.h>
#include <stdlib.h>
#include "jTree.h"

jTree_SYM(jTree_p) jTree_SYM(jTree_init)(jTree_SYM(jTree_p) jtree jTree_REFARG) {
    if (!jtree) jtree = jTree_alloc(sizeof(jTree_SYM(jTree)) jTree_REF);
    if (!jtree) return jTree_NULL;
    jTree_FLD(jtree, left) = jTree_FLD(jtree, right) = jTree_FLD(jtree, back) = jTree_NULL;
    jTree_FLD(jtree, data) = jTree_data_NULL;
    jTree_FLD(jtree, ldepth) = jTree_FLD(jtree, rdepth) = 0;
    return jtree;
}

#define JTREE_BAL_LVL	2

#define	jTree_BAL1(jtree, r, a, b, ad, bd)	if ((r = jTree_FLD(jtree, a)) && (jTree_FLD(r, data) || (r = jTree_NULL))) {\
    jTree_FLD(r, back) = jTree_FLD(jtree, back);\
    if ((jTree_FLD(jtree, a) = jTree_FLD(r, b))) jTree_FLD(jTree_FLD(jtree, a), back) = jtree;\
    jTree_FLD(jtree, ad) = jTree_FLD(r, bd);\
    jTree_FLD(r, b) = jtree;\
    jTree_FLD(jtree, back) = r;\
    jTree_FLD(r, bd) = (jTree_FLD(jtree, ad) > jTree_FLD(jtree, bd) ? jTree_FLD(jtree, ad) : jTree_FLD(jtree, bd)) + 1;\
}

#define	jTree_BAL2(jtree, r, a, b, ad, bd)	if ((r = jTree_FLD(jTree_FLD(jtree, a), b)) && (jTree_FLD(r, data) || (r = jTree_NULL))) {\
    jTree_FLD(r, back) = jTree_FLD(jtree, back);\
    if ((jTree_FLD(jTree_FLD(jtree, a), b) = jTree_FLD(r, a))) jTree_FLD(jTree_FLD(jTree_FLD(jtree, a), b), back) = jTree_FLD(jtree, a);\
    jTree_FLD(jTree_FLD(jtree, a), bd) = jTree_FLD(r, ad);\
    jTree_FLD(r, ad) = (jTree_FLD(jTree_FLD(jtree, a), ad) > jTree_FLD(r, ad) ? jTree_FLD(jTree_FLD(jtree, a), ad) : jTree_FLD(r, ad)) + 1;\
    jTree_FLD(r, a) = jTree_FLD(jtree, a);\
    jTree_FLD(jTree_FLD(r, a), back) = r;\
    if ((jTree_FLD(jtree, a) = jTree_FLD(r, b))) jTree_FLD(jTree_FLD(jtree, a), back) = jtree;\
    jTree_FLD(jtree, ad) = jTree_FLD(r, bd);\
    jTree_FLD(r, b) = jtree;\
    jTree_FLD(jTree_FLD(r, b), back) = r;\
    jTree_FLD(r, bd) = (jTree_FLD(jtree, ad) > jTree_FLD(jtree, bd) ? jTree_FLD(jtree, ad) : jTree_FLD(jtree, bd)) + 1;\
}

jTree_SYM(jTree_data_t) *jTree_SYM(jTree_seek)(jTree_SYM(jTree_p) *ptree, jTree_SYM(jTree_data_t) term, jTree_SYM(jTree_arg_t) arg, int (* cmpfn)(jTree_SYM(jTree_data_t) data, jTree_SYM(jTree_data_t) term, jTree_SYM(jTree_arg_t) arg), unsigned char *depth) {
    int c;
    jTree_SYM(jTree_p) jtree = *ptree;
    jTree_SYM(jTree_data_t) *rs;
    if (!jtree) {
	if (!depth) return NULL;
	jtree = *ptree = jTree_SYM(jTree_init)(jTree_NULL jTree_REF);
	if (!jtree) return NULL;
	*depth = 1;
	return &jTree_FLD(jtree, data);
    }
    c = jTree_FLD(jtree, data) ? cmpfn(jTree_FLD(jtree, data), term, arg) : 0;
    if (!c) {
	rs = &jTree_FLD(jtree, data);
    } else if (c < 0) {
	rs = jTree_SYM(jTree_seek)(&jTree_FLD(jtree, right), term, arg, cmpfn, depth);
	if (depth && rs) {
	    jTree_FLD(jTree_FLD(jtree, right), back) = jtree;
	    jTree_FLD(jtree, rdepth) = *depth;
	    if (jTree_FLD(jtree, rdepth) > jTree_FLD(jtree, ldepth) + JTREE_BAL_LVL) {
		jTree_SYM(jTree_p) r;
		if (jTree_FLD(jTree_FLD(jtree, right), ldepth) > jTree_FLD(jtree, ldepth)) {
		    jTree_BAL2(jtree, r, right, left, rdepth, ldepth)
		} else {
		    jTree_BAL1(jtree, r, right, left, rdepth, ldepth)
		}
		if (r) jtree = *ptree = r;
	    }
	}
    } else {
	rs = jTree_SYM(jTree_seek)(&jTree_FLD(jtree, left), term, arg, cmpfn, depth);
	if (depth && rs) {
	    jTree_FLD(jTree_FLD(jtree, left), back) = jtree;
	    jTree_FLD(jtree, ldepth) = *depth;
	    if (jTree_FLD(jtree, ldepth) > jTree_FLD(jtree, rdepth) + JTREE_BAL_LVL) {
		jTree_SYM(jTree_p) r;
		if (jTree_FLD(jTree_FLD(jtree, left), rdepth) > jTree_FLD(jtree, rdepth)) {
		    jTree_BAL2(jtree, r, left, right, ldepth, rdepth)
		} else {
		    jTree_BAL1(jtree, r, left, right, ldepth, rdepth)
		}
		if (r) jtree = *ptree = r;
	    }
	}
    }
    if (depth) *depth = (jTree_FLD(jtree, ldepth) > jTree_FLD(jtree, rdepth) ? jTree_FLD(jtree, ldepth) : jTree_FLD(jtree, rdepth)) + 1;
    return rs;
}

jTree_SYM(jTree_data_t) *jTree_SYM(jTree_first)(jTree_SYM(jTree_p) jtree jTree_REFARG) {
    if (!jtree) return NULL;
    while (jTree_FLD(jtree, left)) jtree = jTree_FLD(jtree, left);
    return &jTree_FLD(jtree, data);
}

jTree_SYM(jTree_data_t) *jTree_SYM(jTree_last)(jTree_SYM(jTree_p) jtree jTree_REFARG) {
    if (!jtree) return NULL;
    while (jTree_FLD(jtree, right)) jtree = jTree_FLD(jtree, right);
    return &jTree_FLD(jtree, data);
}

jTree_SYM(jTree_data_t) *jTree_SYM(jTree_next)(jTree_SYM(jTree_data_t) *pdata jTree_REFARG) {
    jTree_SYM(jTree_p) jtree = jTree_DATA2P(pdata);
    jTree_SYM(jTree_p) bk;
    if (!pdata) return NULL;
    if (jTree_FLD(jtree, right)) return jTree_SYM(jTree_first)(jTree_FLD(jtree, right) jTree_REF);
    for (bk = jTree_FLD(jtree, back); bk; jtree = bk, bk = jTree_FLD(bk, back)) {
	if (jTree_FLD(bk, left) == jtree) return &jTree_FLD(bk, data);
    }
    return NULL;
}

jTree_SYM(jTree_data_t) *jTree_SYM(jTree_prev)(jTree_SYM(jTree_data_t) *pdata jTree_REFARG) {
    jTree_SYM(jTree_p) jtree = jTree_DATA2P(pdata);
    jTree_SYM(jTree_p) bk;
    if (!pdata) return NULL;
    if (jTree_FLD(jtree, left)) return jTree_SYM(jTree_last)(jTree_FLD(jtree, left) jTree_REF);
    for (bk = jTree_FLD(jtree, back); bk; jtree = bk, bk = jTree_FLD(bk, back)) {
	if (jTree_FLD(bk, right) == jtree) return &jTree_FLD(bk, data);
    }
    return NULL;
}

void jTree_SYM(jTree_delete)(jTree_SYM(jTree_p) *ptree, jTree_SYM(jTree_data_t) *pdata jTree_REFARG) {
    jTree_SYM(jTree_p) jtree, jl, jr, jnew, jback, jlnull, jrnull, *pt, jd, jdn;
    if (!pdata) return;
    jtree = jTree_DATA2P(pdata);
    jback = jTree_FLD(jtree, back);
    jTree_FLD(jtree, data) = jTree_data_NULL;
    jTree_FLD(jtree, ldepth) = jTree_FLD(jtree, rdepth) = 0;
    jl = jTree_FLD(jtree, left);
    jr = jTree_FLD(jtree, right);
    if (jl && !jTree_FLD(jl, data)) jl = jTree_NULL;
    if (jr && !jTree_FLD(jr, data)) jr = jTree_NULL;
    if (jl) while (jTree_FLD(jl, right) && jTree_FLD(jTree_FLD(jl, right), data)) jl = jTree_FLD(jl, right);
    if (jr) while (jTree_FLD(jr, left) && jTree_FLD(jTree_FLD(jr, left), data)) jr = jTree_FLD(jr, left);
    jlnull = jl ? jTree_FLD(jl, right) : jTree_FLD(jtree, left);
    jrnull = jr ? jTree_FLD(jr, left) : jTree_FLD(jtree, right);
    if (jl) {
	jnew = jl;
	if (jTree_FLD(jl, left)) jTree_FLD(jTree_FLD(jl, left), back) = jTree_FLD(jl, back);
	if (jTree_FLD(jTree_FLD(jl, back), right) == jl) {
	    jTree_FLD(jTree_FLD(jl, back), right) = jTree_FLD(jl, left);
	    jTree_FLD(jTree_FLD(jl, back), rdepth) = jTree_FLD(jl, ldepth);
	} else {
	    jTree_FLD(jTree_FLD(jl, back), left) = jTree_FLD(jl, left);
	    jTree_FLD(jTree_FLD(jl, back), ldepth) = jTree_FLD(jl, ldepth);
	}
	if (jr) {
	    pt = &jTree_FLD(jr, left);
	    jTree_FLD(jr, left) = jtree;
	    jTree_FLD(jtree, back) = jr;
	} else {
	    pt = &jTree_FLD(jnew, right);
	    jTree_FLD(jtree, right) = jtree;
	}
    } else if (jr) {
	jnew = jr;
	if (jTree_FLD(jr, right)) jTree_FLD(jTree_FLD(jr, right), back) = jTree_FLD(jr, back);
	if (jTree_FLD(jTree_FLD(jr, back), left) == jr) {
	    jTree_FLD(jTree_FLD(jr, back), left) = jTree_FLD(jr, right);
	    jTree_FLD(jTree_FLD(jr, back), ldepth) = jTree_FLD(jr, rdepth);
	} else {
	    jTree_FLD(jTree_FLD(jr, back), right) = jTree_FLD(jr, right);
	    jTree_FLD(jTree_FLD(jr, back), rdepth) = jTree_FLD(jr, rdepth);
	}
	if (jl) {
	    pt = &jTree_FLD(jl, right);
	    jTree_FLD(jl, right) = jtree;
	    jTree_FLD(jtree, back) = jl;
	} else {
	    pt = &jTree_FLD(jnew, left);
	    jTree_FLD(jtree, left) = jtree;
	}
    } else return;
    jd = jTree_FLD(jnew, back);
    if ((jTree_FLD(jnew, left) = jTree_FLD(jtree, left))) jTree_FLD(jTree_FLD(jnew, left), back) = jnew;
    if ((jTree_FLD(jnew, right) = jTree_FLD(jtree, right))) jTree_FLD(jTree_FLD(jnew, right), back) = jnew;
    jTree_FLD(jnew, ldepth) = jTree_FLD(jtree, ldepth);
    jTree_FLD(jnew, rdepth) = jTree_FLD(jtree, rdepth);
    jTree_FLD(jnew, back) = jback;
    if (jback) {
	if (jTree_FLD(jback, left) == jtree) jTree_FLD(jback, left) = jnew;
	if (jTree_FLD(jback, right) == jtree) jTree_FLD(jback, right) = jnew;
    } else {
	*ptree = jnew;
    }
    if ((jTree_FLD(jtree, left) = jlnull)) jTree_FLD(jlnull, back) = jtree;
    if ((jTree_FLD(jtree, right) = jrnull)) jTree_FLD(jrnull, back) = jtree;
    for (; (jdn = jTree_FLD(jd, back)); jd = jdn) {
	int d = jTree_FLD(jd, data) ? ((jTree_FLD(jd, ldepth) > jTree_FLD(jd, rdepth) ? jTree_FLD(jd, ldepth) : jTree_FLD(jd, rdepth)) + 1) : 0;
	if (jTree_FLD(jdn, left) == jd) jTree_FLD(jdn, ldepth) = d;
	else jTree_FLD(jdn, rdepth) = d;
    }
    jTree_SYM(jTree_collapse)(pt jTree_REF);
}

unsigned char jTree_SYM(jTree_collapse)(jTree_SYM(jTree_p) *ptree jTree_REFARG) {
    jTree_SYM(jTree_p) jtree = *ptree;
    if (!jtree) return 0;
    jTree_FLD(jtree, ldepth) = jTree_SYM(jTree_collapse)(&jTree_FLD(jtree, left) jTree_REF);
    jTree_FLD(jtree, rdepth) = jTree_SYM(jTree_collapse)(&jTree_FLD(jtree, right) jTree_REF);
    if (!jTree_FLD(jtree, data) && !jTree_FLD(jtree, left) && !jTree_FLD(jtree, right)) {
	jTree_free(jtree);
	*ptree = jTree_NULL;
	return 0;
    }
    return (jTree_FLD(jtree, ldepth) > jTree_FLD(jtree, rdepth) ? jTree_FLD(jtree, ldepth) : jTree_FLD(jtree, ldepth)) + 1;
}
