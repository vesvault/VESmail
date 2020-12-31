#include <stddef.h>
#include <stdlib.h>
#include "jTree.h"

jTree *jTree_init(jTree *jtree) {
    if (!jtree) jtree = malloc(sizeof(jTree));
    jtree->left = jtree->right = jtree->back = NULL;
    jtree->data = NULL;
    jtree->ldepth = jtree->rdepth = 0;
    return jtree;
}

#define JTREE_BAL_LVL	2

#define	jTree_BAL1(jtree, r, a, b, ad, bd)	\
    r = jtree->a;\
    r->back = jtree->back;\
    if ((jtree->a = r->b)) jtree->a->back = jtree;\
    jtree->ad = r->bd;\
    r->b = jtree;\
    jtree->back = r;\
    r->bd = (jtree->ad > jtree->bd ? jtree->ad : jtree->bd) + 1;

#define	jTree_BAL2(jtree, r, a, b, ad, bd)	\
    r = jtree->a->b;\
    r->back = jtree->back;\
    if ((jtree->a->b = r->a)) jtree->a->b->back = jtree->a;\
    jtree->a->bd = r->ad;\
    r->ad = (jtree->a->ad > r->ad ? jtree->a->ad : r->ad) + 1;\
    r->a = jtree->a;\
    r->a->back = r;\
    if ((jtree->a = r->b)) jtree->a->back = jtree;\
    jtree->ad = r->bd;\
    r->b = jtree;\
    r->b->back = r;\
    r->bd = (jtree->ad > jtree->bd ? jtree->ad : jtree->bd) + 1;

void **jTree_seek(jTree **ptree, void *term, void *arg, int (* cmpfn)(void *data, void *term, void *arg), unsigned char *depth) {
    jTree *jtree = *ptree;
    if (!jtree) {
	if (!depth) return NULL;
	jtree = *ptree = jTree_init(NULL);
	*depth = 1;
	return &jtree->data;
    }
    void **rs;
    int c = jtree->data ? cmpfn(jtree->data, term, arg) : 0;
    if (!c) {
	rs = &jtree->data;
    } else if (c < 0) {
	rs = jTree_seek(&jtree->right, term, arg, cmpfn, depth);
	if (depth) {
	    jtree->right->back = jtree;
	    jtree->rdepth = *depth;
	    if (jtree->rdepth > jtree->ldepth + JTREE_BAL_LVL) {
		jTree *r;
		if (jtree->right->ldepth > jtree->ldepth) {
		    jTree_BAL2(jtree, r, right, left, rdepth, ldepth)
		} else {
		    jTree_BAL1(jtree, r, right, left, rdepth, ldepth)
		}
		jtree = *ptree = r;
	    }
	}
    } else {
	rs = jTree_seek(&jtree->left, term, arg, cmpfn, depth);
	if (depth) {
	    jtree->left->back = jtree;
	    jtree->ldepth = *depth;
	    if (jtree->ldepth > jtree->rdepth + JTREE_BAL_LVL) {
		jTree *r;
		if (jtree->left->rdepth > jtree->rdepth) {
		    jTree_BAL2(jtree, r, left, right, ldepth, rdepth)
		} else {
		    jTree_BAL1(jtree, r, left, right, ldepth, rdepth)
		}
		jtree = *ptree = r;
	    }
	}
    }
    if (depth) *depth = (jtree->ldepth > jtree->rdepth ? jtree->ldepth : jtree->rdepth) + 1;
    return rs;
}

void **jTree_first(jTree *jtree) {
    if (!jtree) return NULL;
    while (jtree->left) jtree = jtree->left;
    return &jtree->data;
}

void **jTree_last(jTree *jtree) {
    if (!jtree) return NULL;
    while (jtree->right) jtree = jtree->right;
    return &jtree->data;
}

void **jTree_next(void **pdata) {
    if (!pdata) return NULL;
    jTree *jtree = (jTree *)(((char *) pdata) - offsetof(jTree, data));
    if (jtree->right) return jTree_first(jtree->right);
    jTree *bk;
    for (bk = jtree->back; bk; jtree = bk, bk = bk->back) {
	if (bk->left == jtree) return &bk->data;
    }
    return NULL;
}

void **jTree_prev(void **pdata) {
    if (!pdata) return NULL;
    jTree *jtree = (jTree *)(((char *) pdata) - offsetof(jTree, data));
    if (jtree->left) return jTree_last(jtree->left);
    jTree *bk;
    for (bk = jtree->back; bk; jtree = bk, bk = bk->back) {
	if (bk->right == jtree) return &bk->data;
    }
    return NULL;
}


unsigned char jTree_collapse(jTree **ptree) {
    jTree *jtree = *ptree;
    if (!jtree) return 0;
    jtree->ldepth = jTree_collapse(&jtree->left);
    jtree->rdepth = jTree_collapse(&jtree->right);
    if (!jtree->data && !jtree->left && !jtree->right) {
	free(jtree);
	*ptree = NULL;
	return 0;
    }
    return (jtree->ldepth > jtree->rdepth ? jtree->ldepth : jtree->ldepth) + 1;
}
