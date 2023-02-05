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
 * jTree.h                    jTree: A binary tree
 *
 ***************************************************************************/

#ifndef	JTREE_H
#define	JTREE_H
#ifndef	jTree_SYM
#define	jTree_SYM(sym)	sym
typedef struct jTree *	jTree_SYM(jTree_p);
typedef void *		jTree_SYM(jTree_data_t);
typedef void *		jTree_SYM(jTree_arg_t);
#define	jTree_FLD(jtree, fld)	((jtree)->fld)
#define	jTree_EXTRA	void *extra;
#define	jTree_ALIGN	
#define	jTree_REFARG	
#define	jTree_REF	
#define	jTree_NULL	NULL
#define	jTree_data_NULL	NULL
#define	jTree_DATA2P(pdata)	(jTree_p)(((char *) pdata) - offsetof(jTree, data))
#define	jTree_alloc(size)	malloc(size)
#define	jTree_free(jtree)	free(jtree)
#endif

typedef struct jTree_SYM(jTree) {
    jTree_SYM(jTree_data_t) data;
    jTree_EXTRA
    jTree_SYM(jTree_p) left;
    jTree_SYM(jTree_p) right;
    jTree_SYM(jTree_p) back;
    unsigned char ldepth;
    unsigned char rdepth;
    jTree_ALIGN
} jTree_SYM(jTree);

#define jTree_new()	jTree_NULL
jTree_SYM(jTree_data_t) *jTree_SYM(jTree_seek)(jTree_SYM(jTree_p) *ptree, jTree_SYM(jTree_data_t) term, jTree_SYM(jTree_arg_t) arg, int (* cmpfn)(jTree_SYM(jTree_data_t) data, jTree_SYM(jTree_data_t) term, jTree_SYM(jTree_arg_t) arg), unsigned char *depth);
jTree_SYM(jTree_data_t) *jTree_SYM(jTree_first)(jTree_SYM(jTree_p) jtree jTree_REFARG);
jTree_SYM(jTree_data_t) *jTree_SYM(jTree_last)(jTree_SYM(jTree_p) jtree jTree_REFARG);
jTree_SYM(jTree_data_t) *jTree_SYM(jTree_next)(jTree_SYM(jTree_data_t) *pdata jTree_REFARG);
jTree_SYM(jTree_data_t) *jTree_SYM(jTree_prev)(jTree_SYM(jTree_data_t) *pdata jTree_REFARG);
void jTree_SYM(jTree_delete)(jTree_SYM(jTree_p) *ptree, jTree_SYM(jTree_data_t) *pdata jTree_REFARG);
unsigned char jTree_SYM(jTree_collapse)(jTree_SYM(jTree_p) *ptree jTree_REFARG);

#endif
