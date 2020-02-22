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

typedef struct VESmail_imap_token {
    enum {
	VESMAIL_IMAP_T_LINE,
	VESMAIL_IMAP_T_LSET,
	VESMAIL_IMAP_T_LIST,
	VESMAIL_IMAP_T_INDEX,

	VESMAIL_IMAP_T_LITERAL,
    
	VESMAIL_IMAP_T_ATOM,
	VESMAIL_IMAP_T_QUOTED
    } type;
    enum {
	VESMAIL_IMAP_P_INIT,
	VESMAIL_IMAP_P_DONE,
	VESMAIL_IMAP_P_CONT,
	VESMAIL_IMAP_P_ERROR,
	VESMAIL_IMAP_P_ABORT
    } state;
    short int flags;
    unsigned long int len;
    union {
	char data[0];
	struct {
	    union {
		struct VESmail_imap_token **list;
		char *literal;
	    };
	    union {
		struct VESmail_imap_token *parent;
		struct VESmail_imap_token *hold;
		struct VESmail_xform *xform;
	    };
	};
    };
} VESmail_imap_token;

struct VESmail_xform;

#define VESMAIL_IMAP_PF_INIT	0
#define	VESMAIL_IMAP_PE		0xff00
#define	VESMAIL_IMAP_PE_ATOM	0x0100
#define	VESMAIL_IMAP_PE_QUOTE	0x0200
#define	VESMAIL_IMAP_PE_LITERAL	0x0400
#define	VESMAIL_IMAP_PE_LIST	0x0800


struct VESmail_imap_token *VESmail_imap_token_new(int type, unsigned int len);
struct VESmail_imap_token *VESmail_imap_token_clone(struct VESmail_imap_token *orig);
struct VESmail_imap_token *VESmail_imap_token_putc(struct VESmail_imap_token *token, char c);
struct VESmail_imap_token *VESmail_imap_token_splice(struct VESmail_imap_token *list, int offs, int dlen, int ilen, ...);
struct VESmail_imap_token *VESmail_imap_token_push(struct VESmail_imap_token *list, struct VESmail_imap_token *token);
struct VESmail_imap_token *VESmail_imap_token_vall(int type, const char *str, int len);
struct VESmail_imap_token *VESmail_imap_token_val(int type, const char *str);
#define VESmail_imap_token_atom(str)	VESmail_imap_token_val(VESMAIL_IMAP_T_ATOM, str)
#define VESmail_imap_token_quoted(str)	VESmail_imap_token_val(VESMAIL_IMAP_T_QUOTED, str)
#define VESmail_imap_token_line()	VESmail_imap_token_new(VESMAIL_IMAP_T_LINE, 0)
#define VESmail_imap_token_list(len, ...)	VESmail_imap_token_splice(VESmail_imap_token_new(VESMAIL_IMAP_T_LIST, 0), 0, 0, len, ## __VA_ARGS__ )
#define VESmail_imap_token_index(len, ...)	VESmail_imap_token_splice(VESmail_imap_token_new(VESMAIL_IMAP_T_INDEX, 0), 0, 0, len, ## __VA_ARGS__ )
#define VESmail_imap_token_lset(lst)	VESmail_imap_token_splice(VESmail_imap_token_new(VESMAIL_IMAP_T_LSET, 0), 0, 0, 1, (lst))
struct VESmail_imap_token *VESmail_imap_token_astringl(const char *str, int len);
#define VESmail_imap_token_astring(str)	VESmail_imap_token_astringl(str, strlen(str))
struct VESmail_imap_token *VESmail_imap_token_nstring(const char *str);
struct VESmail_imap_token *VESmail_imap_token_uint(unsigned int val);
struct VESmail_imap_token *VESmail_imap_token_nlist(struct VESmail_imap_token *token);
char *VESmail_imap_token_data(struct VESmail_imap_token *token);
int VESmail_imap_token_render(struct VESmail_imap_token *token, struct VESmail_xform *xform, struct VESmail_imap_token **hold);
char *VESmail_imap_token_cp_lcstr(struct VESmail_imap_token *token, char *dst);
int VESmail_imap_token_getuint(struct VESmail_imap_token *token, unsigned int *rs);
struct VESmail_imap_token *VESmail_imap_token_getlist(struct VESmail_imap_token *token);
#define VESmail_imap_token_isAtom(token)	((token)->type == VESMAIL_IMAP_T_ATOM)
#define VESmail_imap_token_isQuoted(token)	((token)->type == VESMAIL_IMAP_T_QUOTED)
#define VESmail_imap_token_isAString(token)	((token)->type >= VESMAIL_IMAP_T_LITERAL)
#define VESmail_imap_token_isLiteral(token)	((token)->type == VESMAIL_IMAP_T_LITERAL)
#define VESmail_imap_token_isIndex(token)	((token)->type == VESMAIL_IMAP_T_INDEX)
#define VESmail_imap_token_isList(token)	((token)->type == VESMAIL_IMAP_T_LIST)
#define VESmail_imap_token_isLSet(token)	((token)->type == VESMAIL_IMAP_T_LSET)
struct VESmail_xform *VESmail_imap_token_xform_new(struct VESmail_imap_token *token);
int VESmail_imap_token_xform_apply(struct VESmail_imap_token *token, struct VESmail_xform *xform);
int VESmail_imap_token_eq(struct VESmail_imap_token *a, struct VESmail_imap_token *b);
struct VESmail_imap_token *VESmail_imap_token_memsplice(struct VESmail_imap_token *token, int offs, int del, const char *ins);
int VESmail_imap_token_error(struct VESmail_imap_token *token);
void VESmail_imap_token_free(struct VESmail_imap_token *token);
