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

typedef struct VESmail_parse {
    struct VESmail *mail;
    enum {
	VESMAIL_S_INIT,
	VESMAIL_S_HDR,
	VESMAIL_S_BODY
    } state;
    enum {
	VESMAIL_T_UNDEF,
	VESMAIL_T_ALT,
	VESMAIL_T_MULTI,
	VESMAIL_T_MSG,
	VESMAIL_T_VES,
	VESMAIL_T_OTHER
    } ctype;
    enum {
	VESMAIL_CTE_UNDEF,
	VESMAIL_CTE_BIN,
	VESMAIL_CTE_B64,
	VESMAIL_CTE_QP
    } ctenc, dstenc;
    enum {
	VESMAIL_EN_UNDEF,
	VESMAIL_EN_ROOT,
	VESMAIL_EN_ALT,
	VESMAIL_EN_INJ,
	VESMAIL_EN_MULTI,
	VESMAIL_EN_DEEP,
	VESMAIL_EN_MSG
    } encap;
    enum {
	VESMAIL_VP_UNDEF,
	VESMAIL_VP_ALT,
	VESMAIL_VP_INJ,
	VESMAIL_VP_BODY,
	VESMAIL_VP_BANNER
    } vespart;
    short int error;
    long int dechdrs;
    struct VESmail_header *hdrbuf;
    struct VESmail_header *divertbuf;
    int (* hdrfn)(struct VESmail_parse *, struct VESmail_header *);
    int (* outfn)(struct VESmail_parse *, struct VESmail_header *);
    void (* partfn)(struct VESmail_parse *, struct VESmail_parse *);
    struct VESmail_xform *xform;
    struct VESmail_parse *nested;
    char *mpboundary;
    char *injboundary;
    struct VESmail_xform *in;
    void *ref;
} VESmail_parse;

struct VESmail_header;
struct VESmail_xform;

#define VESMAIL_PE_HDR_BAD	0x0001
#define VESMAIL_PE_HDR_DUP	0x0002
#define VESMAIL_PE_HDR_INV	0x0004
#define VESMAIL_PE_HDR_VES	0x0008
#define VESMAIL_PE_HDR_END	0x0010
#define VESMAIL_PE_CTE		0x0080

struct VESmail_parse *VESmail_parse_new(struct VESmail *mail, int (* hdrfn)(struct VESmail_parse *, struct VESmail_header *), struct VESmail_xform *xform, int encap);
int VESmail_parse_process(struct VESmail_parse *parse, int final, const char *src, int *srclen);
int VESmail_parse_skip(struct VESmail_parse *parse);

int VESmail_parse_header_type(struct VESmail_parse *parse, const char *lckey);
char *VESmail_parse_get_boundary(struct VESmail_parse *parse);
int VESmail_parse_set_boundary(struct VESmail_parse *parse, const char *bnd);

int VESmail_parse_apply_nested(struct VESmail_parse *parse);
int VESmail_parse_apply_encode(struct VESmail_parse *parse);
int VESmail_parse_apply_decode(struct VESmail_parse *parse);

int VESmail_parse_convert(struct VESmail_parse *parse, char **dst, int final, const char *src, int srclen);
void VESmail_parse_free(struct VESmail_parse *parse);
