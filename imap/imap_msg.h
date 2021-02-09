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

struct VESmail_imap;
struct VESmail_imap_token;
struct VESmail_imap_fetch;

#define VESMAIL_IMAP_HEADERS()	\
    VESMAIL_IMAP_HEADER(CONTENT_TYPE, "content-type") \
    VESMAIL_IMAP_HEADER(CONTENT_TRANSFER_ENCODING, "content-transfer-encoding") \
    VESMAIL_IMAP_HEADER(CONTENT_DISPOSITION, "content-disposition") \
    VESMAIL_IMAP_HEADER(CONTENT_ID, "content-id") \
    VESMAIL_IMAP_HEADER(CONTENT_DESCRIPTION, "content-description") \
    VESMAIL_IMAP_HEADER(MESSAGE_ID, "message-id") \
    VESMAIL_IMAP_HEADER(IN_REPLY_TO, "in-reply-to") \
    VESMAIL_IMAP_HEADER(SUBJECT, "subject")

#define VESMAIL_IMAP_HEADER(tag, hdr)	VESMAIL_IMAP_H_ ## tag,
enum VESmail_imap_msg_header { VESMAIL_IMAP_HEADERS() VESMAIL_IMAP_H__END };
#undef VESMAIL_IMAP_HEADER

#define VESMAIL_IMAP_H__MIME	VESMAIL_IMAP_H_CONTENT_TYPE
#define VESMAIL_IMAP_H__HDR	VESMAIL_IMAP_H_MESSAGE_ID

#define VESMAIL_IMAP_MF_QHDR	0x0001
#define VESMAIL_IMAP_MF_QBODY	0x0002
#define VESMAIL_IMAP_MF_QSTRUCT	0x0004
#define VESMAIL_IMAP_MF_QLEARN	0x0008
#define VESMAIL_IMAP_MF_Q	(VESMAIL_IMAP_MF_QHDR | VESMAIL_IMAP_MF_QBODY | VESMAIL_IMAP_MF_QSTRUCT | VESMAIL_IMAP_MF_QLEARN)

#define VESMAIL_IMAP_MF_PHDR	0x0100
#define VESMAIL_IMAP_MF_PBODY	0x0200

#define VESMAIL_IMAP_MF_CHKBUG	0x1000
#define VESMAIL_IMAP_MF_CFMBUG	0x2000
#define VESMAIL_IMAP_MF_OOR	0x4000

#define VESMAIL_IMAP_MF_HDR	0x00010000
#define VESMAIL_IMAP_MF_BODY	0x00020000
#define VESMAIL_IMAP_MF_STRUCT	0x00040000
#define VESMAIL_IMAP_MF_RANGE	0x00080000

#define VESMAIL_IMAP_MF_VES	0x00100000
#define VESMAIL_IMAP_MF_INJ	0x00200000
#define VESMAIL_IMAP_MF_RFC822	0x00400000

#define VESMAIL_IMAP_MF_PASS	0x01000000
#define VESMAIL_IMAP_MF_ENCD	0x02000000
#define VESMAIL_IMAP_MF_ERROR	0x04000000
#define VESMAIL_IMAP_MF_ROOT	0x08000000

#define VESMAIL_IMAP_MF_INIT	0

#define VESMAIL_IMAP_MSG_RESULTBUF	8
#define VESMAIL_IMAP_MSG_MAXHDR		255


typedef struct VESmail_imap_msg {
    union {
	struct VESmail_imap_msg *sections;
	struct VESmail_imap_msg *rfc822;
    };
    union {
	struct VESmail_imap_msg *chain;
	struct VESmail_imap_fetch *queries;
    };
    int flags;
    unsigned long int hbytes;
    unsigned long int bbytes;
    unsigned long int lines;
    struct VESmail_server *server;
    char *boundary;
    struct VESmail_header *cphdrs;
    char *headers[VESMAIL_IMAP_H__END];
    struct VESmail_imap_result *result;
    int rcount;
    char mail[0];
} VESmail_imap_msg;

union VESmail_imap_msg_page;

#define VESMAIL_IMAP_MAIL(msg)	((VESmail *) &(msg)->mail)

#define VESmail_imap_msg_PASS	(*((VESmail_imap_msg *) -1))

struct VESmail_imap_msg *VESmail_imap_msg_new(struct VESmail_server *srv);
struct VESmail_imap_msg *VESmail_imap_msg_new_part(struct VESmail_imap_msg *parent);
struct VESmail_imap_msg **VESmail_imap_msg_ptr(struct VESmail_imap *imap, unsigned int seq);
int VESmail_imap_msg_pass(struct VESmail_imap_msg *msg);
struct VESmail_imap_msg *VESmail_imap_msg_section(struct VESmail_imap_msg *parent, int seclen, unsigned long int *sec);
#define VESmail_imap_msg_isRFC822(msg)	((msg) && ((msg)->flags & VESMAIL_IMAP_MF_RFC822))
int VESmail_imap_msg_decrypt(struct VESmail_imap_msg *msg, struct VESmail_imap_msg *root, int flags, struct VESmail_imap_token *token, struct VESmail_imap_fetch *filter);
const char *VESmail_imap_msg_header(struct VESmail_imap_msg *msg, int hdr, int (* callbk)(void *arg, const char *key, const char *val), void *arg);
const char *VESmail_imap_msg_hparam(struct VESmail_imap_msg *msg, int hdr, const char *key);
char *VESmail_imap_msg_set_msgid(struct VESmail_imap_msg *msg, const char *msgid, int len);
#define VESmail_imap_msg_get_msgid(msg)	VESmail_imap_msg_set_msgid(msg, NULL, 0)
void VESmail_imap_msg_free(struct VESmail_imap_msg *msg);
void VESmail_imap_msg_page_free(union VESmail_imap_msg_page *pg, int depth, int pagesize);
