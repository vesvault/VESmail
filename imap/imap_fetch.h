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

#define VESMAIL_IMAP_FETCH_VERBS() \
    VESMAIL_VERB(BODY) \
    VESMAIL_VERB2(BODY, PEEK) \
    VESMAIL_VERB(BODYSTRUCTURE) \
    VESMAIL_VERB(ENVELOPE) \
    VESMAIL_VERB(INTERNALDATE) \
    VESMAIL_VERB(FLAGS) \
    VESMAIL_VERB(UID) \
    VESMAIL_VERB(RFC822) \
    VESMAIL_VERB2(RFC822, HEADER) \
    VESMAIL_VERB2(RFC822, TEXT) \
    VESMAIL_VERB2(RFC822, SIZE)

#define VESMAIL_VERB(verb)		VESMAIL_IMAP_FV_ ## verb,
#define VESMAIL_VERB2(verb, sub)	VESMAIL_IMAP_FV_ ## verb ## _ ## sub,

#ifndef VESMAIL_ENUM
#define	VESMAIL_ENUM(_type)	unsigned char
#endif

enum VESmail_imap_fetch_mode {
    VESMAIL_IMAP_FM_NONE,
    VESMAIL_IMAP_FM_SECTION,
    VESMAIL_IMAP_FM_START,
    VESMAIL_IMAP_FM_RANGE
};
enum VESmail_imap_fetch_type {
    VESMAIL_IMAP_FETCH_VERBS()
    VESMAIL_IMAP_FV__END
};
enum VESmail_imap_fetch_stype {
    VESMAIL_IMAP_FS_TEXT,
    VESMAIL_IMAP_FS_MIME,
    VESMAIL_IMAP_FS_HEADER,
    VESMAIL_IMAP_FS_HEADER_FIELDS,
    VESMAIL_IMAP_FS_HEADER_FIELDS_NOT,
    VESMAIL_IMAP_FS_NONE
};

typedef struct VESmail_imap_fetch {
    VESMAIL_ENUM(VESmail_imap_fetch_mode) mode;
    VESMAIL_ENUM(VESmail_imap_fetch_type) type;
    VESMAIL_ENUM(VESmail_imap_fetch_stype) stype;
    union {
	char **fields;
	struct VESmail_imap_fetch *qchain;
    };
    unsigned long int range[2];
    int seclen;
    union {
	unsigned long int section[0];
	char rhash[0];
    };
} VESmail_imap_fetch;

#undef VESMAIL_VERB
#undef VESMAIL_VERB2

#ifndef VESMAIL_IMAP_FETCH_FLD_SAFENUM
#define	VESMAIL_IMAP_FETCH_FLD_SAFENUM	255
#endif
#ifndef VESMAIL_IMAP_FETCH_FLD_SAFELEN
#define	VESMAIL_IMAP_FETCH_FLD_SAFELEN	127
#endif

struct VESmail_imap_fetch *VESmail_imap_fetch_new(char type);
struct VESmail_imap_fetch *VESmail_imap_fetch_new_body(char type, char mode, char stype, int seclen, unsigned long int *sec);
struct VESmail_imap_fetch *VESmail_imap_fetch_parse(struct VESmail_imap_token *key);
struct VESmail_imap_token *VESmail_imap_fetch_render(struct VESmail_imap_fetch *fetch);

char *VESmail_imap_fetch_rhash(struct VESmail_imap_fetch *f, char *dst);
struct VESmail_imap_fetch *VESmail_imap_fetch_new_rhash(int mode, const char *rhash);
int VESmail_imap_fetch_check_rhash(struct VESmail_imap_fetch *fetch, const char *rhash);
struct VESmail_imap_fetch **VESmail_imap_fetch_queue(struct VESmail_imap_fetch **queue, struct VESmail_imap_fetch *fetch);
struct VESmail_imap_fetch *VESmail_imap_fetch_unqueue(struct VESmail_imap_fetch **queue);

void VESmail_imap_fetch_free(struct VESmail_imap_fetch *fetch);
