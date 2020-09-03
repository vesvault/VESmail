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

typedef struct VESmail_imap_fetch {
    enum {
	VESMAIL_IMAP_FM_NONE,
	VESMAIL_IMAP_FM_SECTION,
	VESMAIL_IMAP_FM_START,
	VESMAIL_IMAP_FM_RANGE
    } mode;
    enum {
	VESMAIL_IMAP_FETCH_VERBS()
	VESMAIL_IMAP_FV__END
    } type;
    enum {
	VESMAIL_IMAP_FS_TEXT,
	VESMAIL_IMAP_FS_MIME,
	VESMAIL_IMAP_FS_HEADER,
	VESMAIL_IMAP_FS_HEADER_FIELDS,
	VESMAIL_IMAP_FS_HEADER_FIELDS_NOT,
	VESMAIL_IMAP_FS_NONE
    } stype;
    char _algn;
    union {
	char **fields;
	struct VESmail_imap_fetch *qchain;
    };
    unsigned long int range[2];
    int seclen;
    unsigned long int section[0];
} VESmail_imap_fetch;

#undef VESMAIL_VERB
#undef VESMAIL_VERB2

struct VESmail_imap_fetch *VESmail_imap_fetch_new(char type);
struct VESmail_imap_fetch *VESmail_imap_fetch_new_body(char type, char mode, char stype, int seclen, unsigned long int *sec);
struct VESmail_imap_fetch *VESmail_imap_fetch_parse(struct VESmail_imap_token *key);
struct VESmail_imap_token *VESmail_imap_fetch_render(struct VESmail_imap_fetch *fetch);
struct VESmail_imap_fetch **VESmail_imap_fetch_queue(struct VESmail_imap_fetch **queue, struct VESmail_imap_fetch *fetch);
struct VESmail_imap_fetch *VESmail_imap_fetch_unqueue(struct VESmail_imap_fetch **queue);
void VESmail_imap_fetch_free(struct VESmail_imap_fetch *fetch);
