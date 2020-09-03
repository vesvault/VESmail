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

typedef struct VESmail_header {
    const char *key;
    const char *val;
    int len;
    int type;
    struct VESmail_header *chain;
    char data[0];
} VESmail_header;

struct VESmail_parse;

enum {VESMAIL_H_UNDEF, VESMAIL_H_MSGID, VESMAIL_H_CTYPE, VESMAIL_H_CTENC, VESMAIL_H_CDISP, VESMAIL_H_SUBJ, VESMAIL_H_RCVD,
    VESMAIL_H_VES, VESMAIL_H_VESID, VESMAIL_H_PART, VESMAIL_H_XCHG, VESMAIL_H_RCPT, VESMAIL_H_NOENC, VESMAIL_H_OTHER, VESMAIL_H_BLANK};


struct VESmail_header *VESmail_header_new(const char *key, int type, int len);
struct VESmail_header *VESmail_header_dup(struct VESmail_header *hdr, struct VESmail_header *chain);

const char *VESmail_header_get_eol(const struct VESmail_header *hdr);
struct VESmail_header *VESmail_header_add_val(struct VESmail_header *hdr, int len, const char *val);
struct VESmail_header *VESmail_header_add_eol(struct VESmail_header *hdr, const struct VESmail_header *src);

char *VESmail_header_get_val(const struct VESmail_header *hdr, char *val, const char **extra);
int VESmail_header_get_ctype(const char *ctype, struct VESmail_parse *parse);
int VESmail_header_get_ctenc(const char *ctenc);
int VESmail_header_keys_values(const char *str, int len, void (* cb)(void *arg, const char *key, const char *val), void *arg);

int VESmail_header_push(struct VESmail_parse *parse, struct VESmail_header *hdr, int (* pushfn)(struct VESmail_parse *, struct VESmail_header *, int));
int VESmail_header_collect(struct VESmail_parse *parse, struct VESmail_header *hdr);
int VESmail_header_output(struct VESmail_parse *parse, struct VESmail_header *hdr);
int VESmail_header_commit(struct VESmail_parse *parse, struct VESmail_header *hdr);
int VESmail_header_divert(struct VESmail_parse *parse, struct VESmail_header *hdr);
int VESmail_header_commit_or_divert(struct VESmail_parse *parse, struct VESmail_header *hdr);
int VESmail_header_undivert(struct VESmail_parse *parse);

char *VESmail_header_apply_msgid(struct VESmail_header *hdr, struct VESmail *mail);

#define VESmail_header_free(hdr)	free(hdr)
