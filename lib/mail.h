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
 * (c) 2020-2026 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * Apache License, Version 2.0
 * You may use, copy, modify, merge, publish, distribute and/or sell copies
 * of the Software under the terms of the Apache License, Version 2.0, a copy
 * of which is provided in the COPYING file, or http://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
 *
 ***************************************************************************/

typedef struct VESmail {
    struct libVES *ves;
    struct VESmail_optns *optns;
    struct libVES_VaultItem *vaultItem;
    short int flags;
    short int error;
    char *msgid;
/****************************
    None of the fields below are needed for a decrypt-only fragment parser,
    such as for VESmail_imap_msg
*****************************/
    struct VESmail_parse *root;
    struct VESmail_xform *out;
    char *nowUrl;
    struct libVES_List *share;
    void (*logfn)(void *logref, const char *fmt, ...);
    void *logref;
} VESmail;

struct VESmail_parse;
struct VESmail_header;

#define	VESMAIL_F_ENCD		0x0100
#define	VESMAIL_F_BANNER_ADDED	0x0200
#define	VESMAIL_F_PASS		0x0800

#define	VESMAIL_F_INIT		0

struct VESmail *VESmail_init(struct VESmail *mail, struct libVES *ves, struct VESmail_optns *optns);
struct VESmail *VESmail_new(struct libVES *ves, struct VESmail_optns *optns, int (* headerfn)(struct VESmail_parse *, struct VESmail_header *));
struct libVES_VaultItem *VESmail_get_vaultItem(struct VESmail *mail);
struct libVES_Cipher *VESmail_get_cipher(struct VESmail *mail);
int VESmail_cipher_ready(struct VESmail *mail);
int VESmail_decrypt_error(struct VESmail *mail);
void VESmail_unset_vaultItem(struct VESmail *mail);
int VESmail_add_rcpt(struct VESmail *mail, const char *rcpt, int update_only);
int VESmail_save_ves(struct VESmail *mail);
struct VESmail *VESmail_new_encrypt(struct libVES *ves, struct VESmail_optns *optns);
struct VESmail *VESmail_new_decrypt(struct libVES *ves, struct VESmail_optns *optns);
struct VESmail *VESmail_set_out(struct VESmail *mail, struct VESmail_xform *xform);
int VESmail_convert(struct VESmail *mail, char **dst, int final, const char *src, int srclen);
void VESmail_inject_header(struct VESmail *mail, struct VESmail_header *hdr);
const char *VESmail_nowUrl(struct VESmail *mail);
void VESmail_clean(struct VESmail *mail);
void VESmail_free(struct VESmail *mail);
