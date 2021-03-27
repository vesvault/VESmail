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


#ifndef VESMAIL_ENUM
#define	VESMAIL_ENUM(_type)	unsigned char
#endif

#define	VESMAIL_OVRD_MODES()	\
    VESMAIL_VERB(AUTO, "auto") \
    VESMAIL_VERB(DENY, "deny") \
    VESMAIL_VERB(ALLOW, "allow") \
    VESMAIL_VERB(IGNORE, "ignore")

#define	VESMAIL_VERB(verb, str)	VESMAIL_OVRD_ ## verb,
enum VESmail_override_modes { VESMAIL_OVRD_MODES() VESMAIL_OVRD__END };
#undef VESMAIL_VERB

extern const char *VESmail_override_modes[];

struct libVES;
struct libVES_VaultItem;
struct VESmail_optns;
struct VESmail_conf;

typedef struct VESmail_override {
    struct VESmail_optns *optns0;
    struct VESmail_optns *optns1;
    struct jVar *jvar;
    char **banner;
    long code;
    VESMAIL_ENUM(VESmail_override_modes) mode;
} VESmail_override;

struct VESmail_override *VESmail_override_new(int mode);
int VESmail_override_load(struct VESmail_override *ovrd, const char *url, struct libVES_VaultItem *vitem, struct libVES *ves);
int VESmail_override_apply(struct VESmail_override *ovrd, struct VESmail_optns **poptns);
int VESmail_override_geterror(struct VESmail_override *ovrd, struct libVES *ves, char *buf);
int VESmail_override_mode(struct VESmail_conf *conf);
void VESmail_override_free(struct VESmail_override *ovrd);
