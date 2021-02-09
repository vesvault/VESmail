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

#define	VESMAIL_SASL_MECHS()	\
    VESMAIL_VERB(PLAIN) \
    VESMAIL_VERB(LOGIN) \
    VESMAIL_VERB(XOAUTH2)

#define	VESMAIL_VERB(verb)	VESMAIL_SASL_M_ ## verb,
enum VESmail_sasl_mech { VESMAIL_SASL_MECHS() VESMAIL_SASL__END } mech;
#undef VESMAIL_VERB

typedef struct VESmail_sasl {
    char *user;
    char *passwd;
    int pwlen;
    VESMAIL_ENUM(VESmail_sasl_mech) mech;
    short int state;
    char *(* tokenfn)(struct VESmail_sasl *, const char *token, int len);
    void (* freefn)(struct VESmail_sasl *);
    struct VESmail_sasl *chain;
    char data[0];
} VESmail_sasl;

#define	VESMAIL_SASL_SRV_LAST	VESMAIL_SASL_M_LOGIN

extern const char *VESmail_sasl_mechs[];

struct VESmail_sasl *VESmail_sasl_new_client(int mech);
struct VESmail_sasl *VESmail_sasl_new_server(int mech);
void VESmail_sasl_set_user(struct VESmail_sasl *sasl, const char *user, int len);
void VESmail_sasl_set_passwd(struct VESmail_sasl *sasl, const char *passwd, int len);
char *VESmail_sasl_process(struct VESmail_sasl *sasl, const char *token, int len);
#define VESmail_sasl_authd(sasl)	((sasl)->user && (sasl)->passwd)
#define VESmail_sasl_get_name(sasl)	(VESmail_sasl_mechs[(sasl)->mech])
void VESmail_sasl_free(struct VESmail_sasl *sasl);
