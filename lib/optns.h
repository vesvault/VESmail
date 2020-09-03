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

struct VESmail;
struct VESmail_xform;

typedef struct VESmail_optns {
    int flags;
    char *vesDomain;
    char *idSuffix;
    char *idBase;
    char *subj;
    char **mime;
    char **injected;
    const char **(* getBanners)(struct VESmail_optns *);
    struct {
	char *url;
	char *dir;
    } now;
    char *acl;
} VESmail_optns;

struct VESmail_parse;

#define	VESMAIL_O_HDR_WHITE	0x0001
#define	VESMAIL_O_HDR_RCPT	0x0002
#define	VESMAIL_O_XCHG		0x0004
#define	VESMAIL_O_VES_NTFY	0x0008

extern struct VESmail_optns VESmail_optns_default;
struct VESmail_optns *VESmail_optns_new();
#define VESmail_optns_free(optns)	free(optns)

