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


#define VESMAIL_VERSION_STR	"VESmail " VESMAIL_VERSION " (c) 2020 VESvault Corp"
#define VESMAIL_VERSION_SHORT	"vesmail/" VESMAIL_VERSION
#define	E_PARAM		64
#define E_IO		65
#define E_VES		66
#define	E_INTERNAL	80

struct setfn_st {
    void *data;
    int mode;
    int (*setfn)(void *, int);
};

extern struct param_st {
    char *user;
    char *veskey;
    char *token;
    char *apiUrl;
    char *dumpfd;
    char *hostname;
    struct VESmail_optns *optns;
    char *confPath;
    char *veskeyPath;
    char **bannerPath;
    const char **banner;
    char debug;
} params;

extern struct VESmail_tls_server tls_srv;
