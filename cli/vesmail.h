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


#define VESMAIL_VERSION_STR	"VESmail " VESMAIL_VERSION " (c) 2020-2026 VESvault Corp"
#define VESMAIL_VERSION_SHORT	"vesmail-cli/" VESMAIL_VERSION
#define	E_PARAM		64
#define E_IO		65
#define E_VES		66
#define E_CONF		67
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
    char *confPath;
    char *veskeyPath;
    char *sni;
    char *input;
    char debug;
} params;
