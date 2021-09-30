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

typedef struct VESmail_xform {
    struct VESmail_xform *chain;
    union {
	void *obj;
	struct VESmail_parse *parse;
	struct VESmail_server *server;
    };
    int (* xformfn)(struct VESmail_xform *, int, const char *, int *);
    void (* freefn)(struct VESmail_xform *);
    char *buf;
    int buflen;
    int bufmax;
    int eof;
    long long int offset;
    union {
	void *data;
	struct libVES_Cipher *cipher;
	struct VESmail_xform_multi *multi;
	struct VESmail_xform_inject {
	    int (* prefn)(struct VESmail_xform *);
	    int (* postfn)(struct VESmail_xform *);
	} *inject;
	int fd;
	struct VESmail_imap_xform *imap;
	struct VESmail_imap_token *imapToken;
	struct bio_st *bio;
    };
} VESmail_xform;

#ifndef VESMAIL_BUFMINPAD
#define	VESMAIL_BUFMINPAD	256
#endif
#ifndef VESMAIL_BUFMAXPAD
#define	VESMAIL_BUFMAXPAD	1048576
#endif

struct VESmail_parse;

struct VESmail_xform *VESmail_xform_new(int (* xformfn)(struct VESmail_xform *xform, int final, const char *src, int *srclen), struct VESmail_xform *chain, void *obj);
struct VESmail_xform *VESmail_xform_new_inject(struct VESmail_parse *parse, struct VESmail_xform_inject *inject);
struct VESmail_xform *VESmail_xform_new_null(void *obj);
int VESmail_xform_process(struct VESmail_xform *xform, int final, const char *src, int srclen);
int VESmail_xform_capture_buf(struct VESmail_xform *xform, char **buf);
void VESmail_xform_free(struct VESmail_xform *xform);
struct VESmail_xform *VESmail_xform_free_chain(struct VESmail_xform *xform, void *obj);
