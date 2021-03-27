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

#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include "util.h"

int VESmail_b64decode(char **dst, const char *src, int *srclen, const char **error) {
    const char *tail = src + *srclen;
    if (!*dst) *dst = malloc((*srclen + 3) / 4 * 3);
    *srclen = 0;
    const char *s;
    int sh = 18;
    char pad = 0;
    const char *e = NULL;
    char *d = *dst;
    int r = 0;
    for (s = src; s < tail; s++) {
	char c = *s;
	int v = -1;
	switch (c) {
	    case '=':
		if (sh > 12 && !e) e = s;
		if (!pad) pad = sh + 6;
		break;
	    case ' ': case '\t': case '\r': case '\n':
		break;
	    case '+':
		v = 0x3e;
		break;
	    case '/':
		v = 0x3f;
		break;
	    default:
		if (c >= 'A' && c <= 'Z') v = c - 'A';
		else if (c >= 'a' && c <= 'z') v = c - 'a' + 0x1a;
		else if (c >= '0' && c <= '9') v = c - '0' + 0x34;
		else {
		    if (!e) e = s;
		}
		break;
	}
	if (v >= 0 || pad) {
	    if (v >= 0) {
		if (pad) {
		    if (!e) e = s;
		} else {
		    r |= v << sh;
		}
	    }
	    if (sh > 0) {
		sh -= 6;
	    } else {
		if (pad <= 16) *d++ = r >> 16;
		if (pad <= 8) *d++ = r >> 8;
		if (pad <= 0) *d++ = r;
		r = 0;
		sh = 18;
	    }
	}
	if (sh >= 18) {
	    *srclen = s - src + 1;
	    if (pad) break;
	}
    }
    if (e && error) *error = e - 1;
    return d - *dst;
}

void VESmail_randstr(int len, char *buf) {
    const static char hex[16] = "0123456789abcdef";
    int l = (len + 1) / 2;
    char *tail = buf + len;
    char *s = tail - l;
    RAND_bytes((unsigned char *) s, l);
    char *d = buf;
    char sh = 4;
    while (d < tail) {
	*d++ = hex[(*s >> sh) & 0x0f];
	sh ^= 4;
	if (sh) s++;
    }
}

char *VESmail_strndup(const char *s, int len) {
    const char *tail = memchr(s, 0, len);
    if (tail) len = tail - s;
    char *d = malloc(len + 1);
    memcpy(d, s, len);
    d[len] = 0;
    return d;
}

char *VESmail_memsplice(char *str, int steml, unsigned long int *strl, int offs, int del, const char *ins, int insl) {
    if (offs > *strl) return str;
    if (offs + del > *strl) del = *strl - offs;
    if (insl != del) {
	*strl += insl - del;
	if (insl > del) str = realloc(str, *strl + steml);
	memmove(str + steml + offs + insl, str + steml + offs + del, *strl - offs - insl);
    }
    if (insl > 0) memcpy(str + steml + offs, ins, insl);
    return str;
}
