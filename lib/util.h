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


// Internal undocumented functions of libVES
#define libVES_b64decsize(len)		((len) * 3 / 4)
#define libVES_b64encsize(len)		(((len) + 2) / 3 * 4 + 1)
char *libVES_b64encode(const char *data, size_t len, char *b64);



int VESmail_b64decode(char **dst, const char *src, int *srclen, const char **error);
#define VESmail_b64decsize(len)		libVES_b64decsize(len)
#define VESmail_b64encode(data, len, b64)	libVES_b64encode(data, len, b64)
#define VESmail_b64encsize(len)		libVES_b64encsize(len)
void VESmail_randstr(int len, char *buf);
char *VESmail_strndup(const char *s, int len);
char *VESmail_memsplice(char *str, int steml, unsigned long int *strl, int offs, int del, const char *ins, int insl);
#ifdef VESMAIL_NOCLEANSE
#define VESmail_cleanse(buf, len)	(void)0
#else
void VESmail_cleanse(void *buf, unsigned long len);
#endif
