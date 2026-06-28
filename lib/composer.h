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
 * (c) 2026 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * Apache License, Version 2.0
 ***************************************************************************/

/*
 * Streaming MIME composer. Wraps a VESmail parser with a CTE-aware
 * header handler — the caller streams an RFC 5322 message in (headers,
 * blank line, body or `--boundary` markers for multipart), and the
 * composer emits a fully CTE-encoded RFC 5322 message out. Per-part
 * Content-Transfer-Encoding headers in the input select the encoder
 * (base64 / quoted-printable) on the body path; bodies without a CTE
 * pass through verbatim.
 *
 * All functions return either >= 0 on success or a negative VESMAIL_E_*
 * code from VESmail.h (E_PARAM, E_BUF, E_INTERNAL, ...). No
 * composer-specific error enum.
 */

#ifndef VESMAIL_COMPOSER_H
#define VESMAIL_COMPOSER_H

#include <stddef.h>

typedef struct VESmail_composer VESmail_composer;

VESmail_composer *VESmail_composer_new(void);
void              VESmail_composer_free(VESmail_composer *c);

/* Feed RFC 5322 bytes. `final` = 1 on the last chunk signals end of
 * input — encoders flush. Returns bytes processed (>=0) or VESMAIL_E_*. */
int    VESmail_composer_input  (VESmail_composer *c,
				const unsigned char *buf, size_t len, int final);

/* Captures and transfers the accumulated output. On success returns the
 * length (>=0) with *buf set to a malloc'd buffer (caller free's). When
 * there's nothing pending, returns 0 and may leave *buf NULL. */
int    VESmail_composer_drain  (VESmail_composer *c, char **buf);

/* Bytes currently queued in the drain — cheap probe before drain(). */
size_t VESmail_composer_pending(const VESmail_composer *c);

/* Last negative return seen on a public API call (0 if none). */
int    VESmail_composer_lasterror(const VESmail_composer *c);

/* 32-char hex boundary token (128 bits of entropy). Caller free's. */
char  *VESmail_composer_boundary(void);

#endif
