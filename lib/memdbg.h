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

/*
 * Diagnostic allocation accounting. Off by default; build with
 * -DVESMAIL_MEMDBG to compile in lightweight live/total counters for the
 * object classes on the IMAP parse hot path (see [[vesmail-proxy-oom]]).
 * When the macro is not defined every hook expands to nothing, so this
 * imposes zero cost on normal builds.
 *
 * Add a counter class by extending the enum below and the names[] table in
 * memdbg.c, then call VESMAIL_MEMDBG_INC / _DEC at the matching
 * allocation / free sites.
 */

#ifndef VESMAIL_MEMDBG_H
#define VESMAIL_MEMDBG_H

#ifdef VESMAIL_MEMDBG

enum {
    VESMAIL_MEMDBG_TOKEN = 0,	/* VESmail_imap_token */
    VESMAIL_MEMDBG_XFORM,	/* VESmail_xform */
    VESMAIL_MEMDBG_COUNT
};

/* Token live-count at which we declare a runaway (the proxy-OOM signature)
 * and trip, so a parser bug aborts the offending session instead of
 * exhausting address space. ~500k tokens is ~40 MB of token headers --
 * orders of magnitude above any legitimate single IMAP response, orders
 * of magnitude below the ~22 GB OOM. Override with -DVESMAIL_MEMDBG_TRIP. */
#ifndef VESMAIL_MEMDBG_TRIP
#define VESMAIL_MEMDBG_TRIP	500000
#endif

/* A single ATOM/QUOTED token sized above this is the proxy-OOM signature:
 * the parser allocates each atom token with capacity == remaining line
 * length (imap_xform.c), so one long line of short atoms is O(L^2) memory.
 * Legitimate atoms/quoted strings are small (bulk data uses literals), so
 * anything past 128 KB is a runaway. Override with -DVESMAIL_MEMDBG_BIGTOKEN. */
#ifndef VESMAIL_MEMDBG_BIGTOKEN
#define VESMAIL_MEMDBG_BIGTOKEN	131072
#endif

void VESmail_memdbg_inc(int kind);
void VESmail_memdbg_dec(int kind);

/* Note a token-buffer allocation of the given size; trips if it is large
 * enough to be a runaway (see VESMAIL_MEMDBG_BIGTOKEN). */
void VESmail_memdbg_bigalloc(unsigned long len);

/* Format a one-line snapshot ("token live=N total=N xform live=N total=N")
 * into buf; returns the number of chars that would have been written
 * (snprintf semantics). Thread-safe. */
int VESmail_memdbg_snprintf(char *buf, int len);

/* Non-zero once token live-count has crossed VESMAIL_MEMDBG_TRIP; auto-clears
 * once live-count falls back below the threshold (i.e. after the offending
 * session is torn down). Parser loops poll this to bail out of a runaway. */
int VESmail_memdbg_tripped(void);

/* Record a one-shot diagnostic event (printf-style). Keeps only the FIRST
 * event until it is drained, so the snippet that triggered the trip isn't
 * overwritten by noise from the abort path. */
void VESmail_memdbg_capturef(const char *fmt, ...);

/* Drain the captured event into buf (cleared after). Returns its length, or
 * 0 if nothing was captured. */
int VESmail_memdbg_event(char *buf, int len);

#define VESMAIL_MEMDBG_INC(kind)	VESmail_memdbg_inc(kind)
#define VESMAIL_MEMDBG_DEC(kind)	VESmail_memdbg_dec(kind)
#define VESMAIL_MEMDBG_TRIPPED()	VESmail_memdbg_tripped()
#define VESMAIL_MEMDBG_BIGALLOC(len)	VESmail_memdbg_bigalloc(len)

#else

#define VESMAIL_MEMDBG_INC(kind)
#define VESMAIL_MEMDBG_DEC(kind)
#define VESMAIL_MEMDBG_TRIPPED()	0
#define VESMAIL_MEMDBG_BIGALLOC(len)

#endif

#endif
