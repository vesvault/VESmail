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

#ifdef VESMAIL_MEMDBG

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdatomic.h>
#include "memdbg.h"

static atomic_long VESmail_memdbg_live[VESMAIL_MEMDBG_COUNT];
static atomic_long VESmail_memdbg_total[VESMAIL_MEMDBG_COUNT];

static const char *VESmail_memdbg_names[VESMAIL_MEMDBG_COUNT] = {
    "token",
    "xform"
};

static atomic_int VESmail_memdbg_trip = 0;

/* First captured event, held until drained. Guarded by VESmail_memdbg_caplk
 * so a concurrent capture+drain can't tear the buffer; the atomic capset
 * flag makes "keep the first event" lock-free on the common (already-set)
 * path. */
static char VESmail_memdbg_capbuf[512];
static atomic_int VESmail_memdbg_capset = 0;

void VESmail_memdbg_inc(int kind) {
    if (kind < 0 || kind >= VESMAIL_MEMDBG_COUNT) return;
    long live = atomic_fetch_add(&VESmail_memdbg_live[kind], 1) + 1;
    atomic_fetch_add(&VESmail_memdbg_total[kind], 1);
    if (kind == VESMAIL_MEMDBG_TOKEN && live > VESMAIL_MEMDBG_TRIP) atomic_store(&VESmail_memdbg_trip, 1);
}

void VESmail_memdbg_dec(int kind) {
    if (kind < 0 || kind >= VESMAIL_MEMDBG_COUNT) return;
    atomic_fetch_sub(&VESmail_memdbg_live[kind], 1);
    /* Trip is NOT re-armed here: the primary signal (bigalloc) fires at a low
     * token count, so a count-based re-arm would clear it before the parser's
     * capture/abort runs. It is cleared instead when the event is drained. */
}

void VESmail_memdbg_bigalloc(unsigned long len) {
    if (len > VESMAIL_MEMDBG_BIGTOKEN) atomic_store(&VESmail_memdbg_trip, 1);
}

int VESmail_memdbg_tripped(void) {
    return atomic_load(&VESmail_memdbg_trip);
}

void VESmail_memdbg_capturef(const char *fmt, ...) {
    int expected = 0;
    /* Only the first event wins until drained. */
    if (!atomic_compare_exchange_strong(&VESmail_memdbg_capset, &expected, 1)) return;
    va_list va;
    va_start(va, fmt);
    vsnprintf(VESmail_memdbg_capbuf, sizeof(VESmail_memdbg_capbuf), fmt, va);
    va_end(va);
}

int VESmail_memdbg_event(char *buf, int len) {
    if (atomic_load(&VESmail_memdbg_capset)) {
	int l = snprintf(buf, len > 0 ? len : 0, "%s", VESmail_memdbg_capbuf);
	atomic_store(&VESmail_memdbg_capset, 0);
	atomic_store(&VESmail_memdbg_trip, 0);	/* re-arm: sessions resume */
	return l;
    }
    /* Tripped but nothing was captured (trip set outside the parser): clear it
     * anyway so we don't wedge every session permanently. */
    if (atomic_load(&VESmail_memdbg_trip)) {
	atomic_store(&VESmail_memdbg_trip, 0);
	return snprintf(buf, len > 0 ? len : 0, "tripped (no capture)");
    }
    return 0;
}

int VESmail_memdbg_snprintf(char *buf, int len) {
    int rs = 0;
    int i;
    for (i = 0; i < VESMAIL_MEMDBG_COUNT; i++) {
	int avail = len - rs;
	if (avail < 0) avail = 0;
	int r = snprintf(buf + rs, avail, "%s%s live=%ld total=%ld",
	    i ? " " : "", VESmail_memdbg_names[i],
	    (long) atomic_load(&VESmail_memdbg_live[i]),
	    (long) atomic_load(&VESmail_memdbg_total[i]));
	if (r < 0) break;
	rs += r;
    }
    return rs;
}

#endif
