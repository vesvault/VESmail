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
 *
 * composertest — read an RFC 5322 message from stdin, feed it through
 * VESmail_composer in chunks, write the encoded output to stdout.
 *
 * Usage:
 *     composertest [chunk_size]   < input.eml > output.eml
 *
 * chunk_size defaults to 4096. Pass 1 for byte-at-a-time streaming, or
 * a large value (e.g. 1048576) to test single-shot input.
 *
 * Exit code 0 on success; non-zero on any composer error (errno-style
 * VESMAIL_E_* propagated as |code|).
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../lib/composer.h"
#include "../VESmail.h"

static int drain_to_stdout(VESmail_composer *c) {
    while (VESmail_composer_pending(c) > 0) {
	char *out = NULL;
	int n = VESmail_composer_drain(c, &out);
	if (n < 0) {
	    fprintf(stderr, "composertest: drain error %d\n", n);
	    free(out);
	    return n;
	}
	if (n > 0 && out) fwrite(out, 1, (size_t) n, stdout);
	free(out);
	if (n == 0) break;
    }
    return 0;
}

int main(int argc, char **argv) {
    int chunk = 4096;
    if (argc > 1) {
	chunk = atoi(argv[1]);
	if (chunk < 1) chunk = 4096;
    }

    VESmail_composer *c = VESmail_composer_new();
    if (!c) {
	fprintf(stderr, "composertest: VESmail_composer_new failed\n");
	return 1;
    }

    unsigned char *buf = malloc(chunk);
    if (!buf) {
	fprintf(stderr, "composertest: malloc %d failed\n", chunk);
	VESmail_composer_free(c);
	return 1;
    }

    int rc = 0;
    for (;;) {
	ssize_t got = read(0, buf, (size_t) chunk);
	if (got < 0) {
	    perror("read");
	    rc = 1;
	    break;
	}
	int final = (got == 0) ? 1 : 0;
	int r = VESmail_composer_input(c, buf, (size_t) got, final);
	if (r < 0) {
	    fprintf(stderr, "composertest: input error %d (consumed=%d, final=%d)\n",
		    r, r, final);
	    rc = -r;
	    break;
	}
	int dr = drain_to_stdout(c);
	if (dr < 0) {
	    rc = -dr;
	    break;
	}
	if (final) break;
    }

    /* One more drain in case finishing pushed bytes through. */
    if (rc == 0) {
	int dr = drain_to_stdout(c);
	if (dr < 0) rc = -dr;
    }

    free(buf);
    VESmail_composer_free(c);
    fflush(stdout);
    return rc;
}
