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

#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include "../VESmail.h"
#include "parse.h"
#include "mail.h"
#include "header.h"
#include "util.h"
#include "xform.h"
#include "composer.h"

/* Declared in lib/parse.c but no public header — same situation as the
 * cte encoder xformfns referenced via parse_apply_encode. */
extern int VESmail_xform_fn_in(VESmail_xform *xform, int final, const char *src, int *srclen);

struct VESmail_composer {
    VESmail *mail;
    int lasterr;
};


/*-------------------------------------------------------------------------
 * Custom hdrfn — a stripped-down sibling of VESmail_header_process_enc.
 * The composer treats every header as pass-through with one exception:
 * Content-Transfer-Encoding declares what we should *emit*, not what we
 * received. We mirror it into dstenc and force ctenc to BIN so the
 * standard apply_decode at BLANK is a no-op (input bodies are raw).
 *
 * At BLANK we run apply_encode (installs b64enc / qpenc on the body path
 * per dstenc) and apply_nested (lib/multi takes over multipart). We
 * deliberately skip apply_decode.
 *
 * On Content-Type we tag a multipart/alternative parse with
 * VESMAIL_VP_ALT so lib/multi's pre-close hook treats the alternative
 * as caller-owned and doesn't bolt on its static VESmail banner part.
 *-----------------------------------------------------------------------*/

static int composer_hdrfn(VESmail_parse *parse, VESmail_header *hdr) {
    int rs = VESmail_header_collect(parse, hdr);
    if (rs < 0) return rs;
    switch (hdr->type) {
	case VESMAIL_H_CTYPE:
	    if (parse->ctype == VESMAIL_T_ALT) parse->vespart = VESMAIL_VP_ALT;
	    break;
	case VESMAIL_H_CTENC:
	    parse->dstenc = parse->ctenc;
	    parse->ctenc  = VESMAIL_CTE_BIN;
	    break;
	case VESMAIL_H_BLANK: {
	    int r = VESmail_header_commit(parse, hdr);
	    if (r < 0) return r;
	    rs += r;
	    r = VESmail_parse_apply_encode(parse);
	    if (r < 0) return r;
	    rs += r;
	    r = VESmail_parse_apply_nested(parse);
	    if (r < 0) return r;
	    rs += r;
	    return rs;
	}
	default:
	    break;
    }
    int r = VESmail_header_commit(parse, hdr);
    if (r < 0) return r;
    return rs + r;
}


/*-------------------------------------------------------------------------
 * Public API.
 *-----------------------------------------------------------------------*/

VESmail_composer *VESmail_composer_new(void) {
    VESmail_composer *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->mail = VESmail_new(NULL, NULL, &composer_hdrfn);
    if (!c->mail) {
	free(c);
	return NULL;
    }
    return c;
}

void VESmail_composer_free(VESmail_composer *c) {
    if (!c) return;
    VESmail_free(c->mail);
    free(c);
}

int VESmail_composer_input(VESmail_composer *c,
			   const unsigned char *buf, size_t len, int final) {
    if (!c || !c->mail) return VESMAIL_E_PARAM;
    /* Wrap parse_process in an xform so the staging mechanism in
     * xform_process buffers partial input across calls. Without this,
     * a chunk that ends mid-header would drop the unconsumed tail. */
    if (!c->mail->root->in) {
	c->mail->root->in = VESmail_xform_new(
	    &VESmail_xform_fn_in, NULL, c->mail->root);
	if (!c->mail->root->in) return c->lasterr = VESMAIL_E_INTERNAL;
    }
    int r = VESmail_xform_process(c->mail->root->in, final,
				  (const char *) buf, (int) len);
    if (r < 0) c->lasterr = r;
    return r;
}

int VESmail_composer_drain(VESmail_composer *c, char **buf) {
    if (!c || !buf || !c->mail) return VESMAIL_E_PARAM;
    int r = VESmail_xform_capture_buf(c->mail->out, buf);
    if (r < 0) c->lasterr = r;
    return r;
}

size_t VESmail_composer_pending(const VESmail_composer *c) {
    if (!c || !c->mail || !c->mail->out) return 0;
    return c->mail->out->buflen > 0 ? (size_t) c->mail->out->buflen : 0;
}

int VESmail_composer_lasterror(const VESmail_composer *c) {
    return c ? c->lasterr : VESMAIL_E_PARAM;
}

char *VESmail_composer_boundary(void) {
    /* 32 hex chars = 128 bits of entropy; alphanumeric is always safe in
     * RFC 2046 boundary chars without quoting. */
    char *b = malloc(33);
    if (!b) return NULL;
    VESmail_randstr(32, b);
    b[32] = 0;
    return b;
}
