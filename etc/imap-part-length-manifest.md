# IMAP part-length manifest (exact sizes via cipher meta)

Status: design, not yet implemented (2026-06-11)

## Problem

On `FETCH BODYSTRUCTURE` / `BODY[...]` of a message the proxy hasn't fully
decrypted this session, VESmail can't know the exact decrypted part sizes
because decryption is streamed. Today it reports the **upstream server's size
of the `application/vnd.ves.encrypted` part** (the base64 ciphertext) as an
estimate (`imap/imap_sect.c`, octet field left as-is; text lines faked as
`octets/48+1`). Two failure modes:

1. **Over-estimate** → Apple clients range-FETCH past real EOF, loop on OOR.
   VESmail detects repeated OOR (`imap/imap_result_proc.c` ~L398-406), pads to
   pacify, and flips on `F_CALC`, which from then on **fully decrypts every
   message** just to populate exact `bbytes`/`lines`. Correct but expensive.
2. **Under-estimate** → the ciphertext size is *not* a guaranteed upper bound.
   The client-visible length is VESmail's **re-encoding** of the plaintext
   (see below); pathological QP (every char encoded ≈ 3× raw) can exceed the
   base64 ciphertext (≈ 1.33× raw). In non-CALC mode that means promising a
   literal shorter than the real content → truncation. The README already
   half-admits this for APPEND ("the saved message will be truncated… extremely
   unlikely").

## Key fact: the length is the *re-encoded* length, not derivable from plaintext

VESmail fully **decodes** the source part and **re-encodes** it
(`lib/parse.c` `apply_decode`/`apply_encode`); on encrypt it forces
`dstenc = B64` for the ciphertext part (`lib/encrypt.c` ~L349) and stashes the
original CTE in the encrypted header. On decrypt it re-encodes the plaintext
with VESmail's **own** encoder under the restored CTE — not the original byte
stream. So the octet/line count the client ultimately sees is:

- **not** the plaintext length (QP depends on byte values),
- **not** the original encoded length (b64 wrap width / QP char choices differ).

It *is* deterministic given (plaintext bytes, target CTE, VESmail's encoder
version): closed-form for base64 (`ceil(n/3)*4` + wraps) and identity
(7bit/8bit), and a cheap streaming count for QP. The **encryptor has the
plaintext** (it just decoded it), so it can compute the exact re-encoded
size by running/counting the same encoder the decryptor will use.

## Approach: store a manifest in the libVES cipher meta

Persist the per-part **re-encoded** octet/line counts (+ root and encapsulated
`message/rfc822` header `hbytes`) at encrypt time, so the proxy reports exact
sizes on FETCH without decrypting the body.

Storage = **`libVES_Cipher` meta** (`libVES_Cipher_setMeta`/`getMeta`). This
serializes *into the cipher value itself*: `Cipher.c` `toStringl` appends
`jVar_toJSON(ci->meta)` after the key bytes; `fromStringl` parses the trailing
JSON back after the fixed-length key. That value is exactly what gets
E2E-encrypted into `vaultEntries[].encData`. Therefore the manifest is:

- **True no-leak** — inside the encrypted value, opaque to *both* the email
  provider and the VES API. (The `CiAlgo_NULL` "secret metadata only" cipher
  confirms this is the intended use.) No manual blob crypto on our side.
- **Free to read** — `libVES_VaultItem_getCipher` already parses the meta while
  deriving the key, which the proxy does anyway to decrypt headers (needed even
  for BODYSTRUCTURE, to learn real Content-Types). The proxy just calls
  `getMeta` — no extra round trip, no extra crypto.

### Why not the alternatives

- **Trailer MIME part** (`X-VESmail-Part: struct`): injected into the
  `multipart/alternative` it would interfere with the client rendering the
  banner placeholder, and a mixed-level part needs stripping on every path.
  Also a cleartext size leak, and exposed to the Yahoo/AOL non-`Content-*`
  header stripping (the existing MIMEBUG class).
- **Plaintext `meta` field on the VaultItem** (`VaultItem.c` serializes `meta`
  as top-level JSON, the slot that holds cipher algo `"a"`): trivial but
  **server-visible** — relocates the size leak from the email provider to VES.
- **Embed in the item `value` by hand**: the value is the *shared* message key
  consumed by `getCipher` on every decryptor (recipients + other VESmail
  instances). Reframing it is an ecosystem-wide protocol change. The cipher
  `meta` mechanism is the supported way to do exactly this.

## Single post at end of message

The manifest is only known after streaming all parts (QP sizes need content),
and we don't buffer the whole message. Conveniently, `VaultItem_entries`
encrypts the **value** (= cipher key + meta JSON) to each share key to produce
`encData` (`VaultItem.c` ~L309) — so the value-share *belongs* at the end once
the meta is set. And `getCipher` only needs the value decrypted in memory, not
the item posted, so the cipher is fully usable for encrypting headers/body
before any deposit.

So: **post the VaultItem exactly once, at end of message**, with the manifest
already in the cipher meta. No early post, no re-share.

- **Split, don't drop, the early step.** The top-of-message `X-VESmail-Xchg` /
  `Verify` headers (`lib/encrypt.c` ~L302-311) depend on the resolved share set
  (the `LIBVES_VK_TEMP` keys for off-VES recipients in `vi->share`). Those come
  from recipient resolution, not the post. So recipient/share resolution stays
  at the root blank line and still emits those headers; only value-set +
  `entries` + `post` slide to the end. `save_ves` effectively splits into
  "resolve shares early" / "deposit late".
- **Fail on the single post raises a VES error**, which aborts before delivery
  commit — verified below.

## Commit gate (verified)

A transformer returning negative aborts the stream to the upstream before the
message is committed:

- The xform layer latches and propagates errors: any `r < 0` sets
  `xform->eof = r` and short-circuits all downstream processing (`lib/xform.c`).
- SMTP end-of-DATA: `smtp/smtp_cmd.c` L222 calls
  `VESmail_convert(..., final=1, ...)` — where the moved `save_ves` fires during
  the encrypt parse finalization — and L223 `if (r < 0) return r;` aborts
  **before** L227 `VESmail_smtp_proxy_over(srv)`. `proxy_over`
  (`smtp/smtp_proxy.c` L406) is the commit point: it transitions to `S_HOLD`
  and registers the tracking callback that finalizes the upstream transaction.
  So a `save_ves` failure tears down before the terminating dot / commit.
- IMAP APPEND has the analogous hold point; confirm during implementation.

## Format / versioning

- Manifest in cipher meta JSON, carrying an **encoder/format version**. On
  version mismatch or absence, ignore it. Bump the version on any change to b64
  wrap width, QP encoding rules, line-ending handling, or header folding that
  affects output length (these become length-ABI-frozen per version).
- Per-part re-encoded **octets + lines**, in BODYSTRUCTURE preorder; root and
  encapsulated `message/rfc822` **hbytes** (+ bbytes/lines). Enables exact
  `RFC822.SIZE` too (`imap/imap_result_proc.c` L135/162).

## Fallback stays

Keep estimate → OOR-detect → `F_CALC` exactly as-is, as the backstop for
messages without a manifest (pre-feature, foreign-encryptor, version-mismatch).
The manifest is an optimization that also fixes the under-estimate/truncation
case; it does not replace the safety net.

## Open items before/while implementing

- Encrypt-side: insert a counting pass that re-encodes each part with its
  *original* CTE to get the exact decrypt-side length (closed-form for
  b64/identity; count for QP). Accumulate into the manifest as parts complete.
- Wire `save_ves` split (resolve early / deposit late); set cipher meta then
  single `VaultItem_post` at end; map failure to `VESMAIL_E_VES`.
- Confirm IMAP APPEND finalization has the same pre-commit hold point.
- Decrypt/proxy side: on `getCipher`, read `getMeta`; if present + version OK,
  populate exact `bbytes`/`lines`/`hbytes` and mark structure known, skipping
  both the inflated estimate and CALC.
