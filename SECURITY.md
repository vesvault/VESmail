# Security Policy

VESmail is transparent end-to-end email encryption software — it handles users' plaintext
mail, their provider credentials, and the keys that protect both. The confidentiality of
real users' email depends on it, so we take vulnerability reports seriously and appreciate
responsible disclosure.

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for security problems.**

Email **security@vesvault.com** with:

- a description of the issue and its impact,
- steps to reproduce (a proof-of-concept if you have one),
- the affected version(s) or commit, and the platform/build options, and
- whether it concerns the encryption engine, the IMAP/SMTP proxies, or the CLI.

If you need to share sensitive details, say so in your first message and we'll arrange an
encrypted channel.

We aim to **acknowledge** a report within 3 business days and to share an initial
**assessment** within 10 business days. We'll keep you updated and coordinate a disclosure
timeline with you — please give us a reasonable window to ship a fix before going public
(typically up to 90 days).

## Scope

**In scope:** the VESmail encryption/decryption engine (`lib/`), the IMAP and SMTP proxy
servers, the `now` HTTP server, and the `vesmail` CLI in this repository. We are especially
interested in:

- cryptographic correctness and anything that could expose plaintext, message keys,
  private keys, App Keys, or VESkeys to a party that should not have them,
- handling of provider credentials carried in a VESmail Profile, and of TLS private keys,
- the proxy boundary — mishandled `FETCH`/`APPEND`/`RCPT` transformations, fallback to
  unencrypted delivery, or leakage between sessions or SNI hosts,
- memory safety in the stream parsers and proxies.

**Out of scope here:** the hosted VESvault service/API (email the same address — we route
it), libVES.c itself (report via the [libVES.c](https://github.com/vesvault/libVES.c)
repository), and bugs in third-party dependencies (OpenSSL, liboqs, libcurl) — please
report those upstream as well, though we're glad to hear about them.

## Design & threat model

VESmail relies on VES for key management, exchange, and recovery. The recovery design and
its explicit, documented threat model live in the libVES.c repository
([`doc/VESrecovery.md`](https://github.com/vesvault/libVES.c/blob/master/doc/VESrecovery.md)
and [`doc/org-key-custody.md`](https://github.com/vesvault/libVES.c/blob/master/doc/org-key-custody.md))
and at <https://ves.host>. Findings that contradict those claims are especially valuable.

## Supported versions

Security fixes target the latest release on the `master` branch. Older versions are handled
case by case.
