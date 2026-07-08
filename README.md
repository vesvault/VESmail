```
  _____
 |\    | >                   VESmail
 | \   | >  ___       ___    Email Encryption made Convenient and Reliable
 |  \  | > /   \     /   \                               https://vesmail.email
 |  /  | > \__ /     \ __/
 | /   | >    \\     //        - RFC5322 MIME Stream Encryption & Decryption
 |/____| >     \\   //         - IMAP4rev1 Transparent Proxy Server
       ___      \\_//          - ESMTP Transparent Proxy Server
      /   \     /   \          - VES Encryption Key Exchange & Recovery
      \__ /     \ __/
         \\     //    _____                     ______________by______________
          \\   //  > |\    |
           \\_//   > | \   |                    VESvault
           /   \   > |  \  |                    Encrypt Everything
           \___/   > |  /  |                    without fear of losing the Key
                   > | /   |                              https://vesvault.com
                   > |/____|                                  https://ves.host
```

# VESmail

[![CI](https://github.com/vesvault/VESmail/actions/workflows/ci.yml/badge.svg)](https://github.com/vesvault/VESmail/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/vesvault/VESmail)](COPYING)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-blue)

**Transparent, end-to-end email encryption that works with the mail client and
provider you already use.**

VESmail is a stream encryptor for RFC 5322 / MIME messages, wrapped in transparent
**IMAP** and **SMTP** proxy servers. Point your existing email client at the proxy
instead of at your provider, and mail is end-to-end encrypted on the way out and
decrypted on the way in — no plugin, no change to how you read and write email.
Encryption keys are managed and recovered through [VES](https://vesvault.com), so a
lost device doesn't mean lost mail.

- **Transparent proxies** — IMAP4rev1 and ESMTP proxies sit between your client and
  your provider, encrypting `APPEND`/outgoing mail and decrypting `FETCH`/incoming
  mail on the fly. Your provider only ever stores ciphertext.
- **Standards-preserving** — the MIME structure is kept intact: each body part becomes
  `application/vnd.ves.encrypted`, headers move into `X-VESmail-*`, and a plaintext
  banner part is injected so unencrypted clients still show something sensible.
- **Stream engine + CLI** — encrypt or decrypt a message straight from the command
  line (or embed `lib/`), with no proxy in the loop.
- **Recoverable keys** — per-message keys are shared to each recipient through VES and
  can be recovered through your trust chain, without VESvault ever seeing plaintext.

## How encryption works

Each message gets a **random encryption key**. That key is encrypted to every
recipient's VES public key (fetched from the VES repository) and the per-recipient
ciphertexts are deposited back into VES; each recipient later unwraps the key with
their own VES keychain. The message's `Message-ID` (RFC 2392) identifies the key —
if a message arrives without one, VESmail generates it.

Most RFC 822 / MIME headers and **all** body parts are encrypted under that key. Each
encrypted header travels as `X-VESmail-Header:` (base64 ciphertext), and each body part
is replaced with an `application/vnd.ves.encrypted` part. A `multipart/alternative`
container and plaintext banner parts are injected so the message still renders in a
client that doesn't know about VESmail. The decryptor reverses all of this, restoring a
message all but identical to the original and stripping the injected parts.

When a message is sent to someone **not yet on VES**, libVES may not be able to wrap the
key for them until they complete VES key exchange — see the `XCHG`/`HIGH` SMTP modes
below.

## Quick start — the CLI

Build VESmail (see [Installing](#installing)) and create your **VES account** — a
one-time browser step: sign in to the
[Profile Manager](https://my.vesmail.email/profile) with your email address, confirm
the emailed verification code and choose a VES PIN. (Without an account, `vesmail`
stops with *"VES account is not set up"*.)

Then stream a message through the encryptor and back. The account is your VES identity
in the `vesmail` domain; the first run opens the libVES keystore PIN dialog
(libVES ≥ 1.24):

```sh
vesmail encrypt -a you@example.com < message.eml > message.ves.eml
vesmail decrypt -a you@example.com < message.ves.eml > roundtrip.eml
```

To run unattended, stage a credential for the user with the `ves` CLI from libVES so the
PIN dialog is skipped — either a **session** (encrypt only, and it never reuses a
`Message-ID`) or the full **App Key** (encrypt *and* decrypt; use with care). Remove it
when you're done:

```sh
ves -a //vesmail/you@example.com/ -E sess,save     # PIN-less session  (encrypt only)
ves -a //vesmail/you@example.com/ -E save          # PIN-less App Key  (encrypt + decrypt)
ves -a //vesmail/you@example.com/ -E forget,sess   # remove the session
ves -a //vesmail/you@example.com/ -E forget,nopin  # remove the App Key
```

## The transparent proxies

The real point of VESmail is to sit transparently between your mail client and your
provider. Each proxy connects to the provider's server, relays requests and responses,
and transforms messages in flight.

To use a proxy you need a **VESmail Profile** — an end-to-end encrypted JSON object
stored in VES that holds your provider's IMAP/SMTP settings and credentials, decryptable
only by your VES keychain. Create one in the
[Profile Manager](https://my.vesmail.email/profile) — signing in with a new email
address also creates the VES account (verification code + a VES PIN of your choice).
Profiles can also be created and managed from the command line with the `ves` CLI —
see [docs/profile-cli.md](docs/profile-cli.md).

Your client then connects to the VESmail proxy and authenticates with:

- **username** — your email address (optionally `address!profile` to select a named
  profile; see [Authentication](#authentication) below).
- **password** — your VES **App Key** for VESmail (shown in the Profile Manager's
  *Email App Setup* section), which unlocks everything pertaining to your VESmail. Keep
  it secret; if it leaks, rekey the vault at [vesvault.com](https://vesvault.com).

```sh
vesmail imap  --tls      # IMAP4rev1 proxy
vesmail smtp  --tls      # ESMTP proxy
vesmail now   --tls      # HTTP mini-server for spooled encrypted mail
vesmail daemon --guard   # run the configured proxies under a restarting guard
```

### Authentication

The login `username` yields three things — the VES account (always
`ves://vesmail/<address>/`), the App Key (the password), and the VESmail **profile**,
selected by an optional suffix on the address:

| `LOGIN` username             | Selected profile                          |
|------------------------------|-------------------------------------------|
| `acme@example.com`           | `ves://vesmail/acme@example.com!`         |
| `acme@example.com!`          | `ves://vesmail/acme@example.com!` (explicit default) |
| `acme@example.com!profile1`  | `ves://vesmail/acme@example.com!profile1` |
| `acme@example.com#profile1`  | `ves://vesmail/acme@example.com%23profile1` |
| `acme@example.com##profile1` | `ves://vesmail/profile1` (shared, not namespaced to the address) |

### SMTP recipient modes

The SMTP proxy collects `RCPT TO:` addresses to share the message key with. When a
recipient isn't on VES yet, behaviour depends on the profile mode:

- **FALLBACK** — send unencrypted if *any* recipient is not on VES. Most convenient,
  least secure.
- **FAIL** — reject any recipient not on VES.
- **XCHG** — onboard new recipients with a VES temp key carried in the message headers;
  they gain access as soon as they set up their VES PIN. Convenient, slightly less
  secure than HIGH.
- **HIGH** — onboard via VES temp-key exchange completed on the *sender's* next proxy
  session; most secure, but access may be delayed until that exchange happens.

### IMAP notes

The IMAP proxy intercepts `FETCH` and `APPEND`. Because encryption is streamed, exact
part sizes aren't known until a message is fully processed, so `BODYSTRUCTURE` returns an
estimate until the message has been handled in the session. A few clients mishandle an
estimate that overshoots and loop on ranged `FETCH` past end-of-content (detected as
"OOR"); VESmail pacifies them and switches to `CALC` mode, computing exact sizes by fully
decrypting. `CALC` can also be forced in the profile. To bound memory, objects larger
than a configurable threshold are transformed as a synchronous stream rather than
buffered. Some providers (notably Yahoo/AOL) strip non-`Content-*` headers from
`BODY[*.MIME]` responses (the "MIME bug"); VESmail detects and works around it.

## Installing

Requirements:

- **libVES** — the VES client library and headers (`libVES.h`, `libVES/*.h`, `jVar.h`),
  from <https://github.com/vesvault/libVES.c>. libVES itself needs **liboqs**
  (post-quantum KEMs, on by default), OpenSSL and cURL.
- **OpenSSL** — `libcrypto` + `libssl` (<https://www.openssl.org/source/>)
- **cURL** — `libcurl` (<https://curl.se/download.html>)

GNU build (after libVES is installed):

```sh
./configure
make
sudo make install
```

Useful `configure` switches: `--without-x509store`, `--without-curlsh`,
`--without-now-oauth`.

Windows uses the same GNU toolchain under [MSYS2](https://www.msys2.org/). From the
**MSYS2 MinGW 64-bit** shell, install the dependencies (`mingw-w64-x86_64-gcc`,
`-openssl`, `-curl`, `-liboqs`, plus `autoconf automake libtool make`), build and install
libVES into `/mingw64`, then build VESmail with `./configure && make`. The
[CI workflow](.github/workflows/ci.yml) shows the exact dependency chain for Linux, macOS
and Windows.

## Repository layout

| Path | Contents |
|------|----------|
| `lib/`  | Email stream encryption / decryption engine |
| `srv/`  | Shared proxy framework — TLS, config, daemonizer, guard |
| `imap/` | IMAP4rev1 proxy |
| `smtp/` | ESMTP proxy |
| `now/`  | HTTP mini-server for instant access to spooled encrypted mail |
| `cli/`  | `vesmail` command-line front end |
| `app/`  | Native bindings (JNI) for the GUI app builds |
| `snif/` | SNIF connector ([snif.host](https://snif.host)) |
| `docs/` | Additional documentation ([CLI profile setup](docs/profile-cli.md)) |
| `etc/vesmail/`  | Sample config and template files |
| `etc/xinetd.d/` | Sample external (xinetd) daemonizer config |
| `etc/systemd/`  | Sample internal daemonizer config |

## Running as a daemon

VESmail proxies run under an internal daemonizer or an external one such as `xinetd`.
Both proxies support STARTTLS and persistent TLS. A `sni` block in the config sets up a
multi-host environment, loading a per-host config based on the negotiated SNI hostname;
SNI configs reload automatically when modified.

The internal daemonizer runs each configured proxy, and each session, in its own thread.
On \*nix, `SIGHUP` triggers a graceful shutdown and `SIGTERM` a forced one. The guard
option (`-G` / `--guard`) starts a guard process that keeps the listening sockets and
restarts terminated workers; `SIGHUP` to the guard does a graceful worker restart.

Sample configs are in `etc/vesmail/` (proxies), `etc/xinetd.d/` (external daemonizer) and
`etc/systemd/` (internal).

## Security considerations

- Run all client-to-proxy traffic over TLS unless it's on `localhost`.
- The proxy needs read access to the TLS private key; run it as a dedicated account (e.g.
  `vesmail`) and restrict write access to `vesmail.conf` and all SNI configs.
- The `audit` config option enables compliance audit: a copy of every message key is
  shared with the listed VESmail audit accounts (which must already exist on VES).
- Report security issues privately — follow [SECURITY.md](SECURITY.md) rather than opening
  a public issue or pull request.

## License

Apache License 2.0 — see [`COPYING`](COPYING). Copyright © 2020–2026 VESvault Corp.

VESmail is a client/proxy application; the VES recovery service it talks to is a separate,
hosted component and is not part of this distribution.

## Links

- VESmail — <https://vesmail.email>
- VESvault — <https://vesvault.com>
- VES documentation — <https://ves.host>
- libVES — <https://github.com/vesvault/libVES.c>
