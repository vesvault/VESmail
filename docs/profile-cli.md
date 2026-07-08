# Creating a VESmail profile from the CLI

A **VESmail profile** holds the provider settings and credentials a VESmail proxy
uses on your behalf. It is an end-to-end encrypted object in the VES repository:
a vault item at `ves://vesmail/<email>!<profile>` whose encrypted metadata carries
the profile JSON, decryptable only by your own VES keychain.

The usual way to manage profiles is the
[Profile Manager](https://my.vesmail.email/profile). Everything it does can also
be scripted with the `ves` CLI from [libVES.c](https://github.com/vesvault/libVES.c) —
handy for self-hosters and automation. The one step that stays in the browser is
creating the VES account itself (sign in to the Profile Manager with your email
address: verification code + a VES PIN of your choice).

## First time: create the vesmail vault

Everything VESmail belongs to an **App Vault** in the `vesmail` domain —
`ves://vesmail/<email>/`. If your VES account has never been used with VESmail,
create the vault from the CLI. Creating a secondary key requires elevated primary
authorization, so the keystore flags are `primary,elevate`:

```sh
ves -A you@example.com -E primary,elevate -a '//vesmail/you@example.com/' -n -up
```

`-n` creates the vault and `-up` prints its generated VESkey — this is your
**App Key**, the password your email client will use with the proxy (see
[below](#the-proxy-password-app-key)). If the vault already exists, the command
fails harmlessly with *"Vault key is already loaded"*.

Troubleshooting: with plain `-E primary` (no `elevate`) the post is rejected with
`API#7521 — A new vaultItem must have an entry for the creator's session vaultKey`;
the elevated session is what authorizes posting the new secondary key.

## The profile JSON

Write the profile to a file (it contains your provider password — keep it
`chmod 600`, and delete it after the upload if you prefer):

```json
{
    "imap": {
        "host": "imap.example.com",
        "port": "993",
        "tls": { "level": "high", "persist": true },
        "login": "you@example.com",
        "password": "provider-or-app-password"
    },
    "smtp": {
        "host": "smtp.example.com",
        "port": "465",
        "tls": { "level": "high", "persist": true },
        "login": "you@example.com",
        "password": "provider-or-app-password",
        "mode": "xchg"
    }
}
```

| Field | Values | Meaning |
|-------|--------|---------|
| `host`, `port` | strings | Your provider's IMAP / SMTP server. |
| `login`, `password` | strings | Your credentials **at the provider**. |
| `tls.level` | `none` `optional` `unsecure` `medium` `high` | TLS requirement for the connection to the provider (default `high`). |
| `tls.persist` | boolean | `true` = wrapped TLS (ports like 993/465), `false` = STARTTLS. |
| `sasl` | `PLAIN` `LOGIN` `XOAUTH2` | Optional; authentication mechanism at the provider (default `PLAIN`). |
| `smtp.mode` | `fallback` `fail` `xchg` `high` | [SMTP recipient mode](../README.md#smtp-recipient-modes) for recipients not yet on VES. |

## Create

The profile JSON travels as the *secret metadata* of a `NULL` cipher on the vault
item (metadata is end-to-end encrypted; `NULL` means the item carries no separate
content key). The first run opens the libVES keystore PIN dialog:

```sh
ves -a '//vesmail/you@example.com/' -o 'you@example.com!' -c NULL -z "$(cat profile.json)"
```

`you@example.com!` is the default profile — the one selected when your email
client logs in to the proxy as plain `you@example.com`. Additional named profiles
are `-o 'you@example.com!work'`, selected by logging in as `you@example.com!work`
(see [Authentication](../README.md#authentication)).

## Read back, update, delete

```sh
ves -a '//vesmail/you@example.com/' -o 'you@example.com!' -zp        # print the profile JSON
ves -a '//vesmail/you@example.com/' -o 'you@example.com!' -z "$(cat profile.json)"   # update
ves -a '//vesmail/you@example.com/' -o 'you@example.com!' --delete   # delete
```

Note the update omits `-c NULL`: it replaces the metadata on the existing cipher.
(Re-running the create command verbatim errors with *"Use '-U' to force creating a
new cipher"* — that guard protects items whose cipher holds a real content key;
for a `NULL` cipher `-U` is harmless.)

## The proxy password (App Key)

Your email client authenticates to the proxy with your VES **App Key** — the
VESkey of the vesmail vault, printed at creation by the `-n -up` command above.
For an existing vault it can be printed at any time (`-up`, or `-upf FILE` to
write it to a file):

```sh
ves -A you@example.com -E primary -a '//vesmail/you@example.com/' -up
```

## Verifying

Point your email client (or any IMAP tool) at your proxy instance and log in with
your email address and the App Key. The proxy's `XVES` error codes tell you where
a failing setup stops:

| Response | Meaning |
|----------|---------|
| `XVES-80 Denied, STARTTLS first` | The client tried plain login on a non-TLS connection — enable TLS/STARTTLS, or set the server `tls.level` to `none` for a localhost-only instance. |
| `XVES-7 Invalid or missing VESmail profile object` | Authentication succeeded but no profile was found for the selected name — check the `-o` URI against the login username. |
| `XVES-17 Connection error, check host & port in the VESmail profile` | The profile loaded and parsed; the provider `host`/`port` in it is unreachable. |

## Profile Manager interop

The Profile Manager sets a couple of extra properties on the item (item type,
share list) that the proxy itself does not require. A profile created from the
CLI works with the proxies as-is; if you later open it in the Profile Manager,
save it once there to normalize those properties.
