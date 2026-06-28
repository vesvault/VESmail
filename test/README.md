# composer CLI test

A standalone test driver for `lib/composer`. Reads an RFC 5322 message
on stdin, feeds it through the composer in chunks, writes the
encoded output to stdout.

## Build

```
make
```

Links against the system `libVES`, `libcrypto`, `libssl`.

## Run

Pass-through plain text:

```
./composertest < samples/text.eml
```

Multipart with a base64 attachment part — the binary part's body is
written *raw* in the input file; composer should emit it base64-encoded:

```
./composertest < samples/multipart.eml
```

Stress-test the streaming path one byte at a time:

```
./composertest 1 < samples/multipart.eml
```

The second argument is the input chunk size (default 4096).

## Sample line endings

The .eml samples here use LF. lib/multi accepts CRLF or LF on the
boundary line; if you want to feed strict RFC 5322 CRLF, pipe through
`unix2dos`:

```
unix2dos < samples/multipart.eml | ./composertest
```
