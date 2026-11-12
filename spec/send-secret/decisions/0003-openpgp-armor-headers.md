# 0003: Keep armor header lines out of OpenPGP output

- Status: research
- Blocks: M1 T08b (armored OpenPGP output), T11 interop on armor headers.
  Binary OpenPGP output and age are not affected.
- SPEC refs: S-8, FR-12, decision 0002 (encrypt-to-self sub-decision),
  section 14 (no own armor code)

## Question

gpg.conf `comment <text>` and `emit-version` make gpg write `Comment:` and
`Version:` lines into the armor. These lines are outside the encryption. A
comment often names the user ("Sent by Jane <jane@example.org>"), so a
forwarded or leaked message would show who sent it. The human's rule for
decision 0002 is "don't expose ... any sensitive info about me ... ensure
good security practices". How do we make sure armored OpenPGP output has no
armor header lines, when we drive gpg through gpgme?

## Context

Checked 2026-11-12 in the devcontainer (gpg 2.4.9, gpgme 2.0.1):

- With `comment Sent by Sender <sender@example.org>` and `emit-version` in a
  temp gpg.conf, `gpg -a -e` writes:

  ```
  -----BEGIN PGP MESSAGE-----
  Version: GnuPG v2
  Comment: Sent by Sender <sender@example.org>
  ```

  With `--no-comments --no-emit-version` on the command line the header
  lines are gone. gpg's defaults have neither line, so this only hits users
  who set these options.
- gpgme starts gpg with its own argument list. The strings in
  `libgpgme.so` (2.0.1) include `--no-encrypt-to`, `--no-auto-check-trustdb`,
  `--no-symkey-cache` and others, but not `--no-comments` or
  `--no-emit-version`. The context flags found (`full-status`,
  `raw-description`, `override-session-key`, `request-origin`,
  `auto-key-locate`, `trust-model`, `extended-edit`, `known-notations`) do
  not include a way to pass extra gpg arguments. Not checked: the gpgme
  source and docs in full. A research agent should confirm.
- `gpgconf --list-options gpg` does not list `comment` or `emit-version`, so
  we cannot read or change them through gpgconf.
- RFC 9580 section 6.2: armor headers are optional key/value lines between
  the BEGIN line and a blank line. The CRC (if any) and base64 body do not
  cover them, so removing them does not change the message.

## Options

### A. Strip armor header lines from gpgme's armored output
A small streaming filter on the output: after the BEGIN line, drop lines up
to the first blank line, keep the rest byte for byte.
Pros:
- Works with any user gpg.conf. No new tools.
- Easy to test (temp gpg.conf with `comment` and `emit-version`).
Cons:
- Touches armor text in our code. It does not encode or decode anything,
  but section 14 says no own armor code. Needs the human to say this filter
  is fine.
- Must be careful: only the first header block, CRLF line ends, never
  touch the body.

### B. Ask gpgme for binary, armor with gpg
Run gpgme in binary mode, then pipe through `gpg --enarmor`.
Cons:
- `--enarmor` writes `BEGIN PGP ARMORED FILE`, not `PGP MESSAGE`. Other
  tools may not accept it. Also honors `comment`. Rejected.

### C. Run gpg with a private options file
Point gpg at our own `--options` file or home, so gpg.conf is not read.
Cons:
- gpgme cannot pass `--options`. A separate home loses the user's keyring
  and agent setup. Ignoring gpg.conf also drops settings users want
  (keyserver, trust model, compliance). Rejected unless gpgme adds a way.

### D. Detect the options and refuse
Read gpg.conf (and `common.conf`) ourselves; if `comment` or
`emit-version` is set, refuse armored OpenPGP output with a clear error, or
fall back to binary output.
Pros:
- No change to gpg's output bytes.
Cons:
- Parsing gpg config ourselves is fragile (includes, `--options`,
  `GNUPGHOME`, global `/etc/gnupg/gpg.conf`). Easy to miss a case.
- Worse UX for users who set a comment.

### E. Patch or extend gpgme upstream
Ask gpgme for a context flag that adds `--no-comments --no-emit-version`.
Pros:
- Clean long-term fix.
Cons:
- Not available on Fedora 45 now. Can be done in addition to A or D.

## Preferred option and why

Not researched yet. First look: A (strip the header block in a streaming
filter) plus E upstream. A research agent should confirm the gpgme facts
and the section 14 question.

## Sources

- RFC 9580, section 6.2 (armor headers): https://www.rfc-editor.org/rfc/rfc9580.html#section-6.2
- gpg options `--comment`, `--no-comments`, `--emit-version`:
  https://www.gnupg.org/documentation/manuals/gnupg/GPG-Esoteric-Options.html
- gpgme context flags (`gpgme_set_ctx_flag`):
  https://www.gnupg.org/documentation/manuals/gpgme/Context-Flags.html
- Local check: devcontainer, `gpg` 2.4.9, `gpgme` 2.0.1, `strings` on
  `libgpgme.so`.

## Human decision
