# 0003: Keep armor header lines out of OpenPGP output

- Status: accepted (keep gpg's armor as it is; no filter)
- Blocks: nothing.
- SPEC refs: S-8, FR-12, decision 0002 (encrypt-to-self sub-decision),
  section 14 (no own armor code), section 16 question 6

## Question

gpg.conf `comment <text>` and `emit-version` make gpg write `Comment:` and
`Version:` lines into the armor. These lines are outside the encryption. A
comment often names the user ("Sent by Jane <jane@example.org>"), so a
forwarded or leaked message would show who sent it. The human's rule for
decision 0002 is "don't expose ... any sensitive info about me ... ensure
good security practices". How do we make sure armored OpenPGP output has no
armor header lines, when we drive gpg through gpgme?

## Context

All checks on 2026-11-12 in a throwaway container built from
`.devcontainer/Containerfile` plus `gpgme-devel`: gpg 2.4.9, gpgme 2.0.1,
Rust `gpgme` crate 0.11.0, Go `age` 1.3.1. Source read: gpgme 2.0.1 and
2.2.0, GnuPG 2.4.9 tarballs from gnupg.org.

**What gpg writes.** Temp `GNUPGHOME`, gpg.conf with two `comment` lines
and `emit-version` four times:

```
-----BEGIN PGP MESSAGE-----
Version: GnuPG v2.4.9 (GNU/Linux)
Comment: Sent by Sender <sender@example.org>
Comment: second line

hF4DaxIOSp4UKQkSAQdA...
```

- Same through gpgme (`sign_and_encrypt_with_flags`, armor on,
  `NO_ENCRYPT_TO`). So the leak is real for our code path.
- `emit-version` repeated also leaks the exact gpg version and the OS. One
  `emit-version` gives `Version: GnuPG v2`.
- `--no-comments --no-emit-version` on the gpg command line remove both.
  The command line is read after gpg.conf, so it wins.
- gpg's defaults have neither line. Only users who set these options are
  hit.

**Which headers gpg can write** (GnuPG 2.4.9 `g10/armor.c`, the armor
writer):

- `Version:` only if `emit-version` is set. `Comment:` once per `comment`
  option. An empty `comment ""` adds nothing. Newlines in a comment are
  written as `\n`, so a comment cannot end the header block early.
- Fixed extra lines (`afx->hdrlines`) only for revocation certificates
  (`revoke.c`) and `gpg --enarmor` (`dearmor.c`:
  `Comment: Use "gpg --dearmor" for unpacking`). Not for messages.
- `Hash:` only in cleartext signatures (`sign.c`, `clearsign_file`). We
  never clearsign.
- `Charset:` and `MessageID:` are only recognized by the reader
  (`is_armor_tag`). gpg never writes them.
- After the headers gpg always writes one empty line, then the base64 body.
  The CRC is reset after the header block (`gcry_md_reset`), so it covers
  only the data.
- Line ends are LF on Linux, CRLF only on Windows builds.

**Stripping is safe for the message.** Removing the lines between the
BEGIN line and the first empty line: `gpg -d` still decrypts, `gpg
--list-packets` output is the same, and `gpg --dearmor` gives the same bytes
as for the original. Matches RFC 9580 section 6.2 (headers are not part of
the data).

**gpgme has no way to pass the options.**

- gpgme 2.0.1 `src/engine-gpg.c` builds the gpg argument list itself. No
  `--no-comments`, `--no-emit-version`, `--options` or general "extra
  arguments" hook. gpgme did pass `--no-comment` once, but that was
  changed in 2004 (`src/ChangeLog-2011`, 2004-02-01 and 2004-08-17) and is
  gone now.
- Context flags in `gpgme_set_ctx_flag` (2.0.1 and 2.2.0, the newest
  release, 2026-08-31): `redraw`, `full-status`, `raw-description`,
  `export-session-key`, `override-session-key`, `include-key-block`,
  `auto-key-import`, `auto-key-retrieve`, `request-origin`,
  `no-symkey-cache`, `ignore-mdc-error`, `auto-key-locate`, `trust-model`,
  `extended-edit`, `cert-expire`, `key-origin`, `import-filter`,
  `import-options`, `no-auto-check-trustdb`, `proc-all-sigs`,
  `known-notations` (2.2.0 adds `export-filter`). None touches armor.
  Values go into one argument (`--trust-model=VALUE`), so they cannot carry
  extra options either (and we must not try).
- Global flags (`gpgme_set_global_flag`): `debug`, `disable-gpgconf`,
  `require-gnupg`, `gpgconf-name`, `gpg-name`, `inst-type`,
  `w32-inst-dir`. `debug` (like `GPGME_DEBUG`) only sets logging. None
  touches armor.
- gpgme 2.1.x and 2.2.0 NEWS: nothing about comments or version headers.
- `gpgconf --list-options gpg` does not list `comment` or `emit-version`,
  so `gpgconf --change-options` cannot help.
- `gpgme_ctx_set_engine_info` can set a different gpg program and home dir
  per context. The Rust crate has `Context::set_engine_path` and
  `set_engine_home_dir`. See option F.
- gpgme has `GPGME_PROTOCOL_SPAWN` (`gpgme_op_spawn`) to run any program.
  The Rust crate 0.11 has `Protocol::Spawn` but no safe wrapper for
  `gpgme_op_spawn`, only `gpgme-sys`.

**age armor has no headers.** The age spec says armor is strict PEM (RFC
7468 section 3), which has no header lines. Go `age -a` output starts
`-----BEGIN AGE ENCRYPTED FILE-----` and the next line is base64.

**Crates that can write OpenPGP armor** (for option A):

- `sequoia-openpgp` 2.4.2: `armor::Writer::new(inner, Kind::Message)` is a
  streaming `Write`, writes no headers unless you use `with_headers`, and
  writes the CRC line. Needs a crypto backend even for armor. With
  `crypto-rust` the dependency tree is 256 crates.
- `pgp` (rPGP) 0.21.1: `armor::write(&impl Serialize, BlockType, writer,
  headers, include_checksum)`. Takes a whole object, not a stream. 188
  crates.

## Options

### A. Binary from gpgme, armor with a crate
Ask gpgme for binary output and armor it with `sequoia-openpgp` (streaming)
or `pgp`.
Pros:
- No header lines unless we ask. Well tested armor code, not ours.
- Works with any gpg.conf.
Cons:
- Breaks the letter of section 14 more than B does: "Only call `age` and
  gpgme". Adds a full OpenPGP library (188 to 256 crates) to use one small
  part. Section 8 lists Sequoia as a later backend, not a helper.
- Armor is encoding, not crypto, so it is not "home-made crypto". But the
  send-secret CLAUDE.md lists armor by name, so it needs the human anyway.
- `pgp` has no streaming armor writer, so large files would sit in memory
  (ciphertext, so S-4 holds, but it is wasteful).
- Two armor writers in the product (gpg's for exported keys, the crate's for
  messages). More surface for interop bugs.

### B. Strip the header block from gpg's armor (preferred)
A small streaming `Write` filter between gpgme and the output. It drops the
lines between the BEGIN line and the first empty line. It passes every byte
after that through unchanged.
Pros:
- Works with any gpg.conf, `common.conf`, global `/etc/gnupg/gpg.conf`, and
  any future header gpg might add. Enforces the S-8 rule on the output
  itself, not on how gpg was set up.
- No new crate, no new program. About 50 lines of Rust plus tests.
- It never encodes, decodes, computes a CRC or reads packets. The body and
  the CRC are gpg's bytes. Checked above: decrypt, packets and dearmored
  bytes stay the same.
- A bug shows up loudly: a broken message fails the interop tests, a kept
  header fails the header test. It cannot weaken the encryption.
Cons:
- It is code that touches armor text. The human must agree that dropping
  optional header lines is not "own armor code" under section 14.
- Must be strict: only the first header block, LF and CRLF, write nothing
  until the block is done, fail if the shape is not what gpg writes.

### C. Private gpg.conf or home dir
Point gpg at a home dir with our own gpg.conf, or set engine options.
Cons:
- gpgme cannot pass `--options` or `--no-options` (see Context).
- A different home dir means a different gpg-agent socket and keyring. The
  user's secret key for signing and the self copy are gone. Copying or
  linking the keyring is a side effect and fragile.
- No ctx flag, global flag, `GPGME_DEBUG` or gpgconf option controls
  comments. Rejected.

### D. Call gpg directly
Either for the whole job (`gpg --no-comments --no-emit-version ...`), or
only for armor.
Cons:
- Armor only: `gpg --enarmor` writes `BEGIN PGP ARMORED FILE`, not `PGP
  MESSAGE`, and adds its own `Comment: Use "gpg --dearmor" for unpacking`
  line (`dearmor.c`). Rejected.
- Whole job: we would parse `--status-fd` output, pass fds and handle the
  agent ourselves. That is what gpgme is for (section 8). Through
  `gpgme_op_spawn` it would need unsafe `gpgme-sys` calls. Rejected.

### E. Detect the options and refuse
Read gpg.conf ourselves, or look at the output, and refuse armored OpenPGP
(or fall back to binary) when headers would appear.
Cons:
- Reading gpg config ourselves is fragile: `GNUPGHOME`, `--homedir`, global
  `/etc/gnupg/gpg.conf`, repeated options, `no-comments` later in the file.
  gpgconf cannot read these options.
- Looking at the output needs the same parsing as B and then gives a worse
  result (an error instead of a clean message).
- Bad UX: the user set a comment for their mail, not to break this app.
  Rejected.

### F. Wrapper program as the gpgme engine
`Context::set_engine_path` to a tiny wrapper that runs
`gpg --no-comments --no-emit-version "$@"`.
Pros:
- Checked: gpgme accepts it (version check passes) and the armor has no
  header lines. The message decrypts and verifies.
- Uses gpg's own options. No armor text in our code.
Cons:
- We must ship and find an executable (Flatpak path, dev builds, tests) and
  find the real gpg for it. gpgme's normal gpgconf based lookup is skipped.
- A program in the crypto path that runs whatever it finds. If its path or
  its target can be changed, that is code execution. More to get wrong than
  B.
- Only covers the two options we know. B covers any header.
- Fallback if the human reads section 14 strictly and rejects B.

### G. Ask gpgme upstream for a flag
A context flag such as `no-comments` that adds `--no-comments
--no-emit-version`.
Pros:
- Clean long term fix.
Cons:
- Not in any release up to 2.2.0. Fedora 45 has 2.0.1. Can only come in
  addition to B. Not filed yet.

## Preferred option and why

**B: strip the armor header block in a strict streaming filter.** Also file
G upstream. If gpgme ever gets the flag, set it too and keep B as the check.

Why it fits S-8: S-8 is a rule about the output ("armored output has no
armor header lines"). B enforces exactly that, on the bytes we write, for
every gpg.conf, gpg version and header kind. It also covers the self copy,
since it uses the same encrypt path.

Why it fits section 14: the rule exists so we do not write our own
ciphers, encodings or packet code, where small bugs hurt security or
interop. B writes no armor. It removes optional lines that RFC 9580 6.2
says are not part of the data, and keeps gpg's base64 and CRC byte for
byte. A is the only way to have zero armor text in our code, but it adds a
second OpenPGP library, which goes against "only call `age` and gpgme" more
than B does. Needs the human's yes on this reading. If accepted, the
implementer should add one sentence to section 14 and to
`send-secret/CLAUDE.md`, so later agents do not flag B as a violation.

Why not the others: C and D lose gpgme or the user's keyring. E is fragile
and worse for users. F works but adds an executable to the crypto path and
covers less.

### Steps for M1 (T08b)

1. In `crypto`, OpenPGP backend, add a private module (for example
   `armor_headers.rs`) with `StripArmorHeaders<W: Write>`.
2. Behavior:
   - Buffer input until the first line end. It must be exactly
     `-----BEGIN PGP MESSAGE-----` plus LF or CRLF. Else error.
   - Buffer the following lines up to the first empty line (LF or CRLF
     alone). Drop them. Cap the buffer (for example 64 KiB); over the cap
     is an error.
   - Then write the BEGIN line and one empty line (same line end as seen)
     to the real output, and pass every later byte through unchanged.
   - Write nothing to the real output before the header block is done. A
     `finish()` (or the drop path) returns an error if that point was never
     reached.
   - Errors name no content (no header text, no ciphertext, S-5).
3. Use it only when armor is on. Turn on gpgme armor
   (`Context::set_armor(true)`) and wrap the output writer. Binary output
   does not use the filter.
4. Keep gpgme for everything else. No other gpg arguments, no engine path
   change.
5. On acceptance: add the section 14 note (see above). File the gpgme
   request (G) and link it here.

### Tests for M1

Unit tests (T08b, no gpg needed):
- `strip_no_headers_is_identity`: gpg style input without headers comes out
  byte for byte the same.
- `strip_removes_comment_and_version`: input with `Version:` and two
  `Comment:` lines comes out with BEGIN, empty line, body unchanged.
- `strip_crlf`: same with CRLF line ends.
- `strip_one_byte_writes`: feed the input one byte at a time and in random
  chunk sizes. Same result.
- `strip_body_untouched`: the bytes after the empty line equal the input
  bytes after its empty line.
- `strip_rejects_missing_begin`, `strip_rejects_other_begin` (for example
  `PGP SIGNATURE`), `strip_rejects_no_empty_line_within_cap`,
  `strip_rejects_truncated_input` (finish before the block ends). In each
  case nothing reached the real output.

Integration tests (T08b, temp `GNUPGHOME`, already listed):
- `openpgp_armor_has_no_comment_or_version`: temp gpg.conf with two
  `comment` lines and four `emit-version` lines. Armored output: line 1 is
  the BEGIN line, line 2 is empty. Run for a recipient message and for the
  self copy, sign on and off.
- `openpgp_armor_stripped_still_decrypts`: same setup, `gpg -d` opens it
  and the signature is good.

Interop (T11, already listed): `interop_armor_has_no_comment_or_version`
with the CLI and the same gpg.conf; `gpg --dearmor` of our output works and
`gpg -d` gives the plaintext.

## Sources

- RFC 9580, section 6.2 (armor headers): https://www.rfc-editor.org/rfc/rfc9580.html#section-6.2
- gpg options `--comment`, `--no-comments`, `--emit-version`:
  https://www.gnupg.org/documentation/manuals/gnupg/GPG-Esoteric-Options.html
- GnuPG 2.4.9 source, https://gnupg.org/ftp/gcrypt/gnupg/gnupg-2.4.9.tar.bz2 :
  `g10/armor.c` (header writer, `is_armor_tag`, CRC reset), `g10/gpg.c`
  (`oComment`, `oNoComments`, `oEmitVersion`), `g10/sign.c`
  (`clearsign_file`, `Hash:`), `g10/dearmor.c` and `g10/revoke.c`
  (`hdrlines`).
- gpgme 2.0.1 source, https://gnupg.org/ftp/gcrypt/gpgme/gpgme-2.0.1.tar.bz2 :
  `src/engine-gpg.c` (`build_argv`, `gpg_set_engine_flags`), `src/gpgme.c`
  (`gpgme_set_global_flag`, `gpgme_set_ctx_flag`), `src/ChangeLog-2011`
  (2004 `--no-comment` entries).
- gpgme 2.2.0 source and NEWS, https://gnupg.org/ftp/gcrypt/gpgme/gpgme-2.2.0.tar.bz2
- gpgme context flags and engine info:
  https://www.gnupg.org/documentation/manuals/gpgme/Context-Flags.html ,
  https://www.gnupg.org/documentation/manuals/gpgme/Crypto-Engine.html
- Rust `gpgme` crate 0.11.0 source (`src/context.rs`: `set_engine_path`,
  `set_flag`, `set_armor`; `src/lib.rs`: `Protocol::Spawn`):
  https://docs.rs/gpgme/0.11.0/gpgme/
- `sequoia-openpgp` 2.4.2 `src/armor.rs` (`Writer::new`, `with_headers`,
  CRC): https://docs.rs/sequoia-openpgp/2.4.2/sequoia_openpgp/armor/
- `pgp` 0.21.1 `src/armor/writer.rs` (`write`):
  https://docs.rs/pgp/0.21.1/pgp/armor/
- age spec, ASCII armor (strict PEM, RFC 7468 section 3):
  https://github.com/C2SP/C2SP/blob/main/age.md#ascii-armor
- Local checks: throwaway podman image from `.devcontainer/Containerfile`
  plus `gpgme-devel`; shell and Rust probes for gpg output, stripping,
  gpgme armored and binary output, and the option F wrapper.

Unverified:
- The Rust filter itself was not written. Stripping was checked with `awk`
  on gpg output, not with the planned streaming code.
- `sequoia-openpgp` and `pgp` armor output was not built or tested against
  gpg. Facts about them come from their source.
- gpgme git master after 2.2.0 was not checked (the web view refused the
  request). Only release tarballs.
- Windows or other gpg builds with CRLF were not run. CRLF support comes
  from reading `armor.c`.
- How common `comment` or `emit-version` is among real users is not known.

## Human decision

2026-11-12, the human: "if the CLI tool exposes the sender, let's keep
that. We also should not invent new formats, and allow receivers to use CLI
commands to reveal the secret. If signing with our public key allows the
receiver to validate the sender, allow this option too. I think this is part
of a good security practice and does not contradict my previous advice."

Applied:
- None of options A to F. We use gpg's own armor through gpgme and do not
  filter or rewrite its output. `Comment:` / `Version:` lines come from the
  user's own gpg.conf, so they are the user's choice.
- Output stays standard OpenPGP and standard age. Recipients can always
  open it with plain `gpg --decrypt` or `age --decrypt` (T11 interop).
- OpenPGP sign-and-encrypt stays (SPEC 9): the recipient checks the sender
  with `gpg --verify` / `gpg --decrypt`. The signature is inside the
  encryption.
- Not changed: S-8 still keeps the sender's key out of recipient messages
  (`GPGME_ENCRYPT_NO_ENCRYPT_TO`); read-back is the separate self copy.
- An age-mode sender signature (SPEC 16 q3) must use a standard format
  that recipients can check with a common tool, for example a detached
  `ssh-keygen -Y sign` signature (verify with `ssh-keygen -Y verify`). It
  stays M3 scope.
