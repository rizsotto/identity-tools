# M1: Crypto core and CLI

Slice of `spec/send-secret/SPEC.md` section 12 (M1). The spec wins if this file differs.

## Goal

A `send-secret` CLI that encrypts and decrypts with OpenPGP and age, and
interoperates with `gpg` and Go `age`. No network, no UI, no TOFU store yet.

## Acceptance criteria

- [ ] `send-secret encrypt --to-key alice.pub -i msg.txt` and
  `send-secret decrypt` work for OpenPGP.
  Refs: [FR-3](../../SPEC.md#functional), [FR-7](../../SPEC.md#functional)
- [ ] The same works for age with x25519 recipients.
  Refs: FR-3, FR-7
- [ ] The same works for age with SSH Ed25519 recipients.
  Refs: FR-3, FR-4, FR-7
- [ ] The same works for age with SSH RSA recipients.
  Refs: FR-3, FR-4, FR-7
- [ ] Unsupported SSH key types (ECDSA, `sk-` keys) and SSH RSA keys
  outside 2048 to 4096 bits (the `age` crate limit) are skipped with a
  note. Refs: FR-4
- [ ] Interop: files from our CLI decrypt with `gpg`, and `gpg` output
  decrypts with our CLI.
- [ ] Interop: files from our CLI decrypt with Go `age`, and Go `age` output
  decrypts with our CLI. For each of x25519, SSH Ed25519, SSH RSA.
- [ ] Both armored text and binary output interoperate.
- [ ] Several `--to-key` files give one message per recipient, always,
  even when all share a format. Each recipient can decrypt their own
  message and cannot decrypt the others'.
  Refs: UC-8, [FR-11](../../SPEC.md#functional),
  decision [0002](../../decisions/0002-mixed-recipients.md)
- [ ] Each message uses that recipient's format: OpenPGP if their key file
  has an OpenPGP key, else age. A mix of OpenPGP and age recipients works
  and gives OpenPGP and age outputs. `--format` forces one format; a
  recipient with no key in it is an error that names them. Refs: FR-3, FR-11
- [ ] Output naming: with one recipient, `-o OUT` is the exact file, or
  stdout if `-o` is not given. With several recipients, `-o BASE` is
  required and writes `BASE.<label>.asc` (armored OpenPGP),
  `BASE.<label>.gpg` (binary OpenPGP) or `BASE.<label>.age`. The label is
  the key file name without its extension. Stdout or stdin with several
  recipients is a usage error (exit 2). Stderr lists each output and who
  it is for. Refs: FR-11
- [ ] A key file with several keys of the chosen format (for example an
  `authorized_keys` list) gives one message that each of those keys can
  open. Refs: FR-4
- [ ] No recipient's message holds the sender's key: an OpenPGP message
  lists only that recipient's key IDs (also when gpg.conf has
  `encrypt-to`), and an age message has no stanza for the sender.
  Refs: [S-8](../../SPEC.md#10-security-rules-must), decision 0002
  (encrypt-to-self sub-decision)
- [ ] Self copy: a separate message encrypted only to the sender, on by
  default, `--no-self-copy` skips it. OpenPGP uses the user's default
  secret key. age uses the user's own native X25519 identity (created on
  first use, mode 0600), never an SSH key. Format: `--format` if given,
  else OpenPGP if the user has a default secret key, else age. Written to
  `BASE.self.<ext>` next to the per-recipient files. With one recipient,
  BASE is OUT without a trailing `.asc`, `.gpg` or `.age`. The self copy
  needs `-i FILE` and `-o`; without them it is not written and stderr says
  why (exit 0). A key file labeled `self` is a usage error (exit 2).
  Refs: [FR-12](../../SPEC.md#functional), section 9, decision 0002
- [ ] OpenPGP output is signed inside the encryption (sign and encrypt in
  one operation), and decrypt reports the verified signer.
  Refs: UC-7, FR-7, section 9 ("Signing")
- [ ] Decrypt detects the format (OpenPGP armor, age armor, binary).
  Refs: FR-7
- [ ] No plaintext in temp files. Files stream from source to output. Plaintext
  buffers are zeroed. Refs: [S-4](../../SPEC.md#10-security-rules-must),
  [S-5](../../SPEC.md#10-security-rules-must), FR-8, NFR-3
- [ ] Keys over 1 MB are rejected. Refs: [S-7](../../SPEC.md#10-security-rules-must)
- [ ] Nothing logs plaintext, ciphertext or passphrases. Refs: S-5
- [ ] All tests use a temp `GNUPGHOME`, temp `HOME` and generated fixture keys.
  Refs: SPEC section 13, section 14
- [ ] `cargo fmt`, `cargo clippy -D warnings` and all tests (including
  interop) pass in CI.

## Out of scope for M1

Key lookup (M2), TOFU (M2), GTK app (M3), clipboard (M3), Files integration
(M4), the "how to open" header text (FR-6, M3).
