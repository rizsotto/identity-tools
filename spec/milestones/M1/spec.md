# M1: Crypto core and CLI

Slice of `spec/SPEC.md` section 12 (M1). The spec wins if this file differs.

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
- [ ] Unsupported SSH key types (ECDSA, `sk-` keys) are skipped with a note.
  Refs: FR-4
- [ ] Interop: files from our CLI decrypt with `gpg`, and `gpg` output
  decrypts with our CLI.
- [ ] Interop: files from our CLI decrypt with Go `age`, and Go `age` output
  decrypts with our CLI. For each of x25519, SSH Ed25519, SSH RSA.
- [ ] Both armored text and binary output interoperate.
- [ ] Multiple recipients work: each recipient can decrypt alone.
  Refs: UC-8, FR-4
- [ ] Encrypt-to-self works: OpenPGP adds the user's default secret key, age
  adds the user's own age identity (created on first run, mode 0600).
  Refs: SPEC section 4 ("Always add the sender"), section 9 ("Sender recipient")
- [ ] OpenPGP output is signed, and decrypt reports the verified signer.
  Refs: UC-7, FR-7
- [ ] Decrypt detects the format (OpenPGP armor, age armor, binary).
  Refs: FR-7
- [ ] Mixed OpenPGP and age recipients: behavior per decision
  [0002](../../decisions/0002-mixed-recipients.md). Until accepted, a clear
  error.
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
