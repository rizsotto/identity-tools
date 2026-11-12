# Send Secret: rules for coding agents

Read the root `CLAUDE.md` first. The spec is `spec/send-secret/SPEC.md`.

Short version of SPEC.md sections 10 and 14. The spec wins if they differ.

- **No home-made crypto.** Only call the `age` crate and gpgme. No own
  ciphers, KDFs, padding, armor or signature code. (Section 14)
- Only the formats and key sources in section 4. Do not add more.
- Keep `crypto`, `resolver`, `trust` and `identity-core` free of GTK.
- Never send plaintext over the network. Network is for key lookups only. (S-1)
- Never write plaintext to temp files. Stream files from source to output. (S-4)
- Zero plaintext buffers after use (`zeroize`, `secrecy`). Never log
  plaintext, ciphertext or passphrases, at any level. (S-5)
- Treat every fetched or pasted key as hostile. Reject keys over 1 MB. (S-7)
- A recipient's message holds only that recipient's keys, never the sender's.
  Read-back is a separate self copy. (S-8, FR-12)
- A changed key for a pinned contact blocks encryption until the user accepts
  it. Always show the key source next to the fingerprint. (S-2, S-3)
- WKD and keys.openpgp.org results must have a user ID matching the queried
  email. Reject the rest. (S-6)
- Every key source handles: not found, timeout, malformed data, oversized data.
- Tests use a temporary `GNUPGHOME` and `HOME`, generated fixture keys and
  mocks. No real lookups. No real people's keys.
- Interop tests against `gpg` and Go `age` must pass before you commit.
- If UX and a security rule conflict, follow the rule and add the issue to
  SPEC.md section 16.
- Desktop rules D-1 to D-3 (section 7.1): public interfaces only, detect
  features at runtime, every desktop feature has a fallback.
- `crates/identity-core` (repo root) is shared with Key Steward. Keep it free
  of Send Secret specific code. Run both apps' tests when you change it. See
  `spec/decisions/0001-identity-core-sharing.md`.
