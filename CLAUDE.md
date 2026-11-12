# send-secret: notes for coding agents

Read `spec/SPEC.md` fully before writing code. Then read `spec/workflow.md`.
SPEC.md section 14 ("Instructions for agents") and section 10/11 (security
rules) are binding.

## Commands (run inside the devcontainer)

- Format: `cargo fmt --all`
- Lint: `cargo clippy --workspace --all-targets -- -D warnings`
- Test: `xvfb-run -a cargo test --workspace`

## Rules

- Work on the current milestone only. Its files are in `spec/milestones/MN/`.
- One task per branch and pull request. Test first.
- Never use real keys, accounts, servers or the user's real home directory in
  tests.
- Missing decision: follow "Blocked on a decision" in `spec/workflow.md`.
  Do not guess.
- If a fact in SPEC.md section 15 turns out wrong, fix SPEC.md in the same PR.

## Project rules (send-secret)

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
- `crates/identity-core` may move out of this repo. See
  `spec/decisions/0001-identity-core-sharing.md`. Keep it free of
  send-secret specific code.
