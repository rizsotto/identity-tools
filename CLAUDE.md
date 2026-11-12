# key-steward: notes for coding agents

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

## Key Steward rules

Short form of SPEC.md sections 10 and 14. The spec wins if they differ.

- Tests never touch real servers, real forge accounts, or the real `~/.ssh` and
  `~/.gnupg`. Use a temp `HOME` and `GNUPGHOME`, a local test sshd, and
  wiremock forges. (SPEC 14, 13)
- Never read private key bytes. Only the header, to see if a file is
  encrypted. (S-1)
- Never delete a private key without two confirmations. Move it to
  `~/.ssh/retired/` instead. (S-2)
- Never remove the old key from a location before the new key is verified at
  that location. (S-3)
- Tokens live only in Secret Service. Never in SQLite, files, logs or error
  text. (S-4, 9.2)
- Checks use `ssh -o BatchMode=yes`. Never accept unknown host keys
  silently. (S-5)
- Remote scripts are static files in `remote-scripts/`. User data goes in
  over stdin only, never into a command string. (S-6, 9.1)
- Every workflow has a dry-run, and the user confirms before any change. (S-7)
- Call `ssh`, `ssh-keygen` and GnuPG. Do not use a Rust SSH library or write
  private keys yourself. (SPEC 8)
- No GTK in `identity-core`, `inventory`, `providers` or `rotation`. No UI or
  network code in `identity-core`. (SPEC 14, 7.3)
- Every provider implements the full `Provider` trait and has mock tests
  before the UI uses it. (SPEC 14)
- Write the journal entry before a remote action and after it ends. (SPEC 14)
- Desktop rules D-1 to D-3: public interfaces only, detect at runtime, always
  a fallback. (SPEC 7.4)
- If a security rule fights convenience, follow the rule and add a note to
  SPEC section 16. (SPEC 14)
- `identity-core` may move to its own repo. Keep its API small and free of
  Key Steward types. See `spec/decisions/0001-identity-core-sharing.md`.
