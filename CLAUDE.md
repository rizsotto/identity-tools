# identity-tools: notes for coding agents

This repo holds two apps, Key Steward and Send Secret, and the shared
`crates/identity-core`. Read the spec of the app you work on
(`spec/<app>/SPEC.md`) fully before writing code, then `spec/workflow.md`
and the app's own `CLAUDE.md` (`key-steward/CLAUDE.md` or
`send-secret/CLAUDE.md`). SPEC sections 10 and 14 are binding.

## Commands (run inside the devcontainer)

- Format: `cargo fmt --all`
- Lint: `cargo clippy --workspace --all-targets -- -D warnings`
- Test: `cargo test --workspace`

## Rules

- Work on the current milestone only. Its files are in
  `spec/<app>/milestones/MN/`.
- One task per branch and pull request. Test first.
- Every test runs in CI. No test is skipped or ignored because it needs a
  server or a tool; put the tool in the devcontainer instead.
- Never use real keys, accounts, servers or the user's real home directory in
  tests.
- A change to `crates/identity-core` must pass both apps' tests.
- Missing decision: follow "Blocked on a decision" in `spec/workflow.md`.
  Do not guess.
- If a fact in SPEC section 15 turns out wrong, fix the SPEC in the same PR.
