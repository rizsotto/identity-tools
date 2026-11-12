# M1: Read-only inventory

Source: [SPEC 12, M1](../../SPEC.md#m1-read-only-inventory). Nothing in M1
changes a key, a server or a forge account.

## Requirements in scope

- [FR-1](../../SPEC.md#functional) key list fields
- [FR-2](../../SPEC.md#functional) location model
- [FR-3](../../SPEC.md#functional) SSH server check
- [FR-4](../../SPEC.md#functional) forge check (list and compare fingerprints)
- [NFR-1](../../SPEC.md#non-functional) private keys stay in GnuPG and `~/.ssh`
- [NFR-2](../../SPEC.md#non-functional) network calls are logged per workflow
- [NFR-4](../../SPEC.md#non-functional) viewing works offline
- [S-1](../../SPEC.md#10-security-rules-must) header-only check of private key files
- [S-4](../../SPEC.md#10-security-rules-must) tokens never in logs or errors
- [S-5](../../SPEC.md#10-security-rules-must) BatchMode, no silent host key accept
- [SPEC 9.4](../../SPEC.md#94-weak-key-rules-v1) weak key rules
- Use cases UC-1, UC-2 (check part), UC-7

Out of scope for M1: any add or remove, rotation, journal, reminders, UI,
import/export (FR-12), VKS and WKD providers.

## Acceptance criteria

Tick each box with evidence: a test name or command output.

### Keys

- [ ] Lists SSH keys from an SSH dir (temp `HOME` in tests) with all FR-1
      fields: comment, type, bits or curve, fingerprint, created, expiry,
      location count, warnings. ([FR-1](../../SPEC.md#functional))
- [ ] Lists OpenPGP keys from GnuPG (temp `GNUPGHOME` in tests) with all FR-1
      fields, including subkeys and their expiry. ([FR-1](../../SPEC.md#functional))
- [ ] Weak key warnings follow SPEC 9.4: RSA < 3072 warning, DSA error, ECDSA
      nistp* info, unencrypted SSH private key warning, OpenPGP key with no
      expiry info. ([9.4](../../SPEC.md#94-weak-key-rules-v1))
- [ ] The unencrypted check reads only the private key file header. No private
      key bytes are parsed or kept. ([S-1](../../SPEC.md#10-security-rules-must),
      [NFR-1](../../SPEC.md#non-functional))
- [ ] Listing keys needs no network. ([NFR-4](../../SPEC.md#non-functional))

### Locations

- [ ] Locations are stored in SQLite with kind, target, key, status
      (`verified`, `unverified`, `missing`, `error`) and `last_checked`.
      ([FR-2](../../SPEC.md#functional))
- [ ] No token column or token value in the database.
      ([S-4](../../SPEC.md#10-security-rules-must))
- [ ] Imports hosts from an SSH config file (with `Include`, skipping wildcard
      patterns) as `unverified` SSH server locations.
      ([UC-2](../../SPEC.md#2-users-and-use-cases))

### Checks

- [ ] SSH server check runs `ssh -o BatchMode=yes -o IdentitiesOnly=yes -i <key>
      -o ConnectTimeout=10 <host> true` against the test sshd. Exit 0 gives
      `verified`. A key that is not installed gives `missing`.
      ([FR-3](../../SPEC.md#functional))
- [ ] A key that is not installed gives `missing` even when the ssh config
      holds another key that logs in. Exit 0 alone is not enough. (Decision
      [0002](../../decisions/0002-ssh-test-servers.md), side finding; fix
      chosen in T12: the `ssh -v` fingerprint check, see `plan.md`.) ([S-3](../../SPEC.md#10-security-rules-must))
- [ ] An unknown host key gives `error` with a clear reason. It is never
      accepted. ([S-5](../../SPEC.md#10-security-rules-must))
- [ ] GitHub provider `list` returns SSH auth keys, SSH signing keys and GPG
      keys from the mock forge. ([FR-4](../../SPEC.md#functional))
- [ ] GitLab provider `list` does the same, with a configurable base URL for
      self-hosted instances. ([FR-4](../../SPEC.md#functional))
- [ ] Forgejo provider `list` does the same (Gitea and Codeberg use it too).
      ([FR-4](../../SPEC.md#functional))
- [ ] Forge `verify` compares fingerprints from `list` with the local key.
      ([FR-4](../../SPEC.md#functional))
- [ ] Every network call (ssh and HTTP) goes into a per-workflow log the user
      can read. ([NFR-2](../../SPEC.md#non-functional))
- [ ] A test proves tokens do not appear in logs or error text.
      ([S-4](../../SPEC.md#10-security-rules-must))

### Process

- [ ] SPEC 15 facts that M1 uses are ticked in SPEC.md with links (see
      `plan.md`).
- [ ] No test touches the real `~/.ssh`, `~/.gnupg`, a real server or a real
      forge. ([SPEC 14](../../SPEC.md#14-instructions-for-agents))
- [ ] `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`
      and `cargo test --workspace` pass in the devcontainer and in CI.
- [ ] The sshd tests run in GitHub CI. No test is `#[ignore]` or skipped.
      ([SPEC 13](../../SPEC.md#13-test-plan))
