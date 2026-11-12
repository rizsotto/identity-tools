# M2: SSH rotation

Source: [SPEC 12, M2](../../SPEC.md#m2-ssh-rotation):

- The full state machine against 2 test sshd servers (section 13) + the mock
  forges.
- Kill the app at each step: on restart it resumes correctly and never
  removes the old key early.
- `authorized_keys` options and comments are preserved (fixture tests).

M2 is headless: a library (`rotation`) and a small CLI. No GTK window (the
app ID is still open, SPEC 16 item 1).

## Requirements in scope

- [FR-2](../../SPEC.md#functional) location model: new key locations are
  added, old ones removed
- [FR-4](../../SPEC.md#functional) forge check, now with add and remove
- [FR-5](../../SPEC.md#functional) rotation state machine with a journal
- [FR-6](../../SPEC.md#functional) `authorized_keys` edits keep options,
  unrelated lines, and a backup
- [FR-10](../../SPEC.md#functional) dry-run for the rotation
- [NFR-1](../../SPEC.md#non-functional) private keys stay in `~/.ssh`
- [NFR-2](../../SPEC.md#non-functional) every ssh and HTTP call is logged
- [S-1](../../SPEC.md#10-security-rules-must) to
  [S-8](../../SPEC.md#10-security-rules-must), all of them
- [SPEC 7.2](../../SPEC.md#72-ssh-rotation-state-machine) state machine and
  its two invariants
- [SPEC 9.1](../../SPEC.md#91-editing-authorized_keys-on-a-server) editing
  `authorized_keys`
- [SPEC 9.2](../../SPEC.md#92-forge-apis-verify-exact-endpoints-and-scopes-see-15)
  forge APIs (SSH keys only)
- Use case UC-3

Out of scope for M2: OpenPGP (M3), GPG key add/remove on forges (M3),
reminders (M4), the GTK wizard, the offer to move to SSH signing (SPEC 16
item 3, deferred), import/export (FR-12), a non-default `AuthorizedKeysFile`
(refused, see below), team rotation (UC-10).

## Acceptance criteria

Tick each box with evidence: a test name or command output.

### State machine

- [ ] A full rotation runs against 2 test sshd servers and the mock GitHub,
      GitLab and Forgejo: new key made with `ssh-keygen`, added at every
      chosen location, verified at each, old key removed at each, ssh config
      `IdentityFile` lines updated (opt in), old key files moved to
      `~/.ssh/retired/`. ([FR-5](../../SPEC.md#functional),
      [UC-3](../../SPEC.md#2-users-and-use-cases),
      [7.2](../../SPEC.md#72-ssh-rotation-state-machine))
- [ ] Every remote or file action has a journal entry written before it
      starts and one after it ends, in SQLite. The journal survives a
      restart. ([FR-5](../../SPEC.md#functional),
      [SPEC 14](../../SPEC.md#14-instructions-for-agents))
- [ ] Crash at every journal point (before the action, after the action
      but before its "done" entry, after the "done" entry), then resume: the
      rotation ends in the same state as a run with no crash.
      ([SPEC 12](../../SPEC.md#m2-ssh-rotation),
      [SPEC 13](../../SPEC.md#13-test-plan))
- [ ] At every crash point, each location still has a key that logs in:
      the old key, or the new key verified there.
      ([S-3](../../SPEC.md#10-security-rules-must))
- [ ] The old key is never removed from a location before the new key is
      verified at that same location. A test where the new key cannot log
      in (sshd reads another `AuthorizedKeysFile`) ends with the old key
      still installed and the location flagged.
      ([S-3](../../SPEC.md#10-security-rules-must),
      [7.2](../../SPEC.md#72-ssh-rotation-state-machine))
- [ ] The step that removes the old key checks the new key again right
      before it, in the same run. A verify from before a restart does not
      count. ([S-3](../../SPEC.md#10-security-rules-must))
- [ ] Rotation refuses when the new key has the same fingerprint as the old
      one. ([S-3](../../SPEC.md#10-security-rules-must), M1 notes for M2)
- [ ] A failed step offers Retry, Skip location and Abort. Abort after
      install removes the new key only where the old key is still installed
      and still logs in. ([7.2](../../SPEC.md#72-ssh-rotation-state-machine))
- [ ] The old private key is never deleted. It is moved to
      `~/.ssh/retired/` only when no location still holds it, and only after
      the user confirms. ([S-2](../../SPEC.md#10-security-rules-must),
      [7.2](../../SPEC.md#72-ssh-rotation-state-machine))
- [ ] The dry-run lists every action (host or forge, file, line, HTTP
      method and path, local file moves) and changes nothing: server files,
      forge state, local files and the database are byte-identical after
      it. A real run needs an explicit confirm.
      ([FR-10](../../SPEC.md#functional),
      [S-7](../../SPEC.md#10-security-rules-must))
- [ ] Every ssh run and HTTP request of a rotation is in its network log.
      ([NFR-2](../../SPEC.md#non-functional))
- [ ] Key Steward never opens the new or old private key file. It runs
      `ssh-keygen` and `ssh` with the path.
      ([S-1](../../SPEC.md#10-security-rules-must),
      [NFR-1](../../SPEC.md#non-functional))

### `authorized_keys`

- [ ] Fixture tests: adding the new key copies the options of each old key
      line (`from=`, `command=`, `no-pty`, `restrict`, quoted values with
      spaces and `\"`). Removing the old key keeps every other line
      byte-for-byte: comments, blank lines, CRLF endings, a last line with
      no newline, `cert-authority` lines, unknown key types.
      ([FR-6](../../SPEC.md#functional),
      [SPEC 13](../../SPEC.md#13-test-plan))
- [ ] The same fixtures pass end to end through the test sshd: the file on
      the server equals the expected file byte-for-byte.
      ([FR-6](../../SPEC.md#functional))
- [ ] Each change leaves a backup `~/.ssh/authorized_keys.keysteward-<timestamp>`
      on the server. ([FR-6](../../SPEC.md#functional))
- [ ] The file is replaced with `mv` from a temp file in `~/.ssh/`. The new
      file is 0600 and `~/.ssh` is 0700; sshd with `StrictModes yes`
      accepts them. ([9.1](../../SPEC.md#91-editing-authorized_keys-on-a-server))
- [ ] If the file changed between download and upload, the apply script
      writes nothing and the step fails with a clear reason.
      ([9.1](../../SPEC.md#91-editing-authorized_keys-on-a-server))
- [ ] A symlinked `authorized_keys`, a login that runs a forced command,
      and a server where the old key is not in `~/.ssh/authorized_keys`
      are refused before any change, with a clear reason.
      ([9.1](../../SPEC.md#91-editing-authorized_keys-on-a-server),
      [S-3](../../SPEC.md#10-security-rules-must))
- [ ] Remote scripts are static files in `remote-scripts/`. User data
      reaches them only on stdin. Tests run them with `bash`, `dash` and
      `busybox sh`. ([S-6](../../SPEC.md#10-security-rules-must))
- [ ] Edits run through the generated ssh config of the M1 check (target
      block plus jump blocks, `BatchMode`, strict host keys), so they reach
      the host the check verified. ([S-5](../../SPEC.md#10-security-rules-must))

### Forges

- [ ] GitHub `add` and `remove` for SSH auth keys and SSH signing keys work
      against the mock forge. ([FR-4](../../SPEC.md#functional),
      [9.2](../../SPEC.md#92-forge-apis-verify-exact-endpoints-and-scopes-see-15))
- [ ] GitLab `add` (with the old key's `usage_type`) and `remove` work
      against the mock forge, with a self-hosted base URL.
- [ ] Forgejo `add` and `remove` work against the mock forge.
- [ ] Every write first checks that the token belongs to the target
      account (`GET /user`).
- [ ] A forge key object that serves more than one purpose (GitLab
      `auth_and_signing`, any Forgejo key) is removed only when the new key
      is verified for every purpose it serves.
      ([S-3](../../SPEC.md#10-security-rules-must))
- [ ] A lost response (the forge applied a POST or DELETE, the answer did
      not arrive) is handled on retry and on resume: no duplicate key, no
      error loop.
- [ ] Tokens are not in logs, errors, the journal or the database.
      ([S-4](../../SPEC.md#10-security-rules-must))

### Storage

- [ ] After a full rotation the database file holds neither key's public
      key text (base64 blob) nor any token. Only fingerprints, paths,
      location settings and journal rows.
      ([S-8](../../SPEC.md#10-security-rules-must),
      [S-4](../../SPEC.md#10-security-rules-must))
- [ ] Only one rotation runs at a time per database; a second start or a
      second process is refused.

### Process

- [ ] SPEC 15 facts that M2 uses are ticked in SPEC.md with links (see
      `plan.md`, "Facts"). Facts that need a real account are listed as
      human checks and are not claimed.
- [ ] No test touches the real `~/.ssh`, a real server or a real forge.
      ([SPEC 14](../../SPEC.md#14-instructions-for-agents))
- [ ] `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`
      and `cargo test --workspace` pass in the devcontainer and in GitHub
      CI. No test is `#[ignore]` or skipped.
      ([SPEC 13](../../SPEC.md#13-test-plan))

## Human checks (cannot be done by agents)

These need real accounts or tokens. They do not block the boxes above,
which are checked against mocks built from the official docs.

1. GitHub: a classic token with `write:public_key` can add an auth key and
   needs `admin:public_key` to delete it; `write:ssh_signing_key` /
   `admin:ssh_signing_key` the same for signing keys. A fine-grained token
   with "Git SSH keys" and "SSH signing keys" set to write can do both, and
   can read `GET /user`.
2. GitLab: a personal access token with `api` can add and delete
   `/user/keys`; `read_user` cannot.
3. Forgejo (Codeberg): a token with `write:user` can add and delete
   `/user/keys`.
4. The error body each forge sends for a duplicate key (GitHub 422, GitLab
   400, Forgejo 422). Record one with fake values as a fixture.
5. The bootstrap command works with a `zsh`, `fish` and `tcsh` login shell
   on a real server (the test sshd can only use the test user's shell).
6. Still open from M1: the token owner scopes for `GET /user`, Forgejo
   `link` pagination, the GNOME keyring check.
