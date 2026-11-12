# M2 plan: SSH rotation

First draft. Status: not reviewed. Acceptance criteria are in `spec.md`.

## Summary

Rotation is a per-location state machine in the `rotation` crate. Each
action is journaled in SQLite before it starts and after it ends. On resume,
an action with a "start" entry and no "end" entry is not trusted: the engine
looks at the location (list or verify) and decides from what it sees. The
old key is removed at a location only after a fresh verify of the new key
at that location in the same run. SSH edits log in with the old key to add
and with the new key to remove, through the generated config of the M1
check. All tests run against the unprivileged test sshd (decision 0002) and
stateful fake forges, in CI.

## Crates touched

| Crate | M2 work | Must not have |
|---|---|---|
| `inventory` | Migration 2: journal tables. Journal API. `Store::remove`. | GTK, network |
| `providers` | Trait change (purpose and login key in options). `ssh_server` list/add/remove with the `authorized_keys` editor and remote scripts. GitHub, GitLab, Forgejo add/remove. | GTK |
| `rotation` | Key generation, plan and pre-flight, engine, journal replay, resume, config update, retire. | GTK, direct HTTP or ssh calls (only through `Provider`) |
| `app` (binary `key-steward`) | Headless CLI: `rotate` and `locations` subcommands. | GTK (not yet) |
| `test-support` | Several sshd servers in one client config. Stateful fake forges with fault injection. | |
| `identity-core` | Nothing. | |

The `authorized_keys` parser lives in `providers::ssh_server::authorized_keys`
for now. Decision 0001 lists a shared parser, but Send Secret only reads
plain `.keys` lines and never needs options. Move it to `identity-core`
when Send Secret needs it.

Devcontainer packages to add: `dash busybox` (remote script tests, T02).
New crates: `clap` (T16). `wiremock` is already a dev-dependency.

## Rotation model

### Units

- A **rotation** replaces one old SSH key (`old_fpr`, private path
  `old_path`) with one new key (`new_path`, `new_fpr` once made).
- A **site** is one place where the key is installed: an SSH host alias, or
  a forge account (`kind`, `base_url`, `account`).
- A **location** is a stored row (FR-2): site plus purpose. The rotation
  takes every stored location of `old_fpr` with purpose `SshAuth` or
  `SshSigning` and kind `SshServer`, `GitHub`, `GitLab` or `Forgejo`, minus
  the ones the user unticks.
- A **remote object** is the thing the remove call deletes: one
  `authorized_keys` line, one GitHub key (auth and signing are separate
  objects), one GitLab key (may serve auth and signing), one Forgejo key
  (always serves both). Removal works on remote objects, see "S-3 gate".

### States

Rotation states follow SPEC 7.2. They are derived from per-location
phases, so one slow or failed location does not hold back the others:

```
rotation: Planned → NewKeyGenerated → Installing → Verifying → ConfigUpdated
          → RemovingOld → Retired → Done
          any → Failed(step, location, error) → Retry | Skip | Abort
location: Pending → Installed → Verified → OldRemoved
          Pending|Installed|Verified → Skipped (user skipped; old key kept)
          Installed|Verified → RolledBack    (abort; new key removed, old kept)
```

`Installing(i/n)`, `Verifying(i/n)` and `RemovingOld(i/n)` in SPEC 7.2 are
counts over the location phases. All installs run before any verify, and
all verifies before any removal, as in SPEC 7.2. A location that failed
verify stays `Installed` and is flagged; the others go on to removal.
`ConfigUpdated` runs once, after the last verify and before any removal. `Retired` runs once, after the last removal. SPEC 7.2
has no `Retired` state; T12 adds it to SPEC 7.2 (SPEC 6 step 5 already
names the archive step).

### Steps and their journal entries

Each step writes `start` (commit), runs, then writes `done` or `failed`
(commit). Nothing else changes state.

| Step | Action | How resume settles a `start` with no end |
|---|---|---|
| `generate` | `ssh-keygen` into a temp dir in the ssh dir, then hard link `id` and `id.pub` to `new_path` (fails if the name exists), then remove the temp names. | Both final files exist: read `.pub`, record `new_fpr`, done. Only the private file: move it to `~/.ssh/retired/`, run again. Neither: move temp leftovers to `retired/`, run again. Never overwrite, never delete (S-2). |
| `install(L)` | Add the new key at L. SSH: log in with the old key. | List L. New key there: done. Not there: run again. |
| `verify(L)` | The M1 verify with the new key. Read-only. | Run again. |
| `remove_old(L)` | Fresh verify of the new key at L, then remove the old key. SSH: log in with the new key. | List L. Old key gone: done. Still there: run again (with a fresh verify first). SSH, old key gone: run the gated removal again (it changes nothing) to learn the `cert-authority` lines; during an abort: done, flagged "cert-authority lines not checked". |
| `rollback(L)` | Remove the new key at L. SSH: log in with the old key. | List L. New key gone: done. Else run again. |
| `config` | Rewrite matching `IdentityFile` lines (opt in). | Run again: the apply skips files that already hold the planned result and checks the others against the backup. |
| `rollback` (no location) | Abort: put the config backups back (`restore_config`). | Run again (files already restored are left alone). |
| `retire` | Move old key files to `~/.ssh/retired/` (0700). | Move again (files already moved are skipped). No new question: the `start` entry means the user said yes. |

For SSH, "list L" logs in with the key the step logs in with: the old key
while settling `install` and `rollback`, the new key while settling
`remove_old`. If that login fails, the step stays unsettled and fails;
nothing is changed.

The location store follows the steps: `verify(L)` passing adds a location
row for `new_fpr` with status `verified`; `remove_old(L)` done deletes the
old row (`Store::remove`, new in T09). Both in the same transaction as the
journal entry.

### S-3 gate (never lock the user out)

The gate is code in one function, `may_remove_old(L)`, and it is the only
way to call `Provider::remove` with the old key:

1. The rotation has `new_fpr != old_fpr` (checked at plan time and again
   here).
2. The new private key file still exists at `new_path`.
3. A verify of `new_fpr` at L, run in this process right now, returned
   `Verified`. It is not read from the journal.
4. Remote object rule: for every purpose the old key's remote object
   serves at that site, the new key is verified for that purpose too.
   GitLab: a key with `usage_type auth_and_signing` is removed only when the
   new key also has both. Forgejo: one key serves both, so the new key is
   in the same list and this holds by itself.
5. SSH: the new `authorized_keys` content still has at least one line with
   the new key, and the removal login itself uses the new key (pinned in the
   generated config). If that login fails, nothing is removed.

`rollback(L)` has the mirror gate: the old key is still listed at L and
logs in (fresh verify of `old_fpr`). Rollback is never offered for a
location in phase `OldRemoved`.

### Failure, retry, skip, abort

- A failed step stops that location, not the rotation. The CLI shows the
  error and offers Retry, Skip location, Abort.
- Retry runs the step again from the start (journal `start` again).
- Skip sets the location to `Skipped`. The old key stays there and keeps
  its location row. The old key is then not retired.
- Abort before any install: mark the rotation aborted. The new key files
  stay where they are; nothing was installed with them.
- Abort after install: offer `rollback(L)` for every location in `Installed`
  or `Verified`. Locations in `OldRemoved` keep the new key. The default
  answer is "keep the new key where it works".
- Abort with rollback sets the rotation state `aborting`. A resume then
  goes on with the abort, never forward. Abort without rollback ends an
  `aborting` rotation too (the new key stays where a rollback failed).
- A failure is "the last journal entry of that location (or of the
  rotation itself) is `failed`". A settle that cannot list the location
  writes nothing and flags it for this run only.
- A rotation that is not `Done` or aborted stays open. Start refuses a new
  rotation while one is open.

### Key generation

- `ssh-keygen -t <type> -C <comment> -f <tmpdir>/id`, default Ed25519
  (SPEC 6). RSA only with `-b 4096`.
- Passphrase: in the CLI, `ssh-keygen` inherits the terminal and asks for
  it itself, so the passphrase never passes through Key Steward and never
  appears on a command line. `--no-passphrase` passes `-N ''` (tests use
  it; the dry-run warns, SPEC 9.4). The GUI way is deferred (decisions
  README).
- An encrypted new key can only be verified through the agent (M1
  trade-off). After generation the CLI offers to run `ssh-add <new_path>`
  with the terminal inherited. If the user says no, verify returns
  `KeyNotUsable` and the step fails safely; Retry after `ssh-add`.
- Default `new_path`: `<old_path>-<YYYYMMDD>` in the same dir; must not
  exist at plan time.

### Plan and pre-flight (dry-run)

`rotate plan` (and the first part of `rotate start`) does only reads:

1. Scan the ssh dir, find the old key by path or fingerprint.
2. Load its locations. For each, run the M1 verify of the old key. A
   location where the old key is not `Verified` is listed as "not
   rotated" with the reason (for example `KeyNotUsable`: add it to the
   agent).
3. SSH sites: `list` (read script). The old key must be in
   `~/.ssh/authorized_keys` and the read must show the script's marker
   (else: forced command, or another `AuthorizedKeysFile`; refused).
4. Forge sites: `list`, token owner check. Show the token scopes each
   forge needs for writing (from "Facts").
5. Print every action in order: `ssh-keygen` command, per SSH host the
   lines to add (options shown, key shown as fingerprint) and to remove,
   per forge the method and path, the `IdentityFile` lines to change, the
   file moves. `--json` gives the same as data.

The plan writes nothing to the database. `rotate start` runs the same
pre-flight again, shows it, needs `yes` typed (or `--yes`), and only then
writes the `rotations` row.

### Config update (`ConfigUpdated`)

Opt in (`--update-config`). For the user's ssh config and the files it
includes (the list M1 `scan_config` already builds), find `IdentityFile`
lines whose value, after the same `~` and `%d` expansion as the M1 import,
equals `old_path`. Replace the value with `new_path`, keep the rest of the
line byte-for-byte. Show a diff in the plan. Write each file through a temp
file and `rename`, keep a backup `<file>.keysteward-<timestamp>`, keep the
mode. Lines with other `%` tokens are listed, not changed.

Order: `ConfigUpdated` runs after every verify and before any removal.
If config were updated after removal, `ssh <host>` would use the old key
while it is already gone from that host, and a crash or a paused rotation
would leave that state open. Rule: config is updated only if every
location of the old key is `Verified`. If any location failed verify or
was skipped, the config step is skipped and the dry-run and summary say
why: the old key still works there and the old config keeps working
everywhere. Changed from the first draft of SPEC 7.2 (orchestrator, 2026-11-12).
Abort with rollback after `ConfigUpdated`: restore the config files from the
backups before any `rollback(L)` removes the new key, so the config never
points at a key that no location accepts.

### Retire

After the last removal, if every location of the old key is `OldRemoved` (none
skipped or failed): ask, then move `old_path` and `old_path.pub` to
`~/.ssh/retired/<name>` (dir 0700, no overwrite; add `-1`, `-2` on a
clash). Never delete (S-2). If any location still holds the old key, skip
this step and say why.

### Locking

One open rotation per database (checked in the same transaction that
creates the `rotations` row). Plus an advisory `flock` on
`<data dir>/rotation.lock` for the whole run, so two processes cannot drive
the same rotation. The lock is released by the kernel when a process dies,
so a crash never leaves a stale lock.

## `authorized_keys` over SSH

### Flow (SPEC 9.1)

1. **Read.** `ssh` with the generated config (login key pinned) runs the
   bootstrap command (below) with `authorized_keys_read.sh`. It prints a
   marker line `key-steward-read v1`, then `ok <cksum> <size>` or `absent`
   or `symlink` or `notfile` or `toolarge`, then the file bytes. Limit
   1 MB.
2. **Edit locally** in Rust (`authorized_keys.rs`, pure, fixture tested).
3. **Apply.** Same login, `authorized_keys_apply.sh`. Stdin: one header
   line `<expected cksum> <expected size>`, then the new content. The script:
   - `cd "$HOME"` (the session starts in the passwd home, decision 0002),
     `umask 077`.
   - Refuses if `.ssh/authorized_keys` is a symlink or not a regular file.
   - Compares `cksum < .ssh/authorized_keys` with the header. Different:
     prints `changed` and exits 3, writes nothing.
   - Writes stdin to `.ssh/authorized_keys.keysteward-tmp.$$` with
     `set -C` (no clobber: fails if the name exists).
   - Copies the current file to
     `.ssh/authorized_keys.keysteward-<UTC timestamp>-$$` (FR-6 backup).
   - `mv -f` the temp file over `.ssh/authorized_keys` (rename in one dir,
     atomic).
   - Prints `done <cksum> <size>` of the new file.
4. **Confirm.** The app compares that checksum with its own POSIX `cksum`
   of the content it sent. Then the normal verify or list confirms the
   effect.

### Why a bootstrap command, not `sh -s` (spike, 2026-11-12)

SPEC 9.1 says `ssh host 'sh -s'` with the script on stdin. That breaks when
data follows the script on the same stdin: `dash` (Debian `/bin/sh`) and
BusyBox `sh` (Alpine) read ahead from a pipe, so the script's `read` and
`cat` find the data already eaten. Seen in containers: `debian:stable-slim`
(dash), `alpine:3.22`, `busybox:1.37` all exited 2 on the first `read`;
Fedora `bash` worked.

Fix, tested in the same four images: the remote command is a fixed string

```
sh -c 'eval "$(dd bs=1 count=<N> 2>/dev/null)"'
```

where `<N>` is the byte length of the static script, known at build time.
`dd bs=1` reads exactly the script, one byte at a time, so the data stays
in the pipe for the script's `read` and `cat`. The script is a function
`main` plus the line `main; exit $?`. The command has no user data (S-6), no
single quote inside, no backslash and no `!`, so `sh`, `bash`, `zsh`, `fish`
and `tcsh` login shells all pass it to `sh` unchanged (from their quoting
rules; only `bash` tested, human check 5). `cksum` gave the same output in
all four images. SPEC 9.1 is updated in this planning commit.

### Editing rules (pure Rust)

- Parse each line into raw bytes plus a view: blank, comment, key line
  (options, key type, base64, comment), or unknown. Keep the line ending of
  each line (LF or CRLF) and whether the last line ends in a newline.
- Options parser: comma separated, double quotes with `\"` inside, as in
  sshd(8) "AUTHORIZED_KEYS FILE FORMAT". A line whose key part does not
  parse is `unknown` and kept as is.
- Fingerprint the key part with `identity_core::parse_public_keys`.
- Lines with the `cert-authority` option hold a CA, not a login key. Never
  match, never change.
- `add_like(old_fpr, new_key)`: after each line holding `old_fpr`, insert a
  line `<same options> <new key type and base64> <new comment>` with the
  same line ending. If the new key is already there with the same options,
  do nothing (idempotent). If no line holds `old_fpr`, refuse.
- `remove(old_fpr, keep: new_fpr)`: drop every line holding `old_fpr`.
  Refuse if no line with `new_fpr` would remain. All other bytes unchanged.
- Never write more than 1 MB.

### File modes and safety

- New file 0600 (umask 077), `~/.ssh` 0700 if the script makes it (it does
  not make the file; install needs the old key already in it). A file that
  was 0644 becomes 0600; sshd accepts both. Backups are 0600.
- `StrictModes yes` in the test sshd checks the result on every login.
- Concurrent edits: the `cksum` compare catches any change made between
  read and apply (another tool, a human, another Key Steward). The window
  between the compare and the `mv` is a few instructions; a change in that
  window is lost. No lock file on the server: a crash would leave it
  behind, and our own processes are already serialized by the local lock.
- Forced command: if the login key's line has `command=`, sshd runs that
  instead and the marker line is missing. Refused in pre-flight.
- Non-default `AuthorizedKeysFile`: the old key is not in
  `~/.ssh/authorized_keys`, so pre-flight refuses. If the old key is in
  both files but sshd reads the other one, install works, verify of the new
  key gives `Missing`, and the old key stays (S-3). Test
  `new_key_not_verified_keeps_old_key`.

## Forge add and remove

Endpoints and scopes: see "Facts". All three share:

- Before any write: `GET /user` owner check (M1 `check_owner`).
- `add`: list first. If the new key is listed for that purpose, done.
  Else `POST`. 201 is success. 422 (GitHub, Forgejo) or 400 (GitLab): list
  again; if the key is there now (a retry after a lost response), done;
  else fail with the forge's message, scrubbed.
- `remove`: list, find every remote object with the fingerprint (computed
  locally from the key text, never the forge's field) and purpose, `DELETE`
  each by its id. 204 is success, 404 means already gone (list again to be
  sure). Remote ids are never stored.
- Title: `<comment> <YYYY-MM-DD>` (the new key's comment, else
  `key-steward`), so it differs from the old key's title. Forgejo and
  Gitea refuse a title the user already has (422 "Key title has been
  used"). If the title is taken in the list read before the POST, add
  ` (2)`, ` (3)`, ... until it is free.
- 401 and 403: fail with advice on the scopes the forge needs.
- Every request in the `NetLog`; tokens scrubbed (M1 `HttpClient`).
  `HttpClient` gets `post_json` and `delete`.

Per forge:

- **GitHub**: auth key `POST /user/keys` `{title, key}`, `DELETE
  /user/keys/{key_id}`. Signing key `POST /user/ssh_signing_keys`,
  `DELETE /user/ssh_signing_keys/{ssh_signing_key_id}`. Separate objects.
- **GitLab**: `POST /api/v4/user/keys` `{title, key, usage_type}`, with the
  old key's `usage_type`, `DELETE /api/v4/user/keys/{key_id}`. One object
  may serve both purposes (remote object rule).
- **Forgejo**: `POST /api/v1/user/keys` `{title, key}` (both required),
  `DELETE /api/v1/user/keys/{id}`. One object serves auth and signing.

## Provider trait change

The SPEC 7.1 sketch has no purpose on `add`/`remove`, and SSH needs to know
which key to log in with and which lines to copy options from. New shape
(T04 updates SPEC 7.1 in the same PR):

```rust
pub struct AddOpts {
    pub purpose: Purpose,
    pub title: Option<String>,
    /// SSH: copy the options of this key's lines; also the login key.
    pub like: Option<KeyRef>,
}
pub struct RemoveOpts {
    pub purpose: Purpose,
    /// SSH: log in with this key, and it must stay in the file.
    pub keep: Option<KeyRef>,
}
async fn add(&self, target: &Target, key: &PublicKey, opts: &AddOpts) -> Result<(), ProviderError>;
async fn remove(&self, target: &Target, key: &Fingerprint, opts: &RemoveOpts) -> Result<(), ProviderError>;
```

`KeyRef` already carries `identity_file`. A forge ignores `like` and
`keep` beyond the purpose. `ssh_server.list` returns one `PublicKeyRef` per
key line (purpose `SshAuth`, `remote_id` = line number, display only).

## What SQLite stores (S-8)

Migration 2 in `inventory::store`:

```sql
CREATE TABLE rotations (
    id              INTEGER PRIMARY KEY,
    created_at      INTEGER NOT NULL,
    old_fingerprint TEXT NOT NULL,
    old_key_path    TEXT NOT NULL,
    new_key_path    TEXT NOT NULL,
    new_key_type    TEXT NOT NULL,
    new_fingerprint TEXT,            -- set by the generate step
    update_config   INTEGER NOT NULL,
    state           TEXT NOT NULL,   -- cache of the replayed journal
    finished_at     INTEGER
);
CREATE UNIQUE INDEX one_open_rotation ON rotations ((1)) WHERE finished_at IS NULL;
-- checked with SQLite 3.53: a second open row fails "UNIQUE constraint failed"
CREATE TABLE rotation_locations (
    rotation_id INTEGER NOT NULL REFERENCES rotations(id),
    location_id INTEGER NOT NULL,    -- the old key's location row
    kind TEXT NOT NULL, ssh_alias TEXT, base_url TEXT, account TEXT,
    purpose TEXT NOT NULL,
    phase TEXT NOT NULL,
    reason TEXT,
    PRIMARY KEY (rotation_id, location_id)
);
CREATE TABLE rotation_steps (
    id INTEGER PRIMARY KEY,
    rotation_id INTEGER NOT NULL REFERENCES rotations(id),
    location_id INTEGER,
    step TEXT NOT NULL,              -- generate, install, verify, remove_old, rollback, config, retire
    event TEXT NOT NULL,             -- start, done, failed
    detail TEXT,                     -- short text, never key material or tokens
    at INTEGER NOT NULL
);
```

- Site columns are copied into `rotation_locations` so the journal stays
  readable after the old location row is deleted.
- Stored: fingerprints, file paths, location settings, phases, short
  reasons. Not stored: public key text, private key bytes, passphrases,
  tokens, forge key ids, `authorized_keys` content.
- `detail` and `reason` go through one function that drops anything that
  looks like a key blob (`AAAA` base64 runs) and scrubs tokens, and caps the
  length.
- Test `database_has_no_key_material_after_rotation`: read the database
  file bytes after a full rotation (and after each crash test); the base64
  blob of both keys, both `.pub` lines and every test token are absent.
- The M1 rules stay: file 0600, dir 0700.

## CLI shape

The `app` crate builds the `key-steward` binary. M2 gives it subcommands
and no window. Global options for tests and odd setups: `--db <file>`,
`--ssh-dir <dir>`, `--ssh-config <file>`, `--known-hosts <file>`,
`--allow-config-commands`.

```
key-steward locations list [--key <path|fpr>]
key-steward locations import-ssh-config
key-steward locations add-forge --kind github|gitlab|forgejo --base-url <url> --account <name> --key <path|fpr> --purpose auth|signing
key-steward locations check --key <path|fpr>

key-steward rotate plan  --key <path|fpr> [--type ed25519|ecdsa|rsa] [--new-path <path>]
                         [--skip <location id>]... [--update-config] [--no-passphrase] [--json]
key-steward rotate start <same options> [--yes]
key-steward rotate status [<rotation id>]
key-steward rotate resume <rotation id>
key-steward rotate retry  <rotation id> --location <id>
key-steward rotate skip   <rotation id> --location <id>
key-steward rotate abort  <rotation id> [--rollback]
key-steward rotate log    <rotation id>      # journal and network log
```

- `plan` is the dry-run (FR-10). `start` prints the plan and asks for
  `yes`; `--yes` skips the question (tests, scripts). Every change still
  goes through the plan.
- Tokens come from Secret Service (`SecretServiceTokens`). Storing a token
  is not in M2's CLI; that comes with the UI. CLI process tests use SSH
  locations only; forge flows are covered in-process.
- Exit codes: 0 done, 1 error, 2 refused (pre-flight), 3 rotation stopped
  with a failed location (resume or skip needed).

## Test strategy

All of it runs in CI with `cargo test --workspace`. No `#[ignore]`.

### Servers and forges

- **SSH**: the test sshd (decision 0002). T03 adds `Sshd::start_named(base,
  alias)` and `ClientConfig::new(&[&a, &b])`, which writes one client
  config and one `known_hosts` for several servers, so the app sees two
  hosts like a user with two servers. Server state is read straight from
  `server_home/.ssh/authorized_keys` in assertions.
- **Non-default `AuthorizedKeysFile`**: `Sshd::start_with(base,
  "AuthorizedKeysFile @DIR@/other_ak\n")` (extra lines come first, sshd
  keeps the first value). Already possible.
- **Forges**: `test_support::FakeForge` on wiremock with custom responders
  and shared state (`Arc<Mutex<..>>`), one flavour per forge: `GET /user`,
  list with pagination, `POST`, `DELETE`, the documented status codes.
  Fault switches: lose the response of the next POST or DELETE (apply it,
  answer 502), answer 500, answer 403, close the connection. Fixtures from
  `tests/mock-forges/` seed it. The fake also records every request so a
  test can assert order.

### Fault injection at every journal point

- The engine takes a `Hooks` trait: `fn at(&self, point: Point) ->
  Result<(), Crash>`, called at `BeforeAction(step)`, `AfterAction(step)`
  (action done, `done` entry not yet written) and `AfterDone(step)`. The
  production hook does nothing.
- A crash returns at once without any more writes. The test drops the
  engine and the `Store`, opens the database file again, and runs
  `resume`. The servers and fakes keep their state, like a real crash.
- `crash_resume_at_every_point`: first a clean run records the list of
  points (about 3 per step; with 2 servers and 3 forge sites, about 60).
  Then for each point: fresh servers and fakes, run to the crash, assert
  the invariants, resume, assert the end state equals the clean run's.
  Split into a few test functions by step kind so they run in parallel.
  Note the CI time in the PR.
- Invariant checker, run at every crash point and also as a non-crashing
  hook at every point of a clean run: for each location, the old key is in
  the server file or fake forge, or the new key is there and the journal
  has a `verify` `done` for it at that location. Plus: the new private key
  file exists once `generate` is done; the old private key file exists
  until `retire` is done.
- Lost responses: fake forge fault "apply but answer 502" on install and on
  remove, then retry and resume. Expect no duplicate key and `done`.
- Real process kill (two tests in T16): the CLI runs with
  `--ssh-program <wrapper>`. The wrapper runs the real `ssh`, then sends
  `SIGKILL` to its parent when its argument count reaches a set number.
  This is a real `kill -9` after a remote action and before the journal
  `done`. No test code in the binary.

### Proofs for S-3

- `new_key_not_verified_keeps_old_key`: two servers, one reads another
  `AuthorizedKeysFile`. The rotation ends with that location `Installed`
  and flagged, the old key still in its file, and the other server
  rotated.
- `remove_only_after_fresh_verify` (mock providers): a recording provider
  logs every call. Over many random runs (verify results, failures and
  crash points chosen from a seed), assert: every `remove(old, L)` comes
  after a `verify(new, L) == Verified` in the same process run, with no
  restart between them.
- `same_fingerprint_is_refused`, `gitlab_shared_key_waits_for_both_purposes`,
  `rollback_never_touches_old_removed_location`.

### `authorized_keys` fixtures

Files in `key-steward/tests/authorized-keys/`: input, the edit, expected
output. Cases: plain, options with quotes and `\"`, `from=` with commas,
`command=` with spaces, `restrict,pty`, comments, blank lines, CRLF, no
final newline, old key on two lines with different options,
`cert-authority` line with the old key, unknown key type, the new key
already present (idempotent), old key missing (refuse), removal that would
leave no new key (refuse). The same fixtures run end to end through the
test sshd (byte compare of the server file).

### Remote scripts

- Unit tests run both scripts locally with `bash`, `dash` and `busybox sh`
  in a temp `HOME` (no ssh): normal apply, changed file (exit 3, no
  write), symlink, not a regular file, too large, absent file, temp name
  already taken, backup made, mode 0600.
- A test checks that the bootstrap command contains no `'`, `\` or `!`, and
  that `<N>` equals the script length.
- Through the test sshd: forced command (`command="echo hi"` on the login
  key) gives "refused" before any change.

## Facts (SPEC 15) M2 relies on

Checked 2026-11-12 in the official docs and source. Ticked in SPEC 15,
fact 1, "Add/remove part".

| Fact | Result | Source |
|---|---|---|
| GitHub add auth key | `POST /user/keys`, body `key` (required), `title`; 201; errors 304, 401, 403, 404, 422 ("Validation failed, or the endpoint has been spammed"). Classic scope `write:public_key`. Fine-grained: "Git SSH keys" write. | [keys](https://docs.github.com/en/rest/users/keys), [fine-grained permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens) |
| GitHub delete auth key | `DELETE /user/keys/{key_id}`; 204; errors 304, 401, 403, 404. Classic scope `admin:public_key` (not `write`). Fine-grained: "Git SSH keys" write. | same |
| GitHub signing keys | `POST /user/ssh_signing_keys` (`key` required, `title`), 201, 422; `DELETE /user/ssh_signing_keys/{ssh_signing_key_id}`, 204. Classic `write:ssh_signing_key` / `admin:ssh_signing_key`. Fine-grained: "SSH signing keys" write. | [SSH signing keys](https://docs.github.com/en/rest/users/ssh-signing-keys), permissions page |
| GitLab add | `POST /user/keys`, `title` and `key` required, `expires_at` (ISO date), `usage_type` (`auth`, `signing`, `auth_and_signing`, default `auth_and_signing`); 201; 400 with a message, duplicate gives `"has already been taken"` on `fingerprint` and `key`. | [user keys](https://docs.gitlab.com/api/user_keys/) |
| GitLab delete | `DELETE /user/keys/:key_id`; 204; 404 if not found. | same |
| GitLab write scope | Docs do not name it. Source: the Users API allows `read_user` only for GET and HEAD (`allow_access_with_scope :read_user, if: request.get? \|\| request.head?`), so writes need `api` ("complete read and write access to the API"). Not in docs: human check 2. | [users.rb](https://gitlab.com/gitlab-org/gitlab/-/raw/master/lib/api/users.rb), [scopes](https://docs.gitlab.com/security/tokens/access_token_scopes/) |
| Forgejo add | `POST /api/v1/user/keys` (`userCurrentPostKey`), body `CreateKeyOption` with `title` and `key` required, `read_only` optional; 201 `PublicKey`; 401, 403, 422. Same in Gitea. | Codeberg swagger (Forgejo 17.0.0), Gitea swagger (29.0.0+dev) |
| Forgejo title rule | A key title is unique per user: a second key with a used title gives 422 "Key title has been used" (`ErrKeyNameAlreadyUsed`). A used key gives 422 "Key content has been used as non-deploy key" (`ErrKeyAlreadyExist`, checked first). GitHub and GitLab document no title rule (GitLab `Key` model: title presence and length only, [key.rb](https://gitlab.com/gitlab-org/gitlab/-/raw/master/app/models/key.rb)). | [ssh_key.go](https://codeberg.org/forgejo/forgejo/src/branch/forgejo/models/asymkey/ssh_key.go) `AddPublicKey`, [key.go](https://codeberg.org/forgejo/forgejo/src/branch/forgejo/routers/api/v1/repo/key.go) `HandleAddKeyError`; same in [Gitea](https://github.com/go-gitea/gitea/blob/main/models/asymkey/ssh_key.go), checked 2026-11-12 |
| Forgejo delete | `DELETE /api/v1/user/keys/{id}` (`userCurrentDeleteKey`); 204; 401, 403, 404. | same |
| Forgejo write scope | `write:user`: "read/write/delete access to user operations", routes `/user/*` and `/users/*`; write covers GET too. Not stated for keys by name: human check 3. | [token scopes](https://forgejo.org/docs/latest/user/token-scope/) |
| Remote `sh -s` with data after the script | Does not work with dash or BusyBox sh (read-ahead). Bootstrap with `dd bs=1 count=N` works in bash, dash, BusyBox, Alpine. POSIX `cksum` output equal in all. | Spike above (new SPEC 15 item) |

Not checked, human only: see `spec.md`, "Human checks".

GPG key add/remove on forges is not needed in M2. It stays open in SPEC 15
fact 1 for M3.

## Decisions

No decision blocks M2. Safe defaults used, with the deferred questions in
`decisions/README.md`:

- SPEC 16 item 3 (offer SSH signing during rotation): not offered in M2.
  Deferred to the GUI wizard.
- SPEC 16 item 1 (app ID): M2 has no window. Blocks the first GTK window,
  not M2.
- New key passphrase in a GUI (pty or askpass): the CLI lets `ssh-keygen`
  ask on the terminal. Deferred to the GUI wizard.
- Non-default `AuthorizedKeysFile`: refused in pre-flight (SPEC 9.1 v1
  note). Deferred.
- Login shells other than bash on real servers: human check 5.

## SPEC changes

- In this planning commit: SPEC 9.1 (bootstrap command instead of
  `sh -s`, the read and apply scripts, the `cksum` compare), SPEC 15
  (fact 1 add/remove part ticked; new remote shell item ticked).
- T04: SPEC 7.1 trait sketch (`AddOpts`, `RemoveOpts`).
- T12: SPEC 7.2 (`Retired` state, per-location phases, the S-3 gate's
  fresh verify).
