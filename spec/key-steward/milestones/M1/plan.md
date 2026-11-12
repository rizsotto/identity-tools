# M1 plan: Read-only inventory

First draft. Status: not reviewed. Acceptance criteria are in `spec.md`.

## Test sshd (decision 0002, accepted)

Decided in [0002](../../decisions/0002-ssh-test-servers.md) on 2026-11-12:
option A. SPEC 11, 13 and 14 are updated.

- Integration tests start `/usr/sbin/sshd` as a plain process, as the test
  user, on `127.0.0.1` and a free port. No root, no nested containers. The
  setup is in 0002, "Steps (T10)".
- Every test runs in CI, in the same devcontainer image. No `#[ignore]`, no
  skip if sshd is missing. T10 adds `openssh-server` and `openssh-clients` to
  the Containerfile.
- Temp dirs go under `CARGO_TARGET_TMPDIR` (`<workspace>/target/tmp`), not
  `/tmp`, so `StrictModes yes` works.
- Child processes get a temp `HOME`. Since OpenSSH reads `~` from passwd,
  every `ssh` also gets `-F` and `UserKnownHostsFile`.
- The uid in CI differs from local (`devcontainers/ci` changes the `dev` uid
  to match the runner). Use the current user and uid at run time. The real-home
  guard uses the passwd home.
- T10 is done only when its harness tests pass in GitHub CI. The open CI
  checks are listed in 0002, "Not verified, and the check for each".
- A non-root sshd can only log in as the user who runs it. That is fine for
  M1 and M2. Two servers for M2 means two sshd processes.

## Crates touched

| Crate | M1 work | Must not have |
|---|---|---|
| `identity-core` | Key types, fingerprints, SSH key scan, private key header check, GnuPG listing, weak key rules | GTK, network, Key Steward types |
| `inventory` | Location model, SQLite store, key list view model, SSH config import | GTK |
| `providers` | `Provider` trait, `ssh_server` verify, `github`, `gitlab`, `forgejo` list and verify, HTTP client with network log | GTK |
| `rotation`, `reminders`, `app` | Nothing. They stay stubs. | |

`key-steward/crates/test-support` (`publish = false`, dev-dependency only)
holds the sshd harness, temp `HOME` and `GNUPGHOME` helpers and mock forge
setup. Accepted in decision 0002, now in SPEC 11.

## Key model (identity-core)

- `Fingerprint`: SHA256 for SSH (as `ssh-keygen -l` prints it), full V4/V5
  fingerprint for OpenPGP.
- `KeyAlgo`: `Ed25519`, `Ecdsa(curve)`, `Rsa(bits)`, `Dsa(bits)`, `Cv25519`,
  `Other(String)`.
- `PublicKey { kind: Ssh | OpenPgp, algo, fingerprint, comment, created:
  Option<Timestamp>, expiry: Option<Timestamp>, subkeys: Vec<SubKey>, source }`.
- Built in the core lane (T02), after review: `PublicKey` is an enum,
  `Ssh(SshPublicKey)`, `Age(AgeRecipient)`, `OpenPgp(OpenPgpKey)`, with
  `kind()`, `algo()` and `fingerprint()` accessors. Reason: the families
  have different fields (SSH: comment and encoded line; OpenPGP: dates,
  user IDs, subkeys; age: only the recipient). A flat struct would carry
  fields that are always empty for some kinds; the enum makes the compiler
  check each case. Decision 0001 suggested it. T05 adds user IDs and
  subkeys to `OpenPgpKey`; the caller keeps the source (file path).
  `KeyAlgo` also has `SkEd25519`, `SkEcdsa(curve)` and `X25519` (age).
  `parse_public_keys` gives one result per line; show
  `SshPublicKey::comment_display()`, not the raw comment.
- SSH keys have no creation time. Use the file mtime and label it as the file
  date. This is a gap in FR-1; add a note to SPEC when T04 lands.
- SSH scan takes the SSH dir as a parameter. It never calls `dirs::home_dir()`
  on its own. The caller passes it in. This keeps tests away from the real
  `~/.ssh`.

### Private key header check (S-1)

Do not use `ssh-key`'s private key parser. It decodes the whole key, so an
unencrypted private key would sit in our memory. Instead:

- New OpenSSH format: read the file, base64-decode only the first chunk after
  `-----BEGIN OPENSSH PRIVATE KEY-----`, check the `openssh-key-v1\0` magic,
  then read the cipher name and KDF name strings. `none`/`none` means not
  encrypted. Stop there.
- Old PEM format: look for `Proc-Type: 4,ENCRYPTED`. PKCS#8: `BEGIN ENCRYPTED
  PRIVATE KEY` vs `BEGIN PRIVATE KEY`.
- Unknown format: report "unknown", not "unencrypted".

Use the `ssh-key` crate for public keys (`.pub` files) and fingerprints only.

### GnuPG (NFR-1)

- Behind a trait `OpenPgpBackend` (SPEC 8 says keep Sequoia possible later).
- First impl: `gpgme` crate, keylist mode local, public keys only. Never export
  secret keys.
- Home dir comes from the caller (`GNUPGHOME` in tests).
- Built in T05: `identity_core::Gpg` (`with_home(dir)` in tests,
  `user_default()` in the app) implements `OpenPgpBackend`: `public_keys`,
  `secret_keys`, `read_keys(bytes)` (no import, 1 MB limit, for forge
  `raw_key` / `key` fields) and `default_secret_key`. `OpenPgpKey` has user
  IDs, subkeys with algo, dates and capabilities, and status flags. Send
  Secret's encrypt-to-key-file helper (`RecipientFile`) is in the core too
  but Key Steward does not need it.

## Location model (inventory)

- `LocationKind`: `SshServer`, `GitHub`, `GitLab`, `Forgejo`, `Vks`, `Wkd`.
  M1 implements the first four.
- `Target`: SSH host alias (plus resolved host, user, port) or forge base URL
  plus account name.
- `Purpose`: `SshAuth`, `SshSigning`, `OpenPgp`.
- `Location { id, kind, target, key: Fingerprint, purpose, status, last_checked }`.
- `Status`: `Verified`, `Unverified`, `Missing`, `Error(reason)`.
- SQLite via `rusqlite`. Schema version in `PRAGMA user_version`, migrations as
  plain SQL in order. The DB path is a parameter; the app passes
  `$XDG_DATA_HOME/key-steward/`. M2 adds `rotation_steps`.
- Keys are not stored. They are scanned each time. Only locations and their
  check results are stored.
- `KeyList` joins scanned keys with location counts and warnings to give the
  FR-1 rows.

### SSH config import

- Read `Host` lines (follow `Include`) to get aliases. Skip patterns with `*`,
  `?` or `!`.
- For each alias, run `ssh -G -F <config> <alias>` to get the effective
  `hostname`, `user`, `port`, `identityfile`. This reuses OpenSSH's own logic
  for `Match`, `Include` and defaults.

## Provider trait (providers)

As in SPEC 7.1, with `async-trait` so we can hold `Box<dyn Provider>`. Native
async fn in traits is not dyn compatible yet without boxing by hand.

```rust
#[async_trait]
pub trait Provider: Send + Sync {
    fn kind(&self) -> LocationKind;
    async fn list(&self, target: &Target) -> Result<Vec<PublicKeyRef>>;
    async fn add(&self, target: &Target, key: &PublicKey, opts: &AddOpts) -> Result<()>;
    async fn remove(&self, target: &Target, key: &Fingerprint) -> Result<()>;
    async fn verify(&self, target: &Target, key: &KeyRef) -> Result<VerifyStatus>;
}
```

- M1 implements `kind`, `list` (forges) and `verify` (all four). `add` and
  `remove` return `Error::NotYet` until M2. M2 must replace them, with mock
  tests, before any UI calls them (SPEC 14).
- `ssh_server.list` (download and parse `authorized_keys`) moves to M2 with
  the parser.
- Every provider gets a `NetLog` handle. Each ssh run and HTTP request adds an
  entry (time, provider, target, method/command, result). Tokens are never
  written. (NFR-2, S-4)
- Tokens come in through a `TokenSource` trait. Tests use an in-memory one.
  The `oo7` impl is task T18.

### ssh_server verify (FR-3, S-5)

- Run the system `ssh` binary (SPEC 8), args as a `Vec`, never a shell string.
- Always add `-o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=10
  -o StrictHostKeyChecking=yes`.
- OpenSSH finds `~` from the passwd entry, not from `$HOME`. So a temp `HOME`
  does not isolate it. The command builder must accept an optional `-F
  <config>` and `-o UserKnownHostsFile=<file>`. Tests always set both.
- Map results: exit 0 alone is not `Verified` (see the open item below).
  "Permission denied (publickey)" is `Missing`. "Host key verification failed" is `Error(UnknownHostKey)` with
  advice to connect once in a terminal. Anything else is `Error`. Match on
  stderr text is fragile; keep the patterns in one place with tests.

#### Open item for T12: `-i` does not replace the config's keys

Found in the 0002 experiment. `-i <key>` (or `-o IdentityFile=<key>`) adds to
the `IdentityFile` list from `~/.ssh/config`. It does not replace it, and
`IdentityFile=none` does not clear it, even with `IdentitiesOnly yes`. So
`verify` of the new key can exit 0 because the old key from the config logged
in. Then S-3 would remove the old key and lock the user out.

No fix is chosen yet. T12 starts with a failing test: the test ssh config
holds a second valid key (the "old" key), the key under test is not on the
server, and `verify` must return `Missing`. Then pick a fix. Options:

- Run `ssh -v` and parse `Server accepts key: <path> <type> SHA256:...
  explicit`. `Verified` only if that fingerprint is the key under test.
  Suggested in 0002. T12 must confirm the text is stable in OpenSSH 10.x.
- Do not pass the user's config to the check. Build a temp `-F` config from
  `ssh -G` output (hostname, user, port, host key settings) without any
  `IdentityFile`. Unverified: `ProxyJump`, `Match` and `Include` may be lost
  or need care.
- Both: the clean config as the main path, and the `-v` fingerprint as a
  second check.

Record the choice and why in the T12 PR. If it changes SPEC 9 or FR-3, change
SPEC in the same PR.

### Forge providers (FR-4)

- One shared `reqwest` client (rustls), base URL as a parameter, so tests
  point it at wiremock.
- GitHub: `/user/keys`, `/user/ssh_signing_keys`, `/user/gpg_keys`.
- GitLab: `/api/v4/user/keys`, `/api/v4/user/gpg_keys`. GitLab key `usage_type`
  (`auth`, `signing`, `auth_and_signing`) tells auth from signing (verified,
  fact 1).
- Forgejo: `/api/v1/user/keys`, `/api/v1/user/gpg_keys`. Forgejo has no
  separate SSH signing key list; one SSH key list serves both.
- Handle pagination: follow the `link` header `rel="next"` on all three.
- GPG keys: GitHub gives only the 16 hex `key_id` plus the armored `raw_key`,
  GitLab only the armored `key`. Get the full fingerprint by parsing the
  armored key. Details and sources: SPEC 15, fact 1.
- `verify` = `list`, then compare fingerprints. For SSH keys, compute the
  fingerprint from the returned key text. Do not trust a server fingerprint
  field.

## Test strategy

- Unit tests next to the code: fingerprints, header check, weak key rules,
  SSH config import, stderr mapping, DB migrations.
- Temp `HOME` and SSH dir: `tempfile::TempDir`. Keys made with `ssh-keygen -q
  -N '' -f <tmp>/id_x` (and `-N pass` for encrypted ones).
- DSA: OpenSSH 10 removed DSA, so `ssh-keygen` cannot make one. Use a checked
  in DSA public key fixture (public only).
- Temp `GNUPGHOME`: make test keys with `gpg --batch --pinentry-mode loopback
  --passphrase '' --quick-gen-key`. Keep the path short (agent socket path
  limit). Run `gpgconf --kill all` with that home on drop.
- SSH server: the sshd harness above. Each test gets its own sshd, port, host
  key and `known_hosts`.
- Forges: `wiremock` servers in `tests/mock-forges/`. Fixtures are JSON files
  copied from the official API docs for now, with fake values. Replace with
  recorded real responses later (no tokens).
- Guard test: a test that fails if any test process has `HOME` or `GNUPGHOME`
  set to the real user's home. Cheap safety net.

## SPEC 15 facts M1 depends on

| Fact | Needed for | When |
|---|---|---|
| 1. Forge endpoints, scopes, payloads | `list` for GitHub, GitLab, Forgejo. Only the read part (GET, pagination, fields, signing vs auth). Add/remove can wait for M2. | T01b, before T14-T16 |
| 6. `oo7` status and API | `TokenSource` impl | T18 only |

Facts 2 (VKS), 3 (`--quick-set-expire`), 4 (Flatpak sockets) and 5
(Background portal) are not needed in M1.

New facts to add to SPEC 15 (proposed, not added yet):

- The `gpgme` Rust crate builds and works against Fedora 45's gpgme 2.0.x.
  (T01a) Verified and added to SPEC 15: it works with gpgme 2.0.1.
- `ssh -G` output fields and how `Include` and `Match` behave with `-F`. (T09)
- The exact stderr text from OpenSSH 10.x for denied auth and unknown host
  keys. (T12)

## Open points

- M1 has no UI in its acceptance criteria. This plan keeps M1 headless. The
  first window needs an app ID (SPEC 16 item 1).
- `identity-core` is shared with Send Secret in this repo (decision 0001).
  Keep its public API small and documented.

## Devcontainer packages to add

The devcontainer starts minimal (Rust only). Add these Fedora packages to
`.devcontainer/Containerfile` in the task that first needs them:

`gpgme-devel libgpg-error-devel gnupg2 openssh-clients openssh-server sqlite-devel`

`openssh-clients` and `openssh-server` come in with T10. The sshd tests need
them in CI (decision 0002).

Also add `gtk4-devel libadwaita-devel` and `xvfb-run` for GTK tests when the
first GTK crate gets real code.
