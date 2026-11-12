# M1 plan: Read-only inventory

First draft. Status: not reviewed. Acceptance criteria are in `spec.md`.

## Proposed SPEC change: test sshd without Docker

Status: proposed. Needs a human OK. SPEC.md is not changed yet.

SPEC 11 and 13 say integration tests start sshd in Docker containers
(`tests/docker/`). Our devcontainer runs under podman. Nested containers inside
it are awkward (extra privileges, a socket mount, or podman-in-podman).

Proposal:

- Integration tests start `/usr/sbin/sshd` as a plain process inside the
  devcontainer, as the test user, on a random free port.
- Each test run makes a temp dir with its own `sshd_config`, a fresh `HostKey`,
  an `AuthorizedKeysFile` with an absolute path, `PidFile none`, `UsePAM no`,
  and `ListenAddress 127.0.0.1`. Start with `sshd -D -e -f <config>`.
- A non-root sshd can only log in as the user who runs it. That is fine for M1
  and M2: the test user is the dev user.
- Keep `tests/docker/` only if CI needs it later. Today CI runs inside the same
  devcontainer image, so the same harness works there.
- If accepted, update SPEC 11 and 13 in the same PR as task T10.

Risk: some sshd behaviour differs when not root (no privilege separation
user switch). We do not test that. M2 crash tests only need `authorized_keys`
edits for one user, so this should be enough. Two servers for M2 means two
sshd processes.

## Crates touched

| Crate | M1 work | Must not have |
|---|---|---|
| `identity-core` | Key types, fingerprints, SSH key scan, private key header check, GnuPG listing, weak key rules | GTK, network, Key Steward types |
| `inventory` | Location model, SQLite store, key list view model, SSH config import | GTK |
| `providers` | `Provider` trait, `ssh_server` verify, `github`, `gitlab`, `forgejo` list and verify, HTTP client with network log | GTK |
| `rotation`, `reminders`, `app` | Nothing. They stay stubs. | |

Proposed small addition to SPEC 11: a `crates/test-support` crate
(`publish = false`, dev-dependency only) for the sshd harness, temp `HOME` and
`GNUPGHOME` helpers and mock forge setup. Needs a human OK, see T10. Fallback:
put the helpers in each crate's `tests/common/` module.

## Key model (identity-core)

- `Fingerprint`: SHA256 for SSH (as `ssh-keygen -l` prints it), full V4/V5
  fingerprint for OpenPGP.
- `KeyAlgo`: `Ed25519`, `Ecdsa(curve)`, `Rsa(bits)`, `Dsa(bits)`, `Cv25519`,
  `Other(String)`.
- `PublicKey { kind: Ssh | OpenPgp, algo, fingerprint, comment, created:
  Option<Timestamp>, expiry: Option<Timestamp>, subkeys: Vec<SubKey>, source }`.
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
- Map results: exit 0 is `Verified`. "Permission denied (publickey)" is
  `Missing`. "Host key verification failed" is `Error(UnknownHostKey)` with
  advice to connect once in a terminal. Anything else is `Error`. Match on
  stderr text is fragile; keep the patterns in one place with tests.

### Forge providers (FR-4)

- One shared `reqwest` client (rustls), base URL as a parameter, so tests
  point it at wiremock.
- GitHub: `/user/keys`, `/user/ssh_signing_keys`, `/user/gpg_keys`.
- GitLab: `/api/v4/user/keys`, `/api/v4/user/gpg_keys`. GitLab key `usage_type`
  tells auth from signing (to verify, fact 1).
- Forgejo: `/api/v1/user/keys`, `/api/v1/user/gpg_keys`.
- Handle pagination.
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
  gpgme 2.0 removed old APIs, so this is not certain. If it fails, options are
  a newer fork or calling `gpg --with-colons`. (T01a)
- `ssh -G` output fields and how `Include` and `Match` behave with `-F`. (T09)
- The exact stderr text from OpenSSH 10.x for denied auth and unknown host
  keys. (T12)

## Open points

- M1 has no UI in its acceptance criteria. This plan keeps M1 headless. The
  first window needs an app ID (SPEC 16 item 1).
- `identity-core` may move to another repo (decision 0001). Keep its public API
  small and documented.
