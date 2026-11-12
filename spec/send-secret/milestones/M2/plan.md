# M2 plan

Status: draft (planner, 2026-11-12). Facts this plan relies on are checked in
SPEC section 15 and in "Facts verified" below. Names are a draft; keep the
shapes.

## Crates touched

| Crate | M2 work |
|---|---|
| `identity-core` (repo root) | WKD hash and URLs; export a key from the keyring; split a key blob into one blob per key; `UserId` email match. All sync, no network (decision 0001). Key Steward needs the WKD hash for its WKD export too. |
| `resolver` | Query parsing, the `KeySource` trait, HTTP layer, the seven sources, merge and order. Async (tokio). No GTK. |
| `trust` | TOFU store (SQLite): contacts, pins, key bytes, history. Sync. No GTK, no network. |
| `cli` | `lookup` subcommand, `encrypt --to QUERY`, small `contacts` listing. A new lib target holds the lookup code so tests can call it in-process with mock endpoints. |
| `crypto` | Untouched. The CLI turns resolved keys into `crypto::Person`. |

Dependency direction: `cli -> {resolver, trust, crypto}`, `resolver -> {trust, identity-core}`
(the contacts source reads the store), `trust -> identity-core`. `resolver`
never depends on `crypto`.

## Reuse from Key Steward (decision 0001)

Key Steward's forge code (`key-steward/crates/providers`) reads the
*authenticated* REST API (`/user/keys`, token, pagination). Send Secret reads
the public, unauthenticated `github.com/<user>.keys` and `.gpg` files. So the
forge code itself does not carry over. What is shared:

- `identity_core::parse_public_keys` already parses `authorized_keys` lines
  (`.keys` lists), marks ECDSA and `sk-` keys, and has the 1 MB limit.
- `identity_core::Gpg::read_keys` reads OpenPGP keys without importing.
- New in identity-core (this milestone): WKD hash, `export_key`,
  `split_keys`, `UserId::has_email`. Key Steward will use the WKD hash and
  export for publishing (its FR-9).
- Not shared: Key Steward's `HttpClient` and `NetLog`. Decision 0001 keeps
  network code out of identity-core, and Key Steward's client is built around
  tokens. The resolver has its own small HTTP layer with the same rules
  (no redirect surprises, plain http only to loopback, body cap, every
  request logged). Its tests copy the wiremock style of
  `key-steward/crates/providers/tests/`.
- Same crate versions as Key Steward, so one `Cargo.lock` entry each:
  `reqwest 0.13.5` (`default-features = false, features = ["rustls"]`),
  `tokio 1`, `async-trait 0.1`, `url 2.5.8`, `rusqlite 0.42.0`, `wiremock 0.6.5`.

## Runtime and HTTP

- **Async runtime: tokio.** Key Steward already uses it with reqwest, gtk4-rs
  can host a tokio runtime next to the GLib loop in M3, and wiremock needs it.
  `resolver` uses `rt` and `time`. The CLI builds a current-thread runtime
  only when a network source must run, and drops it before encryption starts.
  Encryption and decryption stay sync (M1).
- **HTTP client: reqwest 0.13 with rustls.** The `rustls` feature uses
  `rustls-platform-verifier`, which reads the system CA store on Linux
  (checked on docs.rs; matters for Flatpak). Build: `redirect::Policy::none()`
  (redirects are followed by hand, see below), no cookie store,
  `https_only` outside test mode, `user_agent("send-secret/<version>")`,
  `connect_timeout(5 s)`. Proxies from the environment are kept for users;
  test clients call `no_proxy()`.
- **Timeouts.** Each source gets 5 s in total (SPEC 7), enforced with
  `tokio::time::timeout` around `lookup`. Each request inside gets the time
  left. Timeouts are a field of `ResolverConfig`, so tests use 300 ms and a
  wiremock delay of 2 s instead of waiting 5 s.
- **Size limits (S-7).** Refuse at once if `Content-Length` is over
  `identity_core::MAX_KEY_INPUT` (1,000,000). Else read chunks and stop as
  soon as the total passes the limit. The error never holds body bytes. A
  WKD answer with more than 32 keys is refused (same cap as
  `crypto::RecipientFile::all`).
- **Redirects.** Followed by hand, at most 5 hops, each hop must be `https`
  (WKD draft section 3.1: follow redirects only while every target is https).
  Each hop is logged. The final URL is shown as the source when it differs
  from the first. No auth is ever sent, so no origin check is needed beyond
  https. A 401 is an error (the draft says clients must not answer auth
  challenges).
- **Rate limits, politely.** One request per URL per lookup, never an
  automatic retry. A 429 (any source), or a 403 with `x-ratelimit-remaining: 0`
  (GitHub's API style, in case github.com sends it), gives
  `SourceError::RateLimited { retry_after }` from `Retry-After` when present.
  The resolver remembers a `retry_after` per host for the life of the
  `Resolver` value and skips that host until then (the M3 app keeps one
  `Resolver`). keys.openpgp.org allows one by-email request per minute
  (burst 50), so the app must not look up while the user types: M3 runs a
  lookup only on Enter or after the input is a complete query. The resolver
  never looks up a partial query (it only accepts parsed queries).
- **DNS check for WKD.** The advanced method is used when
  `openpgpkey.<domain>` has an address. The check calls `getaddrinfo` on a
  blocking thread and tells "no such name / no address" (`EAI_NONAME`,
  `EAI_NODATA`) apart from "try again" (`EAI_AGAIN`, other errors). Only the
  first falls back to direct. Preferred crate: `dns-lookup` (its error kind
  exposes the EAI code; check the API in task T05 before relying on it), else
  a small `libc::getaddrinfo` wrapper with a `SAFETY` comment. The addresses
  found are handed to reqwest with `ClientBuilder::resolve_to_addrs`, so the
  request uses the same answer (no second lookup). The DNS check is logged
  (NFR-2: it is network traffic too).

### Mock endpoints (no real network in tests, ever)

Sources build real URLs (`https://openpgpkey.example.org/...`). They never
see mock addresses. The HTTP layer maps them:

```rust
pub struct Net { /* reqwest client, origin map, netlog, cooldowns */ }
impl Net {
    pub fn new(cfg: &ResolverConfig) -> Result<Net>;              // real: https only, real DNS
    /// Tests only, by API (no env var, no config file, no CLI flag):
    /// every https origin in `map` goes to its `http://127.0.0.1:PORT`
    /// (or [::1]) mock. Non-loopback targets are refused. A host not in
    /// the map has "no address" for the WKD DNS check, and any request to
    /// it fails with an error, never a real connection.
    pub fn with_mock_origins(cfg: &ResolverConfig, map: OriginMap) -> Result<Net>;
    pub async fn get(&self, url: &Url, deadline: Instant) -> Result<Fetched, NetError>;
    pub async fn host_has_address(&self, host: &str, deadline: Instant) -> Result<bool, NetError>;
    pub fn log(&self) -> &NetLog;
}
```

- The rewrite applies to every hop, so redirect tests work.
- Real and mock modes share the same request, limit and redirect code, so
  the tests cover it. Only the URL rewrite and the DNS answer differ.
- The shipped binary has no way to turn on mock mode. CLI tests that need
  network sources call `cli::lookup::run` and `cli::resolve_recipients` from
  the cli lib target in-process with a mock `Net`. Process-level CLI tests
  (S-1) use only pinned contacts, so they make no request at all.
- One wiremock server per mocked host (for example one for
  `openpgpkey.example.org`, one for `example.org`), so tests also prove the
  right host was asked.
- Mock data lives in `send-secret/tests/mock-sources/` (SPEC 11): canned
  `.keys` lists, a GitHub `.gpg` with no key, junk, WKD and VKS key blobs
  made from fixture keys by `send-secret/tests/fixtures/gen.sh`.

## Queries

```rust
pub enum Query {
    Email(Email),                                   // "alice@example.org"
    GitHub { user: String },                        // "github:alice"
    GitLab { host: Option<Host>, user: String },    // "gitlab:alice", "gitlab:git.example.org/alice"
    Fingerprint(String),                            // 40 or 64 hex digits, spaces allowed, upper-cased
    Contact(String),                                // anything else that names a stored contact
    Pasted(Vec<u8>),                                // from --to-key or the app's paste box, max 1 MB
}
pub fn parse_query(s: &str) -> Result<Query, QueryError>;   // no Pasted: that comes from bytes
impl Query { pub fn contact_key(&self) -> Option<String> }  // canonical form, the store's key
```

- Email: one `@`, non-empty local part (UTF-8 kept as typed, max 64 bytes),
  ASCII domain with at least one dot, labels `[a-z0-9-]`, no IP literal.
  Non-ASCII domains are refused with "type the domain in its xn-- form"
  (IDN is deferred). Canonical form: ASCII lower case of the whole address
  (gpg and WKD match case-insensitively).
- GitHub user: `[A-Za-z0-9-]`, 1 to 39 chars, no leading or trailing `-`,
  no `--`. GitLab user: `[A-Za-z0-9_.-]`, 1 to 255 chars, starting with a
  letter, digit or `_`, no `..`, and not ending in `.`, `.git`, `.atom`,
  `.keys` or `.gpg` (a subset of GitLab's `root_namespace_route_regex`;
  the point is that no value can change the URL path). Canonical form is lower case.
- GitLab host: hostname with optional `:port`, no userinfo, no path, no IP
  literal, not `localhost`. The CLI takes it as typed; a stored list of
  user-added hosts is M3 (SPEC 4 says "instances the user adds").
- Contact names and fingerprints only hit local sources. A query that is not
  an email, a prefixed user or a fingerprint is a contact name; unknown names
  give "no contact named ...".
- Values are only ever put into URLs through `url::Url` path segment and
  query APIs, never by string concatenation.

## Model and the KeySource trait

```rust
#[async_trait]
pub trait KeySource: Send + Sync {
    fn kind(&self) -> SourceKind;                     // Contacts, Keyring, Wkd, Vks, GitHub, GitLab, Pasted
    fn accepts(&self, q: &Query) -> bool;
    async fn lookup(&self, q: &Query, net: &Net, deadline: Instant) -> Result<Found, SourceError>;
}

pub struct Found { pub keys: Vec<FoundKey>, pub rejected: Vec<Rejected> }

pub struct FoundKey {
    pub key: identity_core::PublicKey,      // parsed summary (algo, fpr, created, user IDs)
    pub bytes: KeyBytes,                    // what to encrypt to: one key only
    pub source: Source,
    pub usable: Result<(), Unusable>,       // FR-4 skip note: EcdsaNotAge, SkKey, RsaSize(bits), NoEncryptionSubkey, Revoked, Expired
    pub shown_user_ids: Vec<UserId>,        // WKD/VKS: only those matching the email (S-6, draft 3.1)
}
pub enum KeyBytes { Ssh(String) /* "type base64", no comment */, Age(String), OpenPgp(Vec<u8>) /* one key */ }
pub struct Source { pub kind: SourceKind, pub location: String /* final URL, keyring path, "contacts", "pasted" */, pub first_url: Option<String> }
pub struct Rejected { pub fingerprint: Option<Fingerprint>, pub source: Source, pub reason: RejectReason } // S-6 mismatch, too many keys, ...
pub enum SourceError { NotFound, Timeout, RateLimited { retry_after: Option<Duration> }, TooLarge, Malformed(String), Http(u16), Net(String), Keyring(String) }
```

- `Unusable` keys are kept in the result and shown with their note (FR-4),
  never silently dropped, never encrypted to.
- Every fetched OpenPGP blob goes through `identity_core::Gpg::split_keys`
  (new): it imports the blob into a throwaway 0700 home (gpg.conf
  `no-autostart`, deleted after) and exports each key alone. So `KeyBytes`
  always holds exactly one key, and the user's keyring is never touched.
  This reuses the idea of `crypto::RecipientFile::all` (M1). Moving
  `RecipientFile::all` onto `split_keys` is a later cleanup, not M2.
- **S-6 user ID check.** For WKD and VKS, a key is kept only if one of its
  user IDs is not revoked, not invalid, and its email equals the query
  (ASCII case-insensitive on the whole address, exact otherwise). Keys
  without such a user ID become `Rejected { reason: EmailMismatch }`. Other
  user IDs are never shown or stored as names. We do not rewrite the key to
  drop them (that would need our own packet code, section 14); the draft's
  "drop other user IDs" protects a keyring, and we never import into one.
  GitHub `.gpg` keys have no email check (SPEC 10 only names WKD and VKS);
  their user IDs are shown as found, filtered by `UserId::display`.
- Fingerprints always come from identity-core (`ssh-key` crate, gpgme),
  never from the server.

### Resolve, merge and order

```rust
pub struct ResolverConfig { pub source_timeout: Duration /* 5 s */, pub max_redirects: u8 /* 5 */ }
pub enum Mode { LocalOnly, Full }
pub struct Resolver { sources: Vec<Box<dyn KeySource>>, net: Option<Net>, cfg: ResolverConfig }
impl Resolver {
    pub async fn resolve(&self, q: &Query, mode: Mode) -> Resolution;
}
pub struct Resolution {
    pub candidates: Vec<Candidate>,             // merged, ordered
    pub rejected: Vec<Rejected>,
    pub errors: Vec<(SourceKind, SourceError)>, // per source, shown, never fatal alone
    pub requests: Vec<NetLogEntry>,             // NFR-2
}
pub struct Candidate { pub fingerprint: Fingerprint, pub key: FoundKey /* from the best source */, pub sources: Vec<Source> }
```

- All sources that accept the query run at once (`futures::future::join_all`
  or a `JoinSet`), each with its own timeout. `Mode::LocalOnly` runs only
  contacts, keyring and pasted, and never creates a `Net`.
- Merge by fingerprint. `sources` lists every source that found it, in SPEC 4
  order: contacts, keyring, WKD, keys.openpgp.org, GitHub, GitLab, pasted.
  The key bytes come from the best ranked source (for one OpenPGP key from
  WKD and VKS, the WKD copy: the domain owner's answer). Candidates are
  sorted by their best source rank, then by the order the source returned
  them.
- A query matching a pinned contact short-cuts: by default the CLI resolves
  it with `Mode::LocalOnly` (see "Pinned contacts and refresh").

### Sources

| Source | Accepts | Request | Notes |
|---|---|---|---|
| Contacts | any query whose `contact_key` or contact name is stored; fingerprint | none | Returns the pinned keys from the trust store. `Source` shows "contacts" plus the original source and the pin date (S-3). |
| GnuPG keyring | email, fingerprint | none (gpgme, `Gpg::user_default()`; tests `Gpg::with_home`) | gpgme contexts are not `Send` (Key Steward note), so runs in `spawn_blocking`. Email: valid user ID with that email (`UserId::has_email`). Bytes: `Gpg::export_key(fpr)` (new). Not stored again in the trust store. |
| WKD | email | DNS check of `openpgpkey.<domain>`; then `GET https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>?l=<local>` if it has an address, else `GET https://<domain>/.well-known/openpgpkey/hu/<hash>?l=<local>` | Domain lower case. `<hash>`: z-base-32 of SHA-1 of the local part with only ASCII A-Z lowered (`identity_core::wkd_hash`). `l=` is the local part unchanged, percent-escaped (draft; `gpg-wks-client` sends it lowered, servers ignore it). No fallback on 404, timeout or TLS error at the advanced host (draft 3.1). Answer is binary or armored, may hold several keys; any `Content-Type` accepted. S-6 check. The `policy` file is not fetched (lookups do not need it). |
| keys.openpgp.org | email | `GET https://keys.openpgp.org/vks/v1/by-email/<percent-encoded email>` | 200: armored key (`application/pgp-keys`). 404: not found. 429: rate limited (1 per minute by email, burst 50). S-6 check. |
| GitHub | `github:` | `GET https://github.com/<user>.keys` and `GET https://github.com/<user>.gpg`, in parallel | `.keys`: `authorized_keys` lines via `parse_public_keys`, bad lines are notes. `.gpg`: armored, may hold no key: if gpgme finds zero keys, that is "no OpenPGP key", not an error. 404 on either: user not found (only an error if both fail). |
| GitLab | `gitlab:` | `GET https://gitlab.com/<user>.keys` or `https://<host>/<user>.keys` | Same parsing as GitHub `.keys`. GitLab also serves `/<user>.gpg` (verified keys only), but SPEC 4 does not list it: not used (human question). |
| Pasted | `Pasted` | none | OpenPGP (armored or binary) via `split_keys`; else SSH lines and age recipients via `parse_public_keys`. Max 1 MB. |

## Trust store (TOFU)

Crate `trust`, sync, `rusqlite` (bundled SQLite not needed; the devcontainer
has `sqlite-devel`, same as Key Steward).

### Where and file modes

- `$XDG_DATA_HOME/send-secret/trust.sqlite3` (SPEC 8). `$XDG_DATA_HOME`
  unset, empty or relative: `$HOME/.local/share` (same rule as M1 for
  `XDG_CONFIG_HOME`).
- Dir 0700: created 0700; an existing dir with group or other bits is set to
  0700; a symlinked dir is refused. Same behavior as M1's self identity dir.
- File 0600: created with `O_CREAT | O_EXCL | O_NOFOLLOW`, mode 0600, before
  SQLite opens it; an existing file that is a symlink, not a regular file,
  or readable by group or others is refused (not silently fixed: someone
  else may have read it). SQLite gives its journal file the main file's
  permissions. Journal mode stays `DELETE` (no `-wal`/`-shm` files).
  `busy_timeout` 2 s so the CLI and the app can share it.
- Schema version in `PRAGMA user_version`, migrations list like Key
  Steward's `inventory::Store`. A newer schema is refused, never rewritten.

### What is stored (human rule: no key copies beyond what is needed)

The human rule: keys may not be duplicated in stored data beyond what is
needed; configuration may be stored; pin by fingerprint; keep a history of
accepted changes. Applied:

- A pinned contact must encrypt without the network (S-1, NFR-1), so the
  public key bytes of each pinned key are needed. They are stored **once per
  fingerprint** (`keys` table), shared by every contact that pins it.
- Keys that live in the GnuPG keyring are **not** copied: their row has no
  bytes and is read from the keyring at encrypt time. If such a key leaves
  the keyring, the contact errors with "key no longer in your GnuPG keyring"
  and asks for a lookup.
- Pins and history hold fingerprints only.
- When no pin references a fingerprint any more, its `keys` row is deleted
  (in the same transaction as the change). History keeps the fingerprint
  text, never the bytes.
- No plaintext, ciphertext, passphrases or private keys, ever.

```sql
CREATE TABLE contacts (
    id         INTEGER PRIMARY KEY,
    query      TEXT NOT NULL UNIQUE,   -- canonical: "alice@example.org", "github:alice", "gitlab:git.example.org/alice"
    name       TEXT UNIQUE,            -- optional display name / alias (FR-1 "contact name")
    created    INTEGER NOT NULL
);
CREATE TABLE keys (
    fingerprint TEXT PRIMARY KEY,      -- identity-core form: OpenPGP hex, "SHA256:..." for SSH, "age1..." for age
    kind        TEXT NOT NULL,         -- openpgp | ssh | age
    bytes       BLOB,                  -- NULL when the key is read from the GnuPG keyring
    CHECK (bytes IS NULL OR length(bytes) <= 1000000)
);
CREATE TABLE pins (
    contact_id  INTEGER NOT NULL REFERENCES contacts(id),
    fingerprint TEXT NOT NULL REFERENCES keys(fingerprint),
    source      TEXT NOT NULL,         -- where it was found when pinned (URL or keyring path), for S-3
    pinned_at   INTEGER NOT NULL,
    PRIMARY KEY (contact_id, fingerprint)
);
CREATE TABLE events (                  -- history, append only
    id         INTEGER PRIMARY KEY,
    contact_id INTEGER NOT NULL REFERENCES contacts(id),
    at         INTEGER NOT NULL,
    kind       TEXT NOT NULL,          -- first_use | accepted_change | narrowed
    before     TEXT NOT NULL,          -- space separated fingerprints ("" for first_use)
    after      TEXT NOT NULL,
    sources    TEXT NOT NULL           -- sources of the new keys
);
```

### TOFU states

```rust
pub enum Verdict {
    New,                                         // no contact yet: ask (FR-5)
    Same,                                        // every usable found key is pinned
    Narrowed { removed: Vec<Fingerprint> },      // found keys are a strict subset of the pin
    Changed { old: Vec<PinnedKey>, new: Vec<Candidate> }, // a usable found key is not pinned: BLOCK (S-2)
}
impl Store {
    pub fn open(path: &Path) -> Result<Store>;
    pub fn contact(&self, query_or_name: &str) -> Result<Option<Contact>>;  // with pinned keys
    pub fn verdict(&self, contact_key: &str, found: &[FoundFingerprint]) -> Result<Verdict>;
    pub fn pin_first_use(&mut self, contact_key: &str, name: Option<&str>, keys: &[NewPin]) -> Result<()>;
    pub fn accept_change(&mut self, contact_key: &str, verified: &[Fingerprint], keys: &[NewPin]) -> Result<()>;
    pub fn narrow(&mut self, contact_key: &str, keep: &[Fingerprint]) -> Result<()>;
    pub fn history(&self, contact_key: &str) -> Result<Vec<Event>>;
}
```

- Only usable keys count (an ECDSA line that appears on GitHub is not a
  change).
- **Changed** blocks encryption to that contact. Nothing else does.
  `accept_change` needs the full fingerprint of every new key, typed or
  pasted by the user (the "I verified the new key" action, FR-5); a short
  fingerprint or "all" is refused. The new pin is the accepted set; history
  records before, after, time and sources.
- **Narrowed** (a key vanished from GitHub, for example): safe, since no new
  key is trusted. The pin shrinks to the found keys, a `narrowed` event is
  recorded and a note is shown. Not encrypting to a key its owner removed is
  the safer side.
- **New with conflicting sources:** if the candidates for one email hold more
  than one OpenPGP primary key and they come from different sources (WKD
  says A, keys.openpgp.org says B), `--accept-new` refuses and the user must
  pick with `lookup --accept <full fingerprint>`. Several SSH keys from one
  `.keys` list are normal and are accepted together.

### Pinned contacts and refresh

- Safe default for M2: a query that matches a pinned contact uses the pinned
  keys with **no network request** (`Mode::LocalOnly`). This is what makes
  S-1 natural, keeps NFR-2 traffic low, and never brings in a new key
  without the user asking. `encrypt --refresh` and `lookup` run `Mode::Full`
  for pinned contacts too and apply the verdict (Changed blocks).
- Open for M3: should the app refresh pinned contacts in the background? Added
  to `decisions/README.md` as pending, blocks M3. Not needed for M2's
  criteria.

## CLI

```
send-secret lookup QUERY [--verbose] [--accept-new | --accept FPR ...] [--accept-change FPR ...] [--name NAME]
send-secret encrypt (--to QUERY | --to-key FILE)... [--refresh] [--accept-new] [M1 options]
send-secret contacts [QUERY]          # list contacts, or one contact's pins and history
```

- `lookup` prints one block per candidate: state (`pinned`, `new`,
  `CHANGED`), key type, full fingerprint and short form (last 16 hex digits
  for OpenPGP, `SHA256:` first 12 for SSH), creation date (OpenPGP), each
  source on its own line next to the fingerprint (S-3), and skip notes
  (FR-4). Then rejected keys with reasons (S-6), then source errors.
  `--verbose` adds the request log (NFR-2). Exit 0 if a usable key was
  found, 1 if not.
- `--accept-new` pins all usable candidates of a new contact (refused on
  conflicting sources, see above). `--accept FPR` pins exactly the named
  keys. `--accept-change FPR` replaces a changed pin with the named keys.
  `--name` sets a contact name (FR-1 "contact name").
- `encrypt --to QUERY`: one recipient per `--to`, mixed freely with
  `--to-key` (which keeps its M1 behavior: an explicit key file, no TOFU).
  Label for output names: the canonical query with characters outside
  `[A-Za-z0-9._-]` turned into `_` (`alice@example.org` gives
  `alice_example.org`, `github:alice` gives `github_alice`). Every `--to` is
  resolved and checked before any output is opened:
  - pinned and not refreshed: pinned keys;
  - new: exit 1 with the candidates and "check the fingerprint, then run
    again with --accept-new"; with `--accept-new` the keys are pinned and
    used;
  - changed (only possible with `--refresh`): exit 1, red text on a tty,
    old and new fingerprints with sources, and the `lookup --accept-change`
    command to run. Never an `--accept-change` on `encrypt` itself, so a
    script can not accept changes blindly while sending;
  - no usable key: exit 1 naming the recipient (FR-11).
  Resolved keys become `crypto::Person { label, keys }` (`Recipient::OpenPgp`
  from one-key bytes, `Recipient::Age` from SSH lines and age recipients),
  then the M1 flow runs unchanged, including the sender's key (FR-12,
  decision 0004).
- Code layout: new `cli/src/lib.rs` with modules `lookup` and `recipients`
  (`resolve_recipients(&[Query], &Env) -> Result<Vec<Person>, Fail>`).
  `Env` holds the store path, the GnuPG home and how to make a `Net`
  (real in `main.rs`, mock in tests). `main.rs` only dispatches and keeps
  the M1 encrypt code; the `--to` hook into `encrypt()` is a few lines.

## Test strategy

- **No real network, ever.** All network sources are tested against wiremock
  servers through `Net::with_mock_origins`. A host outside the map has no
  address and any request to it fails, so a test that forgets a mapping
  fails loudly instead of going out. DNS tests use only the map (and
  `localhost` from `/etc/hosts` for the real `getaddrinfo` wrapper).
- **Each network source** has tests for: found, not found (404), empty
  answer, timeout (wiremock delay over a 300 ms source timeout), malformed
  (junk bytes, HTML, broken armor), oversized (1,000,001 bytes with and
  without `Content-Length`), 429 with `Retry-After`, redirect to https
  followed, redirect to http refused, redirect loop stops at 5.
- **WKD**: hash vectors (below); advanced host present gives the advanced
  URL only; advanced host absent gives the direct URL; advanced 404 or
  timeout does not fall back; binary and armored answers; two concatenated
  keys, one with a matching user ID and one without (one kept, one
  rejected); a key whose only matching user ID is revoked is rejected.
- **WKD hash vectors** (identity-core unit test), checked here with
  `gpg-wks-client --print-wkd-hash` (GnuPG 2.4.9) and a Python
  SHA-1 + z-base-32 one-liner on 2026-11-12:

  | Address | Hash |
  |---|---|
  | `Joe.Doe@Example.ORG` (draft example) | `iy9q119eutrkn8s1mk4r39qejnbu3n5q` |
  | `alice@example.org` | `kei1q4tipxxu1yj79k9kfukdhfy631xe` |
  | `a+b@Example.ORG` | `i6wwpbayndmjsnjzbzdj15jgc77g8a4f` |
  | `Ünïcode@example.org` (non-ASCII kept as is) | `hss8e8o6az1fjiz8iujfffi83416i73g` |
  | `ÜNÏCODE@example.org` (only ASCII lowered: `ÜnÏcode`) | `me6bhw5jgh86yue7p4s8pfoqcfkuz3au` |

  Plus a cross-check test that runs `gpg-wks-client --print-wkd-hash` (in
  the devcontainer's `gnupg2`) on these and a few generated addresses and
  compares. URL test: the draft's two example URLs for `Joe.Doe@Example.ORG`
  come out exactly (with `l=Joe.Doe`).
- **VKS**: by-email path percent-encodes `+`, `@` stays or is encoded the
  way `Url` path segments do (assert the exact path wiremock sees);
  mismatched email rejected (S-6).
- **GitHub/GitLab**: `multi.keys` style list gives usable keys plus skip
  notes for ECDSA, `sk-`, RSA 1024 and RSA 8192; `.gpg` with no key; `.gpg`
  with an expired key (unusable with note); one of `.keys`/`.gpg` 404 and the
  other fine; bad user names never reach wiremock.
- **Keyring and pasted**: temp `GNUPGHOME` with fixture keys; email match
  ignores revoked user IDs; export gives one key; pasted armored, binary,
  SSH, age, junk, over 1 MB.
- **Merge and order** (`all_sources_merged_and_ordered`): one resolver with
  every source mocked; the same OpenPGP key from keyring, WKD and VKS gives
  one candidate with three sources in SPEC 4 order; the order of candidates
  follows source rank; one source timing out still returns the others.
- **Trust**: state machine unit tests (new, same, narrowed, changed, accept
  change with full fingerprint only, history rows), store file modes (0700
  dir, 0600 file, symlink refused, loose file refused), key bytes stored once
  when two contacts pin the same key, keyring keys stored without bytes,
  unused key rows removed, schema too new refused.
- **CLI in-process** (cli lib target, mock `Net`): `lookup` output holds
  source next to fingerprint (S-3), states, skip notes, `--verbose` log;
  `encrypt --to` new without `--accept-new` writes nothing; with it, the
  pin is stored and the message opens with the recipient's key and with
  the sender's key; `--refresh` with a changed mock key exits 1, writes
  nothing, prints both fingerprints with sources; `lookup --accept-change`
  then works and `contacts QUERY` shows the history.
- **S-1** (`s1_no_network_after_lookup`, in `crates/cli/tests/security.rs`):
  1. In-process: look up `alice@example.org` against a mock WKD and accept,
     writing the trust store into the test's temp `XDG_DATA_HOME`.
  2. Run the real binary `send-secret encrypt --to alice@example.org -i msg
     -o out` and then `send-secret decrypt` under
     `strace -f -e trace=socket,connect -o LOG`, with the temp `HOME`.
  3. Assert both succeed, the plaintext round-trips, and no `LOG` line has
     `AF_INET` or `AF_INET6` (Unix sockets to gpg-agent are fine).
  4. Control test `s1_strace_check_catches_inet_socket`: the same checker
     on a `python3 -c` that opens a TCP socket to 127.0.0.1 must fail.
  `unshare -n` is not used: Docker's default seccomp profile in CI blocks
  new user namespaces, while `strace` already runs there (M1 T12).
  Note: a user gpg.conf with `auto-key-retrieve` could make gpg fetch keys
  while verifying a signature. The test's temp home has no such option; the
  risk is noted for M3 docs.
- Test env: temp `HOME`, `GNUPGHOME`, `XDG_DATA_HOME`, `XDG_CONFIG_HOME`
  (M1 `TestEnv`), generated fixture keys only, fake names, `example.org`.

## Fixtures to add (gen.sh)

- `openpgp/alice-new.asc`: a second key for `alice@example.org` (the
  "changed key").
- `openpgp/mallory-other.asc`: user ID `mallory@example.net` only (S-6
  mismatch when served for alice).
- `openpgp/olivia-two-uids.asc`: user IDs `olivia@example.org` and
  `olivia@example.net`.
- `openpgp/rita-revoked-uid.asc`: `rita@example.org` user ID revoked, other
  user ID valid.
- `openpgp/eve-expired.asc`: encryption subkey expired.
- Binary (`.gpg`) exports of alice and alice+mallory concatenated, for WKD.
- `mock-sources/github-empty.gpg`: armor with no key in it, in the shape
  GitHub sends for a user without keys (exact text to confirm, see
  facts).

## Facts verified (SPEC 15)

| Fact | Status |
|---|---|
| WKD URL forms, hashing, `l=`, fallback rule, answer format, redirects | Verified, draft-koch-openpgp-webkey-service-22 (2026-07-22) and `gpg-wks-client` 2.4.9. SPEC 9 corrected: fall back only when the subdomain has no address. |
| keys.openpgp.org by-email endpoint, answer, 404, rate limit | Verified, https://keys.openpgp.org/about/api : armored `application/pgp-keys`, 404 if none, 1 request per minute by email (burst 50), 429 above. Only verified addresses are published (FAQ). |
| GitLab `/<user>.keys` | Verified in GitLab source: route `':username.keys' => 'users#ssh_keys'`, plain text of all SSH keys, no login, no per-action rate limit. GitLab.com unauthenticated limit: 500 requests per minute per IP now, 60 per hour proposed with no date (docs.gitlab.com rate limits page). |
| GitHub `/<user>.keys` and `.gpg` | Not documented by GitHub. `.keys` is used in the age README (`curl https://github.com/<user>.keys | age -R -`). Rate limits for these web paths are not published; GitHub's 2025-05-08 changelog tightened unauthenticated limits for API, git and raw without numbers. Design does not depend on numbers (no retries, 429 handled). The exact "no keys" answer of `.gpg` is not confirmed without a live request (human question). |
| reqwest 0.13 `rustls` feature uses `rustls-platform-verifier` | docs.rs feature list. |

## Risks

- `dns-lookup` crate API not as remembered: use the `libc` wrapper (T05).
- `gpg --import` into a throwaway home for `split_keys` costs a gpg run per
  lookup. Not measured; expected to be fine for a lookup.
- GitHub may change the `.gpg` empty answer. The source treats "zero keys
  read" as "no key", whatever the text.
- Wildcard DNS: a domain with `*.example.org` makes the advanced host
  "exist", so WKD never falls back. This follows the draft and GnuPG.
