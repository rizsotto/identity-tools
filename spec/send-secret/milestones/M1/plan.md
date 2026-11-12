# M1 plan (first draft)

Status: draft. Verify the facts below before coding the tasks that need them.

## Crates touched

| Crate | M1 work |
|---|---|
| `identity-core` | Public key parsing (OpenPGP, age x25519, SSH), fingerprints, size limit, gpgme context wrapper |
| `crypto` | Encrypt/decrypt facade with two backends: age and OpenPGP (gpgme) |
| `cli` | `send-secret` binary, thin layer over `crypto` |
| `resolver`, `trust`, `app` | Untouched |

No GTK in any of these. No network.

## identity-core

Built in the core lane (T05), after review. Shared API:

- `PublicKey` is an enum with one variant per key family:
  `Ssh(SshPublicKey)`, `Age(AgeRecipient)`, `OpenPgp(OpenPgpKey)`. Common
  accessors: `kind()`, `algo()`, `fingerprint()`, `is_age_recipient()`.
- Why an enum and not one flat struct: the families have different fields
  (SSH has a comment and an `authorized_keys` encoding, age has only the
  recipient, OpenPGP has dates, user IDs and subkeys). A flat struct would
  carry fields that are always empty for some kinds, and code would have
  to check `kind` before trusting them. With the enum the compiler makes
  each caller handle each family. Decision 0001 suggested this too.
- `parse_public_keys(bytes)` returns one `ParsedLine { line, key:
  Result<PublicKey, LineError> }` per key line, so bad or unknown lines are
  skipped with a note (FR-4) and good ones still work. Whole-input errors
  (over 1,000,000 bytes, not UTF-8, OpenPGP armor, private key) are
  `KeyError`. Error text is fixed and never echoes the input.
- `is_age_recipient()`: age X25519, SSH Ed25519, SSH RSA 2048 to 4096 bits.
- `SshPublicKey::comment_display()` drops control and bidi characters.
  The raw `comment` is kept.
- `OpenPgpKey` (T06): algo, fingerprint, created, expiry, user IDs,
  subkeys (each with algo, dates and capabilities), `can_encrypt`,
  `can_sign` (usable subkey, as gpg computes it), revoked, expired,
  disabled, invalid.
- `Gpg` (T06): a gpgme context. `Gpg::with_home(dir)` in tests, always;
  `Gpg::user_default()` only in the app. `Gpg::home()` gives the home, so
  `crypto` can set the same home on its own gpgme context.
- `OpenPgpBackend` trait, implemented by `Gpg`: `public_keys`,
  `secret_keys`, `read_keys(bytes)` (no import, 1 MB limit) and
  `default_secret_key()`, which copies gpg 2.4's rules (checked against
  gpg 2.4.9): read the first existing of `gpg.conf-2.4.9`, `gpg.conf-2.4`,
  `gpg.conf-2`, `gpg.conf` (lossy UTF-8); try `default-key` values last
  first, skipping values with no secret key or only revoked, expired,
  disabled or invalid keys; else the first usable secret key that can
  sign. Not `gpgconf`: it shows only the last value and does not skip
  expired keys. Read-back (FR-12) uses
  `default_secret_key()` and its `can_encrypt` to build `OpenPgpSelf`.
- `RecipientFile` lives in `crypto` (`src/recipient_file.rs`), not in
  identity-core: it is Send Secret only (decision 0001, review of the
  core lane round 2). `RecipientFile::new(&mut identity_core::Gpg, bytes)`
  checks size, exactly one key, and that it can encrypt (refuses expired
  encryption subkeys and revoked keys), writes it 0600 in a fresh 0700 dir
  (`$XDG_RUNTIME_DIR`, else the temp dir), and deletes it on drop.
  `gpgme_recipients()` is the checked `--file\n<path>` string. Errors:
  `RecipientFileError`.
- The encrypt call is in `crypto` too: decision 0001 keeps encrypt, sign
  and decrypt out of the core, and the call needs gpgme `Data` streams
  and flags (sign, `NO_ENCRYPT_TO`) that only `crypto` should know. So
  `crypto` depends on `gpgme` and `gpgme-sys`, owns its context (same home
  as `Gpg::home()`), and makes the one `unsafe` call
  `gpgme_op_encrypt_sign_ext` (or `gpgme_op_encrypt_ext` without signing)
  with `RecipientFile::gpgme_recipients()`, keeping the `RecipientFile`
  alive until the call returns. Document the `unsafe` block with a
  `SAFETY` comment. `send-secret/crates/crypto/tests/recipient_file.rs`
  (`encrypt_sign_to`) is the model.

The sketch below is the first draft.

```rust
pub enum PublicKey {
    OpenPgp { fingerprint: String, armored: Vec<u8> },
    AgeX25519(String),           // "age1..."
    Ssh { kind: SshKind, line: String, fingerprint: String },
}
pub enum SshKind { Ed25519, Rsa, Unsupported(String) }   // ecdsa, sk-*
pub fn parse_public_keys(bytes: &[u8]) -> Result<Vec<PublicKey>>;
```

- One file can hold several keys (an `authorized_keys` list, several armored
  certs). Return all of them. Unsupported SSH kinds come back marked, so the
  caller can skip them with a note (FR-4).
- Reject input over 1 MB before parsing (S-7).
- OpenPGP fingerprints come from gpgme (import into a throwaway context),
  not from our own packet parser. No home-made OpenPGP parsing.
- `Gpg` wrapper: builds a gpgme context with an explicit home dir. Tests
  always pass a temp dir. Production uses the default.
- Names are a draft. Keep the crate free of send-secret specific logic, since
  Key Steward uses it too (decision 0001).

## crypto facade

Follows SPEC section 7, adjusted to real types:

```rust
pub enum Recipient {
    OpenPgp(OpenPgpCert),   // key file bytes, max 1 MB; one or more keys, each checked (F3)
    Age(AgeKey),            // AgeKey::X25519(age::x25519::Recipient) | AgeKey::Ssh(age::ssh::Recipient)
}
pub enum Format { OpenPgp, Age }
pub struct EncryptOpts {
    pub armor: bool,
    pub sign: bool,
    pub gnupg_home: Option<PathBuf>,  // None: gpg's default (GNUPGHOME or ~/.gnupg)
    pub signer: Option<String>,       // fingerprint from openpgp_user(); needed to sign
}

/// One recipient. In M1, one `--to-key` file. May hold keys of both formats.
pub struct Person { pub label: String, pub keys: Vec<Recipient> }

/// One message: one format, that person's keys of that format, plus the
/// sender's key in that format (FR-12, S-8). `plan` leaves `sender: None`.
pub struct MessagePlan { pub label: String, pub format: Format, pub keys: Vec<Recipient>,
                         pub sender: Option<Recipient> }

/// Pure: FR-3 per person, or the forced format. Err names unreachable people.
pub fn plan(people: &[Person], force: Option<Format>) -> Result<Vec<MessagePlan>, PlanError>;

/// The sender's own keys, added to each message for read-back (FR-12,
/// decision 0004). Found before any output is written. `age` is `None`
/// when no message is age, so no identity is made for nothing.
pub struct Sender { pub openpgp: OpenPgpSelf, pub age: Option<age::x25519::Recipient> }
/// The default secret key as read-back key and signer (the same key).
pub struct OpenPgpUser { pub self_key: OpenPgpSelf, pub signer: Option<String> }
pub fn openpgp_user(home: Option<&Path>) -> Result<OpenPgpUser>;
/// The default secret key (gpg.conf `default-key`, else the first secret
/// key) and whether it has a valid encryption subkey.
pub enum OpenPgpSelf { CanEncrypt(OpenPgpCert), NoSecretKey, CannotEncrypt }
/// Pure: sets `sender` on each plan to the sender's key in its format.
/// OpenPGP without `OpenPgpSelf::CanEncrypt`: stays `None`, the caller
/// notes it. Never touches `keys`.
pub fn add_sender(plans: &mut [MessagePlan], sender: &Sender);

/// One message, to `plan.keys` and `plan.sender` only. Never adds any
/// other key (S-8).
pub fn encrypt(input: impl Read + Send, output: impl Write + Send,
               plan: &MessagePlan, opts: &EncryptOpts) -> Result<()>;

/// Checks ALL plans first; Err if one fails, and then nothing is opened.
/// Else one result per plan, in order.
pub struct Sent { pub label: String, pub format: Format }
pub fn encrypt_each<R: Read + Send, W: Write + Send>(
    open_input: impl FnMut() -> io::Result<R>,
    open_output: impl FnMut(&MessagePlan) -> io::Result<W>,
    plans: &[MessagePlan], opts: &EncryptOpts) -> Result<Vec<Result<Sent>>>;
pub fn decrypt(input: impl Read + Send, output: impl Write + Send,
               ctx: &DecryptCtx) -> Result<Decrypted>;  // format, more_messages, signer
pub fn detect_format(head: &[u8]) -> Detection;  // format: OpenPgpArmor, AgeArmor, OpenPgpBinary, AgeBinary, Unknown; start: offset of the armor line
```

- Streaming `Read` to `Write`, never a temp file (S-4). SPEC section 7
  now shows this shape.
- As built (T08b/T09): readers and writers must be `Send` (gpgme data
  callbacks need it). `EncryptOpts` also holds `gnupg_home` (`None`: gpg's
  default) and `signer` (fingerprint from `openpgp_user()`, which reads
  `default_secret_key()` and also gives `OpenPgpSelf`). Signing on, an
  OpenPGP message and no signer is `Error::NoSigner` before any output;
  the CLI adds "use --no-sign". `encrypt_each` builds every OpenPGP
  `RecipientFile` and sets the signer before it opens anything, so a bad
  key file also writes nothing. A key file with several OpenPGP keys gives
  one message all of them open (FR-4): `RecipientFile::all` imports the
  file into a throwaway home (0700, gpg.conf `no-autostart`, deleted
  after; the user's keyring is never touched), exports each key, checks
  each one like a single key (one unusable key refuses the file, at most
  32 keys), and the `--file` lines are joined. Before any output,
  `prepare` also refuses a gpg.conf (the file gpg reads, versioned names
  first, `Gpg::conf_file`) with `recipient`, `hidden-recipient`,
  `recipient-file` or `hidden-recipient-file`, which `NO_ENCRYPT_TO` does
  not turn off, and `local-user` when signing (it adds a second signer)
  (`Error::GpgConf`, S-8). gpg takes these names only in full, at line
  start after spaces or tabs (checked with gpg 2.4.9). `Sender.age` is an
  `Option`, so the age identity is only created when a message is age.
  `Decrypted::signer` holds the
  fingerprint, status and validity; a bad signature is an error. Armored
  OpenPGP input is cut after the END line like age.
- In-memory plaintext uses `secrecy`/`zeroize` (NFR-3, S-5).
- One message per recipient, always (decision 0002, FR-11). `encrypt_each`
  opens the input once per message, so no plaintext is buffered and no
  temp file is used (S-4). The caller checks `plan` first, so an
  unreachable person stops the run before any output is written.
- Format choice per person (FR-3): OpenPGP if the person has an OpenPGP
  key, else age with all their age/SSH keys. `force` overrides; a person
  with no key in that format is `PlanError::Unreachable` naming them.
- `encrypt` refuses a plan whose keys (incl. `sender`) are not all of
  `plan.format` (`Error::WrongFormat`). This is a guard; `plan` never builds such a plan.
- A recipient's message holds that recipient's keys plus the sender's
  key, no one else's (S-8, FR-12, decision 0004). `encrypt` uses only
  `plan.keys` and `plan.sender`; the sender's key goes in through our own
  `--file` recipient list, never through gpg.conf. The OpenPGP backend
  sets `GPGME_ENCRYPT_NO_ENCRYPT_TO`, so gpg.conf `encrypt-to` cannot add
  a key, and refuses a gpg.conf with the options that flag does not cover
  (see "As built" above).
- Read-back (FR-12): `add_sender` puts the sender's key in each plan.
  OpenPGP: the default secret key, if it can encrypt. age: the sender's
  own X25519 identity, never an SSH key. No separate self copy file.
- Order: the caller builds `Sender` (asks gpgme for the default secret key
  and its encryption subkey, loads or creates the age identity if a
  message is age) and runs `plan` and `add_sender` before it opens any
  output.
- Decrypt starts reading at `Detection::start`, so text before the armor
  (BOM, backticks, a header line) is skipped. Text after the END line
  (closing backticks) must not break decrypt either: T08a/T08b check how
  the `age` crate and gpgme handle trailing text, and cut the input at the
  END line if they reject it. Done for age (T08a): the backend stops
  reading after the END line. If another armored message follows (two
  pasted together), only the first is decrypted and
  `Decrypted::more_messages` is true; the CLI prints a note on stderr
  (not an error).
- Errors never contain plaintext or key material.
- **Decrypt output on error.** Plaintext is written as it is authenticated
  (age: per 64 KiB chunk), so a damaged or truncated message can leave
  up to a few hundred KB of plaintext in the output before `Err`. The
  callers must handle it:
  - File output (`-o FILE`): open the final path with `create_new` and mode
    0600, no temp file. On error, `set_len(0)`, remove the file, exit 1.
  - Stdout: exit 1 and stderr says "output incomplete, discard it".
  - GUI (M3): decrypt into a pre-sized zeroizing buffer and show nothing
    on error.
  - No `BufWriter` around plaintext output (its buffer is not zeroed).

### age backend

- `age` crate 0.12.1 with `ssh` and `armor` features. Encrypt to all
  recipients in one call. Decrypt with x25519 identity files and SSH
  private keys. API notes in SPEC 15 item 1.
- The crate accepts `ssh-rsa` only with a 2048 to 4096 bit modulus.
  Keys outside that range are skipped with a note, like ECDSA and `sk-`
  keys (FR-4). So the age backend, not only the key type, decides if an
  SSH key is usable: build the `age::ssh::Recipient` and turn
  `Unsupported`, `RsaModulusTooSmall` and `RsaModulusTooLarge` into a
  skip note.
- SSH private keys with a passphrase: M1 CLI reads the passphrase from the
  terminal (`rpassword` or similar). The libadwaita dialog is M3.
- Self identity: a native X25519 identity in
  `$XDG_CONFIG_HOME/send-secret/identities`, created on the first encrypt
  that makes an age message (unless `--no-self`), file mode 0600 (parent
  dir 0700). Added as one more X25519 stanza to every age message. Never
  an SSH key, so the message has no SSH tag that links it to the sender. Passphrase protection
  is optional in the spec, not in M1. The file is opened with
  `O_NOFOLLOW | O_NONBLOCK`; a symlink, a FIFO or a file group or others
  can read is refused. An existing `send-secret` dir that is too open is
  set to 0700; a symlinked one is refused.
- `$XDG_CONFIG_HOME`: the CLI ignores it when it is unset, empty or a
  relative path (the XDG spec says relative paths are invalid) and uses
  `$HOME/.config` instead.
- Hostile headers: the `age` crate parses the header again after every
  read, so a 128 KiB header took 74 s. The backend caps the header at
  16 KiB and uses `Decryptor::new_buffered` (a real header with eight SSH
  RSA keys is about 5 KiB).
- Recipient messages hold only the recipient's keys and the sender's
  X25519 stanza (S-8, FR-12).

### OpenPGP backend

- gpgme, user's normal keyring and gpg-agent for signing and decrypting.
- Encrypt to a key file without importing it into the user's keyring (fact
  F3, verified): `gpgme_op_encrypt_sign_ext` with `--file\n<path>`, one
  `unsafe` call into `gpgme-sys`. Build the file with `crypto::RecipientFile`
  (see identity-core above); the `unsafe` call is in `crypto`. The recipient string is an injection point
  (a newline adds recipients or keywords such as `--hidden`). So the wrapper
  takes key bytes, not a path: size check, exactly one key (`read_keys`),
  write to a fresh 0700 temp dir as 0600 under our own name, pass that
  absolute path, delete after. Paths from outside, if ever accepted, must be
  absolute UTF-8 with no control characters and no leading or trailing
  spaces. Mapped errors, no `unwrap`. Details in SPEC 15, F3.
- Sign and encrypt in one gpgme operation, so the signature (and the
  sender's key ID) is inside the encryption. Only the recipient sees it.
- Encrypt with `GPGME_ENCRYPT_NO_ENCRYPT_TO`, so gpg.conf `encrypt-to` or
  `default-recipient-self` never adds a key (S-8). The sender's own key is
  added by us, explicitly (decision 0004).
- Armored output: use gpg's own armor through gpgme, unchanged (decision
  0003). Header lines from the user's gpg.conf are kept.
- Sign with the default secret key. Set the signer explicitly
  (`Context::add_signer`) to the key from
  `identity_core::OpenPgpBackend::default_secret_key()`, the same key that is
  added for read-back. Never rely on gpg's own default choice, so the
  signer and the read-back key cannot differ. Decrypt reports signer fingerprint
  and validity.

## CLI shape (draft)

```
send-secret encrypt --to-key FILE [--to-key FILE ...] [-i IN] [-o OUT]
                    [--armor] [--no-self] [--no-sign] [--format openpgp|age]
send-secret decrypt [-i IN] [-o OUT] [--identity FILE ...]
```

- `-i`/`-o` default to stdin/stdout. `--armor` like `age -a` and `gpg -a`.
- Each `--to-key FILE` is one recipient. Label: the file name without its
  extension, with any character outside `[A-Za-z0-9._-]` turned into `_`.
  Two files with the same label: usage error (exit 2).
- One recipient: `-o OUT` is the exact output file; no `-o` means stdout.
- Several recipients: one output per recipient. `-o BASE` is required and
  writes `BASE.<label>.asc` (OpenPGP, armored), `BASE.<label>.gpg` (OpenPGP,
  binary) or `BASE.<label>.age` (age, armored or binary). No `-o` (stdout)
  or no `-i` (stdin) is a usage error (exit 2): stdout cannot hold several
  messages, and stdin cannot be read twice without buffering plaintext.
- Read-back (FR-12, decision 0004), on unless `--no-self`: the sender's
  key goes into every recipient's message. No extra file; works with
  stdin and stdout too. If an OpenPGP message can not get the sender's
  key (no default secret key, or it can not encrypt; also with
  `--format openpgp`), the message is made without it and stderr prints
  a note naming that recipient, exit 0. The note is printed only after
  every message is checked.
- Stderr prints one line per output: label, file, format.
- If a write fails midway, stderr names the outputs already written and
  the exit code is 1.
- `--format` forces the format for all recipients. It never converts keys.
- `decrypt` with no `--identity` uses FR-7 defaults: `~/.ssh/id_ed25519`,
  `~/.ssh/id_rsa`, `$XDG_CONFIG_HOME/send-secret/identities`, and gpg.
- Skipped keys (unsupported SSH types) print a note to stderr.
- Signer info prints to stderr, so stdout stays clean plaintext.
- Exit codes: 0 ok, 1 error, 2 usage. No plaintext in error messages.
- As built (T10): encrypt refuses to overwrite: if any output file exists,
  it exits 1 before writing anything. A message that fails midway has its
  file removed.

## Interop test harness

Lives in `crates/cli/tests/` (integration tests that run the built binary).

- Helper `TestEnv`: makes a temp dir with `HOME`, `GNUPGHOME`,
  `XDG_CONFIG_HOME`, `XDG_DATA_HOME`. Runs our binary, `gpg` and `age` with
  only those env vars set. Drops the dir at the end.
- Imports fixture OpenPGP keys into the temp `GNUPGHOME` with
  `gpg --batch --import`. Uses `--pinentry-mode loopback` and passphrase-free
  fixture keys, so no agent prompt appears.
- Round trips per format and key type, both directions:
  ours to `gpg`/`age`, and `gpg`/`age` to ours. Armored and binary.
- Metadata checks (S-8): `gpg --list-packets` on a recipient's message
  shows only that recipient's key IDs plus the sender's, even with
  `encrypt-to <other>` in the temp `gpg.conf`. An age recipient's message
  has the recipient's stanzas plus one X25519 stanza that the sender's
  identity opens. With `--no-self`, only the recipient's keys.
- Armor (decision 0003): armored OpenPGP output is gpg's output unchanged;
  plain `gpg --decrypt` and `gpg --verify` open it (covered by T11 interop).
- Plaintext marker: a random string per test, so the S-4 test can scan the
  temp `HOME` for it after a run.
- Tests skip with a loud failure (not a silent pass) if `gpg` or `age` is
  missing. CI must have both (devcontainer `EXTRA_PACKAGES`).

## Fixtures

`tests/fixtures/gen.sh` makes every key: OpenPGP (Ed25519/Cv25519 and RSA,
no passphrase, one with passphrase for the agent path), age x25519, SSH
Ed25519, SSH RSA, plus unsupported ECDSA, a fake `sk-` line and an SSH RSA
key over 4096 bits (the `age` crate rejects it, see F1). Output is
committed. Regenerate only with the script. Fake names and `example.org`
emails only.

## Facts from SPEC section 15 that M1 depends on

| ID | Fact | Status |
|---|---|---|
| F1 | SPEC 15 item 1: `age` crate API for SSH recipients, armor, multiple recipients, and which SSH key types it accepts | verified (T01), `age` 0.12.1. SSH RSA only 2048 to 4096 bits. See SPEC 15. |
| F2 | New: the Rust `gpgme` crate builds against Fedora's gpgme 2.0.x (Fedora 45 ships 2.0.1). Add to SPEC 15 | verified, SPEC 15 (core lane) |
| F3 | New: gpgme can encrypt to a key file without importing it into the user's keyring (gpg has `--recipient-file`). Add to SPEC 15 | verified, SPEC 15: `gpgme_op_encrypt_sign_ext` with `--file`, needs one `unsafe` call into `gpgme-sys` (core lane) |
| F4 | New: Go `age` (Fedora `age` 1.3.x) decrypts SSH RSA and Ed25519 recipients from the `age` crate, armored and binary | checked by T10 tests |

Items 2 to 6 of SPEC 15 are for M2 to M4.

## Risks

- F2 fails: pin an older crate, patch it, or switch the facade backend. Needs
  a decision record.
- F3 fails: importing into the user's keyring is a side effect the user did
  not ask for. Needs a decision record.
- gpg-agent in CI: use loopback pinentry and passphrase-free keys.

## Devcontainer packages to add

The devcontainer starts minimal (Rust only). Add these Fedora packages to
`.devcontainer/Containerfile` in the task that first needs them:

`gpgme-devel gnupg2 openssh-clients age sqlite-devel`

Also add `gtk4-devel libadwaita-devel` and `xvfb-run` for GTK tests when the
first GTK crate gets real code.
