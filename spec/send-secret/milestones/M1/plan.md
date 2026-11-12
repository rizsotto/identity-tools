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
    OpenPgp(identity_core::PublicKey),   // spec sketch says Cert
    Age(age::x25519::Recipient),
    Ssh(age::ssh::Recipient),
}
pub enum Format { OpenPgp, Age }
pub struct EncryptOpts { pub armor: bool, pub sign: bool }

/// One recipient. In M1, one `--to-key` file. May hold keys of both formats.
pub struct Person { pub label: String, pub keys: Vec<Recipient> }

/// One message: one format, that person's keys of that format.
pub struct MessagePlan { pub label: String, pub format: Format, pub keys: Vec<Recipient> }

/// Pure: FR-3 per person, or the forced format. Err names unreachable people.
pub fn plan(people: &[Person], force: Option<Format>) -> Result<Vec<MessagePlan>, PlanError>;

/// The sender's own keys, for the self copy (FR-12).
pub struct Sender { pub openpgp: Option<Recipient>, pub age: age::x25519::Recipient }
/// Pure: label "self", only the sender's key. Forced format, else OpenPGP
/// if `sender.openpgp` is set, else age. Forced OpenPGP with no key: Err.
pub fn self_plan(sender: &Sender, force: Option<Format>) -> Result<MessagePlan, PlanError>;

/// One message, to `plan.keys` only. Never adds any other key (S-8).
pub fn encrypt(input: impl Read, output: impl Write,
               plan: &MessagePlan, opts: &EncryptOpts) -> Result<()>;

/// One result per plan (recipients, then the self copy if present), in order.
pub struct Sent { pub label: String, pub format: Format }
pub fn encrypt_each<R: Read, W: Write>(
    open_input: impl FnMut() -> io::Result<R>,
    open_output: impl FnMut(&MessagePlan) -> io::Result<W>,
    plans: &[MessagePlan], opts: &EncryptOpts) -> Vec<Result<Sent>>;
pub fn decrypt(input: impl Read, output: impl Write,
               ctx: &DecryptCtx) -> Result<Decrypted>;  // format, signer
pub fn detect_format(head: &[u8]) -> Detected;  // OpenPgpArmor, AgeArmor, OpenPgpBinary, AgeBinary, Unknown
```

- Streaming `Read` to `Write`, never a temp file (S-4). The spec sketch uses
  `Input`/`Output` types. Streams are simpler for M1. Change SPEC section 7 in
  the same PR if we keep this.
- In-memory plaintext uses `secrecy`/`zeroize` (NFR-3, S-5).
- One message per recipient, always (decision 0002, FR-11). `encrypt_each`
  opens the input once per message, so no plaintext is buffered and no
  temp file is used (S-4). The caller checks `plan` first, so an
  unreachable person stops the run before any output is written.
- Format choice per person (FR-3): OpenPGP if the person has an OpenPGP
  key, else age with all their age/SSH keys. `force` overrides; a person
  with no key in that format is `PlanError::Unreachable` naming them.
- `encrypt` refuses a plan whose keys are not all of `plan.format`
  (`Error::WrongFormat`). This is a guard; `plan` never builds such a plan.
- No sender key in a recipient's message (S-8, decision 0002
  encrypt-to-self sub-decision). `encrypt` uses only `plan.keys`. The
  OpenPGP backend sets `GPGME_ENCRYPT_NO_ENCRYPT_TO`, so gpg.conf
  `encrypt-to` cannot add a key.
- Read-back is a separate self copy (FR-12): `self_plan` gives one more
  `MessagePlan` with only the sender's key, and `encrypt_each` runs it
  after the recipients. One self copy per run.
- Errors never contain plaintext or key material.

### age backend

- `age` crate with `ssh` and `armor` features. Encrypt to all recipients in
  one call. Decrypt with x25519 identity files and SSH private keys.
- SSH private keys with a passphrase: M1 CLI reads the passphrase from the
  terminal (`rpassword` or similar). The libadwaita dialog is M3.
- Self identity: a native X25519 identity in
  `$XDG_CONFIG_HOME/send-secret/identities`, created on the first encrypt
  that makes an age self copy, file mode 0600 (parent dir 0700). Never an
  SSH key, so the self copy has no linkable SSH tag. Passphrase protection
  is optional in the spec, not in M1.
- Recipient messages hold only the recipient's keys (S-8).

### OpenPGP backend

- gpgme, user's normal keyring and gpg-agent for signing and decrypting.
- Encrypt to a key file without importing it into the user's keyring (see
  fact F3). If that is not possible, stop and open a decision record.
- Sign and encrypt in one gpgme operation, so the signature (and the
  sender's key ID) is inside the encryption. Only the recipient sees it.
- Encrypt with `GPGME_ENCRYPT_NO_ENCRYPT_TO`, so gpg.conf `encrypt-to` or
  `default-recipient-self` never adds the sender key (S-8).
- Sign with the default secret key. Decrypt reports signer fingerprint and
  validity.

## CLI shape (draft)

```
send-secret encrypt --to-key FILE [--to-key FILE ...] [-i IN] [-o OUT]
                    [--armor] [--no-self-copy] [--no-sign] [--format openpgp|age]
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
- Self copy (FR-12), on unless `--no-self-copy`: `BASE.self.<ext>` next to
  the per-recipient files, same extension rules. With one recipient, BASE
  is OUT without a trailing `.asc`, `.gpg` or `.age` (`-o msg.age` gives
  `msg.self.age`, `-o msg` gives `msg.self.age`). The self copy reads the
  input a second time and needs a file, so it needs `-i FILE` and `-o`.
  With one recipient and stdin or stdout, the message is still written,
  no self copy is made, stderr prints a note naming the missing option and
  `--no-self-copy`, and the exit code is 0. `--no-self-copy` silences it.
- The label `self` is reserved. A key file whose label is `self` is a
  usage error (exit 2).
- Stderr prints one line per output: label, file, format.
- If a write fails midway, stderr names the outputs already written and
  the exit code is 1.
- `--format` forces the format for all recipients. It never converts keys.
- `decrypt` with no `--identity` uses FR-7 defaults: `~/.ssh/id_ed25519`,
  `~/.ssh/id_rsa`, `$XDG_CONFIG_HOME/send-secret/identities`, and gpg.
- Skipped keys (unsupported SSH types) print a note to stderr.
- Signer info prints to stderr, so stdout stays clean plaintext.
- Exit codes: 0 ok, 1 error, 2 usage. No plaintext in error messages.

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
  shows only that recipient's key IDs, even with `encrypt-to` in the temp
  `gpg.conf`. An age recipient's message does not open with the sender's
  self identity, and the self copy has one X25519 stanza only.
- Plaintext marker: a random string per test, so the S-4 test can scan the
  temp `HOME` for it after a run.
- Tests skip with a loud failure (not a silent pass) if `gpg` or `age` is
  missing. CI must have both (devcontainer `EXTRA_PACKAGES`).

## Fixtures

`tests/fixtures/gen.sh` makes every key: OpenPGP (Ed25519/Cv25519 and RSA,
no passphrase, one with passphrase for the agent path), age x25519, SSH
Ed25519, SSH RSA, plus unsupported ECDSA and a fake `sk-` line. Output is
committed. Regenerate only with the script. Fake names and `example.org`
emails only.

## Facts from SPEC section 15 that M1 depends on

| ID | Fact | Status |
|---|---|---|
| F1 | SPEC 15 item 1: `age` crate API for SSH recipients, armor, multiple recipients, and which SSH key types it accepts | to verify (T01) |
| F2 | New: the Rust `gpgme` crate builds against Fedora's gpgme 2.0.x (Fedora 45 ships 2.0.1). Add to SPEC 15 | to verify (T02) |
| F3 | New: gpgme can encrypt to a key file without importing it into the user's keyring (gpg has `--recipient-file`). Add to SPEC 15 | to verify (T02) |
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
