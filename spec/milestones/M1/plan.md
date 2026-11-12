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
  it may move out (decision 0001).

## crypto facade

Follows SPEC section 7, adjusted to real types:

```rust
pub enum Recipient {
    OpenPgp(identity_core::PublicKey),   // spec sketch says Cert
    Age(age::x25519::Recipient),
    Ssh(age::ssh::Recipient),
}
pub struct EncryptOpts { pub armor: bool, pub to_self: bool, pub sign: bool }
pub fn encrypt(input: impl Read, output: impl Write,
               recipients: &[Recipient], opts: &EncryptOpts) -> Result<()>;
pub fn decrypt(input: impl Read, output: impl Write,
               ctx: &DecryptCtx) -> Result<Decrypted>;  // format, signer
pub fn detect_format(head: &[u8]) -> Format;  // OpenPgpArmor, AgeArmor, OpenPgpBinary, AgeBinary, Unknown
```

- Streaming `Read` to `Write`, never a temp file (S-4). The spec sketch uses
  `Input`/`Output` types. Streams are simpler for M1. Change SPEC section 7 in
  the same PR if we keep this.
- In-memory plaintext uses `secrecy`/`zeroize` (NFR-3, S-5).
- Mixed OpenPGP and age recipients: error until decision 0002 is accepted.
  The return type may change to a list of outputs if 0002 picks "two outputs".
- Format choice: all recipients OpenPGP, use OpenPGP. All age/SSH, use age.
  FR-3's "prefer OpenPGP if the person has one" is a resolver concern (M2).
- Errors never contain plaintext or key material.

### age backend

- `age` crate with `ssh` and `armor` features. Encrypt to all recipients in
  one call. Decrypt with x25519 identity files and SSH private keys.
- SSH private keys with a passphrase: M1 CLI reads the passphrase from the
  terminal (`rpassword` or similar). The libadwaita dialog is M3.
- Self identity: `$XDG_CONFIG_HOME/send-secret/identities`, created on first
  encrypt with `to_self`, file mode 0600. Passphrase protection is optional
  in the spec, not in M1.

### OpenPGP backend

- gpgme, user's normal keyring and gpg-agent for signing and decrypting.
- Encrypt to a key file without importing it into the user's keyring (see
  fact F3). If that is not possible, stop and open a decision record.
- Sign with the default secret key. Decrypt reports signer fingerprint and
  validity.

## CLI shape (draft)

```
send-secret encrypt --to-key FILE [--to-key FILE ...] [-i IN] [-o OUT]
                    [--armor] [--no-self] [--no-sign] [--format openpgp|age]
send-secret decrypt [-i IN] [-o OUT] [--identity FILE ...]
```

- `-i`/`-o` default to stdin/stdout. `--armor` like `age -a` and `gpg -a`.
- `--format` only checks the auto choice. It never converts keys.
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
