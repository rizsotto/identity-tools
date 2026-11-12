# Send Secret: encrypt a message or file for one person, in three clicks

> Working name: **Send Secret**. Check for name clashes on Flathub before release.
> Target desktops: GNOME first, and any Linux desktop where GTK4 apps run (tested: Niri). See section 7.1.
> This document is the spec for AI coding agents and human reviewers. Read all of it before writing code.
> Related project: **Key Steward** lives in the same repository (`spec/key-steward/SPEC.md`). Both use the shared `identity-core` crate, see `spec/decisions/0001-identity-core-sharing.md`.

---

## 1. Pitch

People send passwords, API tokens and private documents over Slack, Teams and email every day, in plain text. Encryption tools exist, but they make you find and import the other person's key first, so nobody uses them.

Send Secret turns it around: **say who it is for, paste the secret, copy the result.**

1. Type a name, an email address or a GitHub/GitLab username.
2. The app finds that person's public key (WKD, keys.openpgp.org, GitHub/GitLab key lists, or your saved contacts) and shows where it came from.
3. Paste text or drop a file.
4. Get text you can paste into Slack or email (or a file to attach), plus a one-line "how to open this" note.

The same app opens secrets sent to you.

---

## 2. Users and use cases

| ID | User story | v1 |
|---|---|---|
| UC-1 | As a developer, I want to send a database password to a colleague over Slack so that only they can read it. | Yes |
| UC-2 | As a user, I want to type `github:alice` and have the app use Alice's published SSH keys. | Yes |
| UC-3 | As a user, I want to type `bob@example.org` and have the app find Bob's OpenPGP key via WKD or keys.openpgp.org. | Yes |
| UC-4 | As a user, I want the app to remember the key the first time and warn me if it changes later. | Yes |
| UC-5 | As a user, I want to encrypt a file (a PDF contract, a `.env` file) and get a file to attach. | Yes |
| UC-6 | As a recipient, I want to paste an encrypted message into the app and read it. | Yes |
| UC-7 | As a recipient, I want to know who sent it (signature), when the format allows it. | Yes (OpenPGP mode) |
| UC-8 | As a user, I want to send to several people at once. | Yes |
| UC-9 | As a user, I want the copied secret cleared from the clipboard after a while. | Yes |
| UC-10 | As a user, I want to send a self-destructing link instead (needs a server). | No |

---

## 3. Existing solutions and their gaps

| Tool | What it does | Gap |
|---|---|---|
| [Kleopatra](https://apps.kde.org/kleopatra/) (KDE, Qt) | Encrypts to an email address and finds the key through WKD ([GnuPG tracker](https://static.dev.gnupg.org/T5334.html)) | Qt look on GNOME. Heavy certificate-manager UI. OpenPGP only. No GitHub/GitLab lookup. |
| [Lock](https://flathub.org/apps/com.konstantintutsch.Lock) (libadwaita) | Encrypt, decrypt, sign and verify text and files with GnuPG | You must import recipient keys yourself. No lookup, no SSH/age. |
| [GpgFrontend](https://flathub.org/apps/com.bktus.gpgfrontend) (Qt) | Encrypt and sign texts and files | Not native on GNOME. Manual key handling. |
| [Seahorse](https://gitlab.gnome.org/GNOME/seahorse) | Key management, Files integration | Stalled, GTK3, no recipient lookup flow. |
| [Hideout](https://flathub.org/apps/it.andreafontana.hideout) (libadwaita) | File encryption | Password-based only. No recipients. |
| [age](https://github.com/FiloSottile/age) / [rage](https://github.com/str4d/rage) (CLI) | Modern encryption. Can encrypt to SSH keys, including a GitHub user's keys | Command line only. No GUI on Linux. No key memory or trust warnings. No signatures. |
| One-time-secret websites | Link that works once | You must trust the server. Not end-to-end in most cases. |

**Main gap:** finding the recipient's key is the hard part, and no GNOME app does it. No app combines OpenPGP and age/SSH recipients behind one simple "who is it for?" box.

---

## 4. Scope

### In scope (v1)
- Two formats:
  - **OpenPGP** (encrypt + sign) via GnuPG, for recipients with OpenPGP keys.
  - **age** (encrypt only) for recipients with age keys or SSH Ed25519/RSA keys.
- Recipient resolution (in this order, all results shown with their source):
  1. Local contacts (pinned keys) in the app.
  2. Local GnuPG keyring.
  3. WKD (advanced, then direct method).
  4. keys.openpgp.org (by email; it only shows verified addresses).
  5. `github:<user>`: `https://github.com/<user>.keys` (SSH) and `https://github.com/<user>.gpg` (OpenPGP).
  6. `gitlab:<user>`: `https://gitlab.com/<user>.keys` (and self-hosted GitLab instances the user adds).
  7. A pasted public key.
- TOFU (trust on first use): pin the key fingerprint per contact, and warn loudly if it changes.
- Text output: ASCII-armored (OpenPGP armor or age armor). File output: `.age` or `.asc` / `.gpg`.
- A "how to open" note, generated per format.
- Decrypt mode: paste text or drop a file. Uses the user's GnuPG keys or age/SSH identities.
- Multiple recipients: every recipient gets their own message, in the best format for them (FR-3, FR-11). Recipients cannot see who else got it. A recipient's message holds that recipient's keys plus the sender's key, so the sender can read it back (on by default, FR-12, S-8).
- Clipboard auto-clear (default 60 seconds, can be turned off).
- File manager integration that works everywhere: drag-and-drop onto the window, and a desktop "Open With" entry (MIME types for `.age`, `.asc`, `.gpg` to open/decrypt). An "Encrypt for…" Nautilus menu entry is optional extra for GNOME users.
- Runs on GNOME and Niri (tier 1), with best effort on Sway/Hyprland and KDE (section 7.1).

### Out of scope (v1)
- Hosting links or any server of our own.
- Sending messages (no Slack/email integration; the user pastes).
- Key management (use Key Steward or Seahorse).
- Group chats, forward secrecy, ratchets (use Signal for chat).
- S/MIME.
- Signing in age mode (age has no signatures).
- Hardware tokens as age identities (age does not support SSH keys on YubiKeys or via ssh-agent for decryption, see [age docs](https://man.archlinux.org/man/age.1)).

### Later
- Keybase-style proofs, or showing linked identities.
- An optional SSH signature (`ssh-keygen -Y sign` format) for age mode.
- GNOME Contacts integration (store fingerprints in contacts).
- A tiny web decryptor page for recipients without the app (age has a TypeScript implementation, [typage](https://github.com/FiloSottile/typage)).

---

## 5. Requirements

### Functional
- **FR-1** The recipient box accepts: an email, `github:user`, `gitlab:user`, `gitlab:host/user`, a contact name, a fingerprint, or a pasted key. The type is detected automatically.
- **FR-2** For each candidate key, show: source, key type, fingerprint (short and full), creation date, and whether it is pinned, new or changed.
- **FR-3** Format choice, per recipient: if the recipient has an OpenPGP key, use OpenPGP (sign + encrypt). Else if they have age or SSH keys, use age. The user can switch.
- **FR-4** GitHub/GitLab `.keys` can list several keys. Encrypt to all supported ones (any of their devices can open it). Skip unsupported types with a note (for example ECDSA and `sk-` keys are not age recipients).
- **FR-5** TOFU: on first use, show the fingerprint and ask "Use this key for Alice?". Store the pin. On change: block with a red warning, show old and new fingerprints, and require an explicit "I verified the new key" action.
- **FR-6** Output text has a short header the user can remove: `Encrypted for Alice (github:alice) with age. Open with: Send Secret, or 'age -d -i ~/.ssh/id_ed25519'.`
- **FR-7** Decrypt: detect the format (OpenPGP armor, age armor, binary). Armor is found at the start of a line within the first bytes, so pasted text with a UTF-8 BOM, blank lines, triple backticks (section 9) or a header line (FR-6) before it still works; decryption starts at the armor line. Use GnuPG for OpenPGP. For age, try `~/.ssh/id_ed25519`, `~/.ssh/id_rsa` and the age identities in `$XDG_CONFIG_HOME/send-secret/identities`. Show the verified signer for OpenPGP.
- **FR-8** Plaintext is never written to disk, except when the user saves a decrypted file explicitly.
- **FR-9** Clipboard: copy output, then clear after the timeout only if the clipboard still holds our content.
- **FR-10** Large content: if the armored text is longer than a configurable limit (default 20,000 characters), suggest file output instead.
- **FR-11** Several recipients: make one message per recipient, always, even when they all share a format. Each message uses that recipient's format (FR-3) and holds only that recipient's keys plus the sender's key (FR-12, S-8). Each result names its recipient. A recipient with no usable key is an error that names them; never drop one silently. See [decision 0002](decisions/0002-mixed-recipients.md).
- **FR-12** Read-back: to let the sender read back what they sent, the sender's key is added to every recipient's message (on by default, `--no-self` turns it off). OpenPGP: the sender's default secret key. age: the sender's own native X25519 identity (section 9), never an SSH key. If the sender has no key in a message's format (only possible for OpenPGP), that message is made without the sender and a note says so. No separate self copy file. See [decision 0004](decisions/0004-sender-in-recipient-message.md).

### Non-functional
- **NFR-1** The whole send flow takes at most 3 interactions for a known contact.
- **NFR-2** Network is used only for key lookup, and every request is listed in a details view.
- **NFR-3** Sensitive buffers are zeroed after use (`zeroize`, `secrecy` crates).
- **NFR-4** GNOME HIG, keyboard, screen reader, translations.

---

## 6. UX outline

```
┌ Send Secret ─────────────────────────────── [Send] [Open] ┐
│ To:  [ github:alice                                  ✓ ]   │
│      Alice · 2 SSH keys from github.com/alice.keys         │
│      SHA256:Xk3… (pinned 3 months ago)                     │
│                                                            │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ Paste text here, or drop a file                        │ │
│ │                                                        │ │
│ └────────────────────────────────────────────────────────┘ │
│ Format: age (encrypt only)  ▾        [x] Keep a copy for me │
│                                                            │
│                         [ Encrypt and copy ]               │
└────────────────────────────────────────────────────────────┘
```
- Several recipients: the result shows one block per recipient, each with the recipient's name, the format and its own copy button (FR-11). The output header (FR-6) names that recipient.
- "Open" tab: one big paste/drop area. The result appears below, with a sign status line for OpenPGP ("Signed by Bob, key pinned ✓").
- The key change warning is a full-width red banner (AdwBanner) plus a dialog. It is never a small toast.

---

## 7. Architecture

```
crates/
├── identity-core/   # shared with Key Steward: key parsing, fingerprints, GnuPG wrapper
├── resolver/        # recipient resolution: sources, ordering, result model
├── trust/           # TOFU store (SQLite): contact ↔ pinned fingerprints, history
├── crypto/          # encrypt/decrypt facade over OpenPGP (gpgme) and age (age crate)
├── cli/             # `send-secret` CLI (for tests and power users)
└── app/             # GTK4 + libadwaita UI, Files integration
```

Resolver source trait (sketch):
```rust
#[async_trait]
pub trait KeySource {
    fn name(&self) -> &'static str;                 // "WKD", "keys.openpgp.org", "github", ...
    fn accepts(&self, q: &Query) -> bool;
    async fn lookup(&self, q: &Query) -> Result<Vec<FoundKey>>;  // FoundKey has source + raw key + metadata
}
```
Resolution runs the sources that accept the query in parallel, with a timeout per source (5 s), and merges by fingerprint.

Crypto facade:
```rust
pub enum Recipient { OpenPgp(OpenPgpCert), Age(AgeKey) }   // AgeKey: X25519 or SSH
pub fn plan(people: &[Person], force: Option<Format>) -> Result<Vec<MessagePlan>, PlanError>;  // one per person
pub fn encrypt(input: impl Read + Send, output: impl Write + Send, plan: &MessagePlan, opts: &EncryptOpts) -> Result<()>;  // one message: one recipient's keys only
pub fn decrypt(input: impl Read + Send, output: impl Write + Send, ctx: &DecryptCtx) -> Result<Decrypted>;  // includes signer info
```
Streams from source to output, no temp files (S-4). Full sketch in `milestones/M1/plan.md`. Every recipient gets their own message (FR-11), so OpenPGP and age keys never mix in one output. The caller runs `encrypt` once per recipient and gets one result per recipient. Each call also gets the sender's key (FR-12). See [decision 0002](decisions/0002-mixed-recipients.md) and [decision 0004](decisions/0004-sender-in-recipient-message.md).

### 7.1 Desktop compatibility

**Rules (MUST)**
- **D-1** Use only public, cross-desktop interfaces: GTK, portals, freedesktop D-Bus specs. Never call `org.gnome.Shell.*` private APIs.
- **D-2** Detect features at runtime and fall back cleanly. Do not branch on `XDG_CURRENT_DESKTOP` for behavior.
- **D-3** Never hard-depend on Nautilus or other GNOME-only apps.

**What the app needs from the desktop, and the fallbacks**
| Need | Standard used | GNOME | Niri | Fallback |
|---|---|---|---|---|
| Clipboard copy and auto-clear | GTK clipboard (Wayland) | Works | Works while the app has focus | If clearing fails because the app lost focus or exited, tell the user: "Clipboard not cleared, clear it yourself". Never claim it was cleared. |
| gpg-agent (signing, decrypting) | Standard socket | Usually running | Depends on the user's setup | Clear message explaining how to start it. |
| File manager entry | Desktop file + MIME types | Works | Works with any file manager | Nautilus extension only as an extra. |
| Theme | libadwaita + Settings portal | Native | Follows GNOME's dconf color scheme setting ([Niri docs](https://niri-wm.github.io/niri/Important-Software.html)) | n/a |

**Tiers:** tier 1 = GNOME (current stable) and Niri with the recommended portals. Tier 2 = Sway/Hyprland and KDE Plasma (best effort).

---

## 8. Tech stack and decisions

| Decision | Choice | Why |
|---|---|---|
| Language | Rust (stable) | Memory safety. The `age` crate is a native Rust implementation. |
| UI | gtk4-rs + libadwaita-rs | Native GNOME, GNOME Circle path. |
| age | [`age` crate](https://docs.rs/age) (from rage) with the `ssh` and `armor` features | Compatible with Go age. SSH recipient support. |
| OpenPGP | GnuPG via `gpgme` | Uses the user's existing keys and gpg-agent for signing. Sequoia is a later option behind the same facade. |
| HTTP | `reqwest` + rustls | Key lookups. |
| Async | `tokio` | Only for key lookups (resolver). Encrypt and decrypt stay sync. Same as Key Steward. |
| WKD | Own implementation (small: z-base32 of SHA-1 of the lowercased local part, two URL forms) | Few dependencies. Easy to test. |
| Storage | SQLite (`rusqlite`) in `$XDG_DATA_HOME/send-secret/` | Pins and history. |
| Secrets in memory | `secrecy`, `zeroize` | NFR-3. |
| Packaging | Flatpak: `--share=network`, access to the gpg-agent socket, read-only `~/.ssh` (for age identities) | Document every permission. |
| License | GPL-3.0-or-later (proposed) | GNOME Circle norm. |

---

## 9. Implementation notes

- **WKD:** advanced URL `https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>?l=<local>`, direct URL `https://<domain>/.well-known/openpgpkey/hu/<hash>?l=<local>`. `<domain>` in lower case; `<hash>` is z-base-32 of SHA-1 of the local part with only ASCII letters lowered; `l=` is the local part unchanged, percent-escaped. Try advanced first. Use direct only if `openpgpkey.<domain>` has no DNS address; a 404, timeout or TLS error at the advanced host is not a reason to fall back (draft section 3.1). The answer is binary (armor possible) and may hold several keys. Follow redirects only while every hop is https. Check that the returned key actually has a user ID with that email.
- **keys.openpgp.org:** `GET /vks/v1/by-email/<email>`. Results only include verified identities.
- **GitHub:** `https://github.com/<user>.keys` returns `authorized_keys` lines. `https://github.com/<user>.gpg` returns armored keys (may be empty). No token needed. Handle rate limits politely.
- **SSH key caveats** (show as info text when an SSH recipient is used): people may treat SSH keys as short-lived login keys and may rotate them, and keys on hardware tokens cannot decrypt age files ([age README](https://github.com/FiloSottile/age)).
- **Armor:** OpenPGP armor lines are 64 characters wide. Age armor is PEM-like. Both paste fine into Slack code blocks. Wrap the output in triple backticks when copying, as an option (on by default), so chat apps don't reformat it.
- **Read-back (FR-12):** the sender's key goes into each recipient's message. OpenPGP shows a key ID for every recipient key, so a forwarded or leaked message shows who sent it. The human accepted this ([decision 0004](decisions/0004-sender-in-recipient-message.md)). OpenPGP: the user's default secret key. age: an age X25519 identity the app generates for the user on first use (stored with 0600 permissions, optionally passphrase-protected). Never use an SSH key for read-back.
- **Signing:** OpenPGP messages are signed, then encrypted, in one gpgme operation. The signature and the sender's key ID are inside the encrypted part, so only the recipient sees them. Never put a signature outside the encryption.
- **Decrypt identities for age:** read SSH private keys only when decrypting, and prompt for the passphrase with a libadwaita dialog. Never cache passphrases longer than the operation.

---

## 10. Security rules (MUST)

- **S-1** Never send plaintext over the network. The only network traffic is key lookups. A CI test runs encrypt/decrypt with networking disabled after lookup and must pass.
- **S-2** A key change for a pinned contact blocks encryption until the user explicitly accepts it.
- **S-3** Always show the source of a key (which URL or keyring) next to its fingerprint.
- **S-4** Never write plaintext to temporary files. Stream file encryption from source to output.
- **S-5** Zero our own plaintext buffers after use. Known v1 gap, accepted: buffers inside the `age` crate, gpgme and gpg are not zeroed (section 16 question 7). Don't log plaintext, ciphertext or passphrases at any log level.
- **S-6** Verify that the email on a WKD or keys.openpgp.org result matches the query. Reject keys whose user IDs don't match.
- **S-7** Treat all fetched keys as hostile input. Parse them in Rust/gpgme with size limits (reject keys > 1 MB).
- **S-8** A recipient's message holds only that recipient's keys and the sender's own key (FR-12). Never add anyone else's. We add the sender's key ourselves. Turn off gpg.conf `encrypt-to` for these messages (gpgme `GPGME_ENCRYPT_NO_ENCRYPT_TO`). That flag does not cover gpg.conf `recipient`, `hidden-recipient`, `recipient-file` and `hidden-recipient-file`, and `local-user` adds a second signer; gpgme can not turn these off, so OpenPGP encryption refuses to start while the gpg.conf gpg reads has them (`local-user` only when signing). Armor header lines (`Comment:`, `Version:`) come from the user's own gpg.conf and are kept as gpg writes them; we do not filter or rewrite gpg output ([decision 0003](decisions/0003-openpgp-armor-headers.md)). Read-back: [decision 0004](decisions/0004-sender-in-recipient-message.md).

---

## 11. Repository layout

> Changed by decision `spec/decisions/0001-identity-core-sharing.md`: this app lives in a shared repository with the other app. Its crates are in `send-secret/crates/`, the shared crate is `crates/identity-core/`, and specs are in `spec/send-secret/`. The tree below shows the app's own parts.

```
send-secret/
├── Cargo.toml (workspace)
├── crates/ identity-core/ resolver/ trust/ crypto/ cli/ app/
├── data/ (desktop, metainfo, icons, gschema, nautilus extension or share target)
├── po/
├── build-aux/flatpak/
├── tests/
│   ├── fixtures/          # test keys (OpenPGP, age, SSH), never real people's keys
│   └── mock-sources/      # wiremock fake WKD, VKS, GitHub, GitLab
├── spec/                 # SPEC.md, decisions, milestones (for developers)
└── docs/                 # user documentation
```

---

## 12. Milestones and acceptance criteria

### M1: Crypto core + CLI
- `send-secret encrypt --to-key alice.pub -i msg.txt` and `decrypt` work for OpenPGP and age (x25519, SSH Ed25519, SSH RSA).
- Interop: files from our CLI decrypt with `gpg` and Go `age`, and the reverse.
- Multiple recipients work, one message per recipient (FR-11). Each recipient's message opens with that recipient's key and with the sender's key, and holds no one else's (S-8, FR-12).

### M2: Resolver + trust
- All sources in 4 work against the mocks, merged and ordered.
- WKD hash tests against known vectors from the GnuPG wiki/spec.
- TOFU: first use, same key, changed key (blocked), accepted change (history kept).

### M3: App
- Send and Open flows as in 6. With several recipients, one result and one copy button per recipient. Clipboard auto-clear. Large-content suggestion.
- Key change banner and dialog.
- Keyboard-only and Orca walkthrough.

### M4: Integration + polish
- Drag-and-drop and "Open With" for `.age`/`.asc`/`.gpg` on all tier 1 desktops. Optional Nautilus "Encrypt for…" entry.
- Passes the tier 1 desktop matrix (13).
- HIG review, translations, documented Flatpak permissions, Flathub submission.

---

## 13. Test plan

- Unit: query parsing, WKD hashing and URLs, `.keys` parsing (including unsupported key types), armor detection, TOFU state transitions.
- Interop: test against the `gpg` and `age` binaries in CI (round trips both ways).
- Mocks: wiremock for WKD (both methods), VKS, GitHub and GitLab, including 404, timeouts, rate limits, huge responses and mismatched emails (S-6).
- Security tests: no plaintext on disk (run encryption under a temporary `HOME` and scan for the plaintext marker), no network after lookup (S-1).
- Use a temporary `GNUPGHOME` and generated keys only.
- Desktop matrix (manual, record results in the merge request): GNOME; Niri with the recommended portals; Sway. Check clipboard copy and clear (including after focus loss), gpg-agent access, Open With, drag-and-drop.

---

## 14. Instructions for agents

- Never use real people's keys or real lookups in tests. Use fixtures and mocks.
- Keep `crypto`, `resolver` and `trust` free of GTK.
- Don't add a format or a key source that is not listed in section 4.
- Don't build your own crypto. Only call `age` and gpgme.
- Every source must handle: not found, timeout, malformed data and oversized data.
- Run `cargo fmt`, `cargo clippy -- -D warnings` and all tests (including interop) before committing.
- When the user experience and a security rule conflict, follow the rule and write the issue in section 16.
- Follow the desktop rules D-1 to D-3 (section 7.1). Every desktop-dependent feature needs a fallback.

---

## 15. Facts to verify before relying on them

- [x] The `age` crate's current API for SSH recipients, armor and multiple recipients, and which SSH key types it accepts. Checked 2026-11-12 (M1 T01) with `age` 0.12.1 (features `ssh`, `armor`) and Go `age` 1.3.1, by a spike against generated keys:
  - SSH recipients: `age::ssh::Recipient::from_str` takes one `authorized_keys` line (a trailing comment is fine). It accepts `ssh-ed25519` and `ssh-rsa` with a 2048 to 4096 bit modulus. Other types give `ParseRecipientKeyError::Unsupported(key_type)` (seen for `ecdsa-sha2-nistp256` and `sk-ssh-ed25519@openssh.com`), RSA under 2048 bits gives `RsaModulusTooSmall`, RSA over 4096 bits gives `RsaModulusTooLarge` (Go `age` accepts an 8192 bit key, the crate does not), junk gives `Invalid`. So "supported" depends on the RSA size too, not only the key type (FR-4).
  - SSH identities: `age::ssh::Identity::from_buffer(reader, filename)` gives `Unencrypted`, `Encrypted` (passphrase, needs `.with_callbacks(impl age::Callbacks)`) or `Unsupported(UnsupportedKey::{Type, Hardware, ...})`.
  - x25519: `age::x25519::Identity::generate()`, `.to_public()`, `.to_string()` returns a `SecretString`. `age::IdentityFile::from_file` reads `age-keygen` files.
  - Multiple recipients: `age::Encryptor::with_recipients(iter of &dyn age::Recipient)`. x25519, `ssh-ed25519` and `ssh-rsa` mix in one file (all give an empty label set). Every key decrypts alone. No recipients gives `EncryptError::MissingRecipients`.
  - Armor: `age::armor::ArmoredWriter::wrap_output(w, Format::AsciiArmor | Format::Binary)`; call `finish()` on the stream writer, then on the armored writer. `age::armor::ArmoredReader::new(r)` reads armored and binary input alike, so `age::Decryptor::new(ArmoredReader::new(r))` covers both.
  - Decrypt: `Decryptor::decrypt(iter of &dyn age::Identity)`. No matching key gives `DecryptError::NoMatchingKeys`.
  - Interop: Go `age` 1.3.1 decrypts crate output for x25519, SSH Ed25519 and SSH RSA, armored and binary, and the crate decrypts Go `age` output for SSH Ed25519 (armored) and SSH RSA (binary). Full matrix is M1 T11.
  - Metadata: an SSH stanza line is `-> ssh-ed25519 <tag> ...` with a 4 byte key tag, visible in the file. Confirms S-8 / FR-12.
  - Zeroing (checked in M1 T08a, crate source `src/primitives/stream.rs`): decryption hands out plaintext chunks as `SecretSlice` (zeroed on drop), but `StreamWriter` keeps up to one 64 KiB plaintext chunk in a plain `Vec<u8>` that is not zeroed when it drops. Our own copy buffer is zeroed. See section 16, question 7.
  - Grease: the crate adds one random stanza with a type ending in `-grease` to every header (`src/format.rs`). It holds no key and names nobody (M1 T09).
  - Header size (M1 T08a review): `Decryptor` parses the header again after every read, so a hostile 128 KiB header took 74 s. We cap the header at 16 KiB and use `Decryptor::new_buffered` (worst case about 0.26 s; eight SSH RSA keys give about 5 KiB).
  - Trailing text: `ArmoredReader` rejects anything but whitespace after the END line (`TrailingGarbage`). Our age backend stops reading after the END line, so closing backticks work (M1 T08a).
  - Sources: https://docs.rs/age/0.12.1/age/ , https://docs.rs/age/0.12.1/age/ssh/enum.ParseRecipientKeyError.html , crate source `src/ssh/recipient.rs`, `src/protocol.rs`, `src/primitives/armor.rs` (https://docs.rs/crate/age/0.12.1/source/), `rsa` crate `RsaPublicKey::MAX_SIZE = 4096`.
- [ ] Whether `https://github.com/<user>.gpg` and `https://gitlab.com/<user>.keys` are still served and what their rate limits are. Checked 2026-11-12 (M2 planning) from docs and source only, no live request:
  - [x] GitLab: route `get ':username.keys' => 'users#ssh_keys'` (and `':username.gpg' => 'users#gpg_keys'`, verified keys only) in `config/routes/user.rb`; `UsersController#ssh_keys` renders all SSH keys as plain text, needs no login, and has no rate limit of its own. GitLab.com limits unauthenticated traffic to 500 requests per minute per IP; 60 per hour is announced with no date; a limited request gets 429 and `Retry-After`. Sources: https://gitlab.com/gitlab-org/gitlab/-/raw/master/config/routes/user.rb , https://gitlab.com/gitlab-org/gitlab/-/raw/master/app/controllers/users_controller.rb , https://docs.gitlab.com/user/gitlab_com/rate_limits/
  - [ ] GitHub: `github.com/<user>.keys` and `.gpg` are not in GitHub's docs. The age README uses `.keys` (`curl https://github.com/<user>.keys | age -R -`, https://github.com/FiloSottile/age). No rate limit is published for these paths; GitHub tightened unauthenticated limits for API, git and raw on 2025-05-08 without numbers (https://github.blog/changelog/2025-05-08-updated-rate-limits-for-unauthenticated-requests/). Answer of `.gpg` for a user with no key, checked with one live request on 2026-11-12 (users `ghost` and `octocat`): HTTP 200, `text/plain; charset=utf-8`, 125 bytes, an armor block with no packets: `-----BEGIN PGP PUBLIC KEY BLOCK-----`, `Note: This user hasn't uploaded any GPG keys.`, two empty lines, `=twTO`, `-----END PGP PUBLIC KEY BLOCK-----`. A user that does not exist gets 404. Still open: rate limits (none published). M2 does not depend on numbers: no retries, 429 handled, zero keys means "no key".
- [x] The WKD spec details (current draft) and the keys.openpgp.org `by-email` endpoint. Checked 2026-11-12 (M2 planning):
  - WKD: draft-koch-openpgp-webkey-service-22 (2026-07-22). URL forms as in section 9. Fallback to direct only "if an address for the required sub-domain does not exist"; "a non-responding server does not mean that the fall back should be carried out". Hash: only ASCII upper case is lowered, SHA-1, z-base-32 (RFC 6189 5.1.6); example `Joe.Doe@Example.ORG` gives `iy9q119eutrkn8s1mk4r39qejnbu3n5q`. `l=` is the unchanged local part. Answer: binary key, armor discouraged, keys may be concatenated, any Content-Type should be accepted. The client must check the key has the requested user ID and drop the others. Redirects only while every target is https; no answering 401. `gpg-wks-client --print-wkd-hash` (GnuPG 2.4.9) gives the same hashes, including non-ASCII local parts (only ASCII lowered); it prints `l=` lowered, unlike the draft. Sources: https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/ , local `gpg-wks-client`. Vectors in `milestones/M2/plan.md`.
  - keys.openpgp.org: `GET /vks/v1/by-email/<URI-encoded address>`, exact match only, armored answer as `application/pgp-keys`, 404 if not found. By-email requests are limited to one per minute (burst 50), 429 above. Only addresses the owner verified are published; keys without a verified address carry no user ID and gpg refuses to import them. Sources: https://keys.openpgp.org/about/api , https://keys.openpgp.org/about/faq
- [ ] How to ship the optional Nautilus "Encrypt for…" entry (Nautilus extensions can't live inside a Flatpak).
- [ ] Whether a Wayland app can clear the clipboard after it has lost focus, on GNOME and on Niri.
- [ ] How to reach the host gpg-agent from Flatpak for signing.
- [x] F2: the `gpgme` Rust crate (0.11.0, `gpgme-sys` 0.11.0) builds and works against Fedora 45's gpgme 2.0.1 with GnuPG 2.4.9 (checked 2026-11-12, test `gpgme_lists_key_in_temp_home` in `crates/identity-core/tests/gpgme_spike.rs`). Its feature flags stop at GPGME 1.18.
- [x] F3: gpgme can sign and encrypt to a public key in a file without importing it into the user's keyring. Use `gpgme_op_encrypt_ext` / `gpgme_op_encrypt_sign_ext` (GPGME 1.11+) with the recipient string `--file\n<path>`; gpgme passes it to `gpg -f` (`--recipient-file`, GnuPG 2.1.14+), which treats the key as fully valid. The test shows the key is not imported (the manual does not say so). The safe `gpgme` crate does not wrap the `_ext` calls, so the caller needs one small `unsafe` call into `gpgme-sys` (or a patch to the crate). A key read with `Context::read_keys` (no import) can not be used as a recipient in another home: gpgme hands gpg its fingerprint and gpg looks in the keyring. No temp `GNUPGHOME` is needed. Checked 2026-11-12, tests `gpgme_encrypts_to_key_file_without_import`, `key_bytes_must_hold_exactly_one_key` in `send-secret/crates/crypto/tests/recipient_file.rs`, `recipient_path_check_refuses_unsafe_paths` in `send-secret/crates/crypto/src/recipient_file.rs`, and `gpgme_read_keys_key_is_not_a_recipient_without_import` in `crates/identity-core/tests/gpgme_spike.rs`. Sources: [GPGME manual, encrypting](https://www.gnupg.org/documentation/manuals/gpgme/Encrypting-a-Plaintext.html), [gpg `--recipient-file`](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Key-related-Options.html).
  - **The recipient string is an injection point.** Each line is a key spec or a keyword. A newline in the path starts a new line: seen with `GPGME_DEBUG`, `--file\n<a>\n--hidden\n--no-file\n<fpr>` makes gpg run with `-f <a> -R <fpr>`, so an extra (hidden) recipient from the keyring is added. `--hidden`, `--no-hidden`, `--file`, `--no-file` and `--` are only keywords as whole lines (manual), so they need a newline to get in. gpgme also trims spaces at the ends of a line (another file is used), and gpg runs with `--enable-special-filenames`, so a path like `-&3` reads from a file descriptor.
  - **Design for the wrapper:** it takes key bytes, never a path. Check the size (`MAX_KEY_INPUT`) and that `read_keys` finds exactly one key (`gpg -f` wants one key per file). Write the bytes to a fresh 0700 temp dir (prefer `$XDG_RUNTIME_DIR`) with mode 0600 under a name we pick, pass that absolute path, delete the dir after. If a path is ever accepted from outside, refuse it unless it is absolute, valid UTF-8, has no control characters and no leading or trailing spaces. Return mapped errors; never `unwrap` or `assert`. Built as `crypto::RecipientFile` (M1 T06): it also refuses a key with no usable encryption subkey (expired subkey, revoked key), and gives the checked `--file\n<path>` string as a `&CStr`. The `unsafe` encrypt call also lives in `crypto`; `tests/recipient_file.rs` shows it. gpg wants one key per `--file`, so a key file with several keys is split by importing it into a throwaway home (gpg.conf `no-autostart`, so no agent starts; checked with gpg 2.4.9) and exporting each key; the `--file` lines are joined (`RecipientFile::all`, test `key_file_with_two_keys_gives_one_message_both_open`).

---

## 16. Open questions for the human

1. Final name and app ID.
2. ~~Mixed recipients: produce two outputs, or force one format?~~ Answered 2026-11-12: one message per recipient, always. See [decision 0002](decisions/0002-mixed-recipients.md). Read-back changed on 2026-11-12: the sender's key goes into each message, see [decision 0004](decisions/0004-sender-in-recipient-message.md).
3. Should age mode offer an optional SSH signature in v1 (non-standard for age, but it proves the sender)?
4. Default clipboard clear time (proposed 60 s).
5. Is a web decryptor for recipients without the app worth doing early? It helps adoption a lot.
6. gpg.conf `comment` / `emit-version` armor headers: answered, keep what gpg writes. See [decision 0003](decisions/0003-openpgp-armor-headers.md).
7. ~~S-5 and buffers inside `age`, gpgme and gpg.~~ Answered 2026-11-12: accepted for v1. S-5 zeroing covers our own buffers. Known gap: the `age` crate's encrypting `StreamWriter` keeps its last plaintext chunk (up to 64 KiB) unzeroed when it drops (SPEC 15 item 1), and OpenPGP plaintext passes through gpgme's and gpg's own buffers. We do not write our own stream code (section 14). Reporting the `age` gap upstream is a later task.
8. GitLab also serves `/<user>.gpg` (verified OpenPGP keys only, SPEC 15). Add it to section 4 next to GitLab `.keys`? M2 does not use it.
9. Should the app look up pinned contacts again in the background, to notice key changes sooner? M2 default: a pinned contact uses its pinned keys with no network; `lookup` and `encrypt --refresh` check again. Blocks M3. See `decisions/README.md`.

---

## 17. Glossary

- **Encrypt vs sign:** encryption hides content from everyone but the recipient. A signature proves who sent it. OpenPGP does both. age only encrypts.
- **age:** a modern, simple encryption format and tool. It can use SSH keys as recipients.
- **Armor:** text encoding of encrypted data so it can be pasted into chat or email.
- **TOFU (trust on first use):** trust the key the first time, remember it, and warn if it changes.
- **WKD:** looking up an OpenPGP key from the email address's domain.
- **Fingerprint:** a short unique ID of a key, used to compare keys.

## 18. References

- age: https://github.com/FiloSottile/age · spec: https://age-encryption.org/v1
- rage / age crate: https://github.com/str4d/rage · https://docs.rs/age
- age man page (SSH caveats): https://man.archlinux.org/man/age.1
- WKD: https://wiki.gnupg.org/WKD
- keys.openpgp.org API: https://keys.openpgp.org/about/api
- gpgme: https://gnupg.org/software/gpgme/
- Kleopatra WKD support: https://static.dev.gnupg.org/T5334.html
- gtk4-rs book: https://gtk-rs.org/gtk4-rs/stable/latest/book/
- GNOME HIG: https://developer.gnome.org/hig/
