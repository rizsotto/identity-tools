# Send Secret: encrypt a message or file for one person, in three clicks

> Working name: **Send Secret**. Check for name clashes on Flathub before release.
> Target desktops: GNOME first, and any Linux desktop where GTK4 apps run (tested: Niri). See section 7.1.
> This document is the spec for AI coding agents and human reviewers. Read all of it before writing code.
> Related project: **Key Steward**, our sibling repository. The two share the `identity-core` crate. How they share it is still open, see `spec/decisions/0001-identity-core-sharing.md`.

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
- Multiple recipients. Always add the sender as a recipient too (on by default), so you can read what you sent.
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
- **FR-3** Format choice: if the recipient has an OpenPGP key, use OpenPGP (sign + encrypt). Else if they have age or SSH keys, use age. The user can switch.
- **FR-4** GitHub/GitLab `.keys` can list several keys. Encrypt to all supported ones (any of their devices can open it). Skip unsupported types with a note (for example ECDSA and `sk-` keys are not age recipients).
- **FR-5** TOFU: on first use, show the fingerprint and ask "Use this key for Alice?". Store the pin. On change: block with a red warning, show old and new fingerprints, and require an explicit "I verified the new key" action.
- **FR-6** Output text has a short header the user can remove: `Encrypted for Alice (github:alice) with age. Open with: Send Secret, or 'age -d -i ~/.ssh/id_ed25519'.`
- **FR-7** Decrypt: detect the format (OpenPGP armor, age armor, binary). Use GnuPG for OpenPGP. For age, try `~/.ssh/id_ed25519`, `~/.ssh/id_rsa` and the age identities in `$XDG_CONFIG_HOME/send-secret/identities`. Show the verified signer for OpenPGP.
- **FR-8** Plaintext is never written to disk, except when the user saves a decrypted file explicitly.
- **FR-9** Clipboard: copy output, then clear after the timeout only if the clipboard still holds our content.
- **FR-10** Large content: if the armored text is longer than a configurable limit (default 20,000 characters), suggest file output instead.

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
│ Format: age (encrypt only)  ▾        [x] Also encrypt to me │
│                                                            │
│                         [ Encrypt and copy ]               │
└────────────────────────────────────────────────────────────┘
```
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
pub enum Recipient { OpenPgp(Cert), Age(age::x25519::Recipient), Ssh(age::ssh::Recipient) }
pub fn encrypt(input: Input, recipients: &[Recipient], opts: EncryptOpts) -> Result<Output>;
pub fn decrypt(input: Input, ctx: &DecryptCtx) -> Result<Decrypted>;  // includes signer info
```
OpenPGP and age recipients cannot be mixed in one output. If the user picks a mix, produce two outputs or ask the user to choose (see 16).

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
| WKD | Own implementation (small: z-base32 of SHA-1 of the lowercased local part, two URL forms) | Few dependencies. Easy to test. |
| Storage | SQLite (`rusqlite`) in `$XDG_DATA_HOME/send-secret/` | Pins and history. |
| Secrets in memory | `secrecy`, `zeroize` | NFR-3. |
| Packaging | Flatpak: `--share=network`, access to the gpg-agent socket, read-only `~/.ssh` (for age identities) | Document every permission. |
| License | GPL-3.0-or-later (proposed) | GNOME Circle norm. |

---

## 9. Implementation notes

- **WKD:** advanced URL `https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>?l=<local>`, direct URL `https://<domain>/.well-known/openpgpkey/hu/<hash>?l=<local>`. Try advanced first, then direct. Check that the returned key actually has a user ID with that email.
- **keys.openpgp.org:** `GET /vks/v1/by-email/<email>`. Results only include verified identities.
- **GitHub:** `https://github.com/<user>.keys` returns `authorized_keys` lines. `https://github.com/<user>.gpg` returns armored keys (may be empty). No token needed. Handle rate limits politely.
- **SSH key caveats** (show as info text when an SSH recipient is used): people may treat SSH keys as short-lived login keys and may rotate them, and keys on hardware tokens cannot decrypt age files ([age README](https://github.com/FiloSottile/age)).
- **Armor:** OpenPGP armor lines are 64 characters wide. Age armor is PEM-like. Both paste fine into Slack code blocks. Wrap the output in triple backticks when copying, as an option (on by default), so chat apps don't reformat it.
- **Sender recipient:** in OpenPGP mode use the user's default secret key. In age mode generate an age identity for the user on first run (stored with 0600 permissions, optionally passphrase-protected) and add it as a recipient.
- **Decrypt identities for age:** read SSH private keys only when decrypting, and prompt for the passphrase with a libadwaita dialog. Never cache passphrases longer than the operation.

---

## 10. Security rules (MUST)

- **S-1** Never send plaintext over the network. The only network traffic is key lookups. A CI test runs encrypt/decrypt with networking disabled after lookup and must pass.
- **S-2** A key change for a pinned contact blocks encryption until the user explicitly accepts it.
- **S-3** Always show the source of a key (which URL or keyring) next to its fingerprint.
- **S-4** Never write plaintext to temporary files. Stream file encryption from source to output.
- **S-5** Zero plaintext buffers after use. Don't log plaintext, ciphertext or passphrases at any log level.
- **S-6** Verify that the email on a WKD or keys.openpgp.org result matches the query. Reject keys whose user IDs don't match.
- **S-7** Treat all fetched keys as hostile input. Parse them in Rust/gpgme with size limits (reject keys > 1 MB).

---

## 11. Repository layout

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
- Multiple recipients and encrypt-to-self work.

### M2: Resolver + trust
- All sources in 4 work against the mocks, merged and ordered.
- WKD hash tests against known vectors from the GnuPG wiki/spec.
- TOFU: first use, same key, changed key (blocked), accepted change (history kept).

### M3: App
- Send and Open flows as in 6. Clipboard auto-clear. Large-content suggestion.
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

- [ ] The `age` crate's current API for SSH recipients, armor and multiple recipients, and which SSH key types it accepts.
- [ ] Whether `https://github.com/<user>.gpg` and `https://gitlab.com/<user>.keys` are still served and what their rate limits are.
- [ ] The WKD spec details (current draft) and the keys.openpgp.org `by-email` endpoint.
- [ ] How to ship the optional Nautilus "Encrypt for…" entry (Nautilus extensions can't live inside a Flatpak).
- [ ] Whether a Wayland app can clear the clipboard after it has lost focus, on GNOME and on Niri.
- [ ] How to reach the host gpg-agent from Flatpak for signing.

---

## 16. Open questions for the human

1. Final name and app ID.
2. Mixed recipients (one with OpenPGP, one with only SSH keys): produce two outputs, or force one format? See `spec/decisions/0002-mixed-recipients.md`.
3. Should age mode offer an optional SSH signature in v1 (non-standard for age, but it proves the sender)?
4. Default clipboard clear time (proposed 60 s).
5. Is a web decryptor for recipients without the app worth doing early? It helps adoption a lot.

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
