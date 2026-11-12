# Key Steward: manage your SSH and OpenPGP keys, and rotate them safely

> Working name: **Key Steward**. Check for name clashes on Flathub before release.
> Target desktops: GNOME first, and any Linux desktop where GTK4 apps, a Secret Service provider and notifications work (tested: Niri). See section 7.4.
> This document is the spec for AI coding agents and human reviewers. Read all of it before writing code.
> Related project: **Send Secret** lives in the same repository (`spec/send-secret/SPEC.md`). Both use the shared `identity-core` crate (see 7.3).

---

## 1. Pitch

Your digital identity is a few keys: SSH keys that log you in to servers and GitHub, and an OpenPGP key that signs commits and receives encrypted mail. Good practice says to rotate them or set expiry dates. Almost nobody does, because nobody remembers **where** each key is installed, and doing it in the wrong order locks you out.

Key Steward is a GTK4/libadwaita app for Linux desktops (GNOME first; also Niri and others) that:
1. **Keeps an inventory**: for each key, every place it is installed (servers, GitHub, GitLab, Codeberg, keyservers, your WKD).
2. **Rotates safely**: add the new key everywhere, test it, and only then remove the old one. Each step is logged, so a crash never leaves you locked out.
3. **Reminds you** before keys expire, and makes extending OpenPGP expiry a one-click task.

Today, GNOME's key app (Seahorse) is barely maintained and has no rotation workflow. No Linux app has an inventory.

---

## 2. Users and use cases

| ID | User story | v1 |
|---|---|---|
| UC-1 | As a developer, I want to see all my SSH and OpenPGP keys, with type, strength, age and expiry. | Yes |
| UC-2 | As a developer, I want to record where each SSH key is installed (servers from `~/.ssh/config`, GitHub, GitLab, Codeberg), with the app checking it for me where possible. | Yes |
| UC-3 | As a developer, I want to rotate an SSH key: generate a new one, install it everywhere, check that login works, remove the old one. | Yes |
| UC-4 | As an OpenPGP user, I want to extend my subkeys' expiry and republish my key in one step. | Yes |
| UC-5 | As an OpenPGP user, I want to replace an old subkey with a new one, and publish to keys.openpgp.org and GitHub/GitLab. | Yes |
| UC-6 | As a user, I want a reminder 30 days before a key expires. | Yes |
| UC-7 | As a user, I want warnings for weak keys (RSA < 3072, DSA, keys with no passphrase where I can detect it). | Yes |
| UC-8 | As a user, I want my revocation certificate backed up and a reminder of where it is. | Yes |
| UC-9 | As a user, I want to generate WKD files for my own domain. | Yes (export files only) |
| UC-10 | As a team admin, I want to rotate keys for 200 servers or other users. | No |
| UC-11 | As a user, I want to set up a YubiKey/smartcard. | No (later) |

---

## 3. Existing solutions and their gaps

| Tool | What it does | Gap |
|---|---|---|
| [Seahorse / "Passwords and Keys"](https://gitlab.gnome.org/GNOME/seahorse) (C + Vala) | Manages passwords, OpenPGP and SSH keys ([Wikipedia](https://en.wikipedia.org/wiki/Seahorse_(software))) | As of 2024, the last real code change was in October 2023 ([GNOME Discourse](https://discourse.gnome.org/t/seahorse-still-on-development/20555)). Still GTK3. A [GTK4 port branch](https://lists.gnome.org/archives/commits-list/2022-July/msg01827.html) from 2022 never shipped. No inventory, no rotation. |
| [Lock](https://flathub.org/apps/com.konstantintutsch.Lock) (libadwaita) | GnuPG front-end: generate, import and export keys, update expiry, encrypt and sign | OpenPGP only. No SSH, no publishing workflow, no inventory. |
| [Kleopatra](https://apps.kde.org/kleopatra/) (KDE, Qt) | Full OpenPGP and X.509 certificate manager, keyserver and WKD lookup | Qt look on GNOME. No SSH, no rotation workflow. |
| [GpgFrontend](https://flathub.org/apps/com.bktus.gpgfrontend) (Qt) | OpenPGP tool with key databases and profiles | OpenPGP only. Not native on GNOME. No rotation. |
| [Keysign](https://www.linuxlinks.com/keysign-openpgp-key-signing-helper/) (libadwaita) | In-person key signing | A different job. |
| `ssh-copy-id`, forge web UIs, `gpg --quick-set-expire` | The manual way | You have to remember every location yourself, in the right order, with no record. |
| SSH certificates (step-ca, Teleport, …) | Short-lived certificates instead of keys | The right answer for companies, but too much for one person with 5 servers and GitHub. Out of scope. |

**Main gap:** nobody tracks where a key is installed, and nobody guides a safe rotation.

---

## 4. Scope

### In scope (v1)
- Key types: OpenPGP (via the user's GnuPG keyring), SSH (Ed25519, ECDSA, RSA) from `~/.ssh/`.
- Inventory of locations:
  - **SSH servers**: read from `~/.ssh/config` plus added by hand. Installation checked by a test login.
  - **Forges**: GitHub, GitLab (gitlab.com and self-hosted), Forgejo/Gitea/Codeberg. SSH authentication keys, SSH signing keys, GPG keys.
  - **OpenPGP publishing**: keys.openpgp.org, WKD export.
- Rotation workflows: SSH key rotation, OpenPGP subkey expiry extension, OpenPGP subkey replacement.
- A journal (persistent log) for every rotation, with resume after a crash.
- Expiry reminders (background portal + notifications).
- Weak key warnings.
- Revocation certificate backup reminder (OpenPGP).
- Secure storage for forge tokens in the system keyring (Secret Service).
- Runs on GNOME and Niri (tier 1), with best effort on Sway/Hyprland and KDE (section 7.4).

### Out of scope (v1)
- Password management (Key Rack, Secrets and Seahorse do this).
- X.509/S/MIME certificates.
- SSH certificate authorities.
- Managing other people's keys or team-wide rotation.
- Smartcards/YubiKeys (later).
- Encrypting or decrypting messages (that is Send Secret).
- Root/sudo edits on servers. Only the user's own `authorized_keys`.
- Windows or macOS.

### Later
- YubiKey/OpenPGP card support.
- Signing your own keys across machines.
- Sourcehut, Bitbucket.
- Automatic WKD publishing over SFTP to your web host.

---

## 5. Requirements

### Functional
- **FR-1** Key list: name/comment, type, bits/curve, fingerprint, created, expiry, number of locations, warnings.
  SSH keys have no creation time. For them, "created" is the file date: the modification time of the private key file, else of the `.pub` file, labeled as the file date (`identity_core::scan_ssh_dir`, M1 T04).
- **FR-2** Location model: each location has a kind, a target, the key it holds, a status (`verified`, `unverified`, `missing`, `error`) and a `last_checked` time.
- **FR-3** SSH server check: run `ssh -v -E <private log file> -o BatchMode=yes -o IdentitiesOnly=yes -i <key> -o ConnectTimeout=10 <host> true` (plus the safety options in the M1 plan, which keep the check free of side effects). Verified means, in the `-E` log of the main client only: exit 0, `Authenticated to ... using "publickey".`, no partial success, and the last key the server accepted (`Server accepts key: <key path> <TYPE> SHA256:...`) is `<key>` and not a certificate. A login with `<key>-cert.pub` is reported apart, not as verified. Jump hosts, the server banner and the remote command write to stderr, which never decides the result. Exit code 0 is not enough: `-i` adds to the config's `IdentityFile` list, so another key from the config can log in (decision 0002, M1 plan "Open item for T12"). Never ask for passwords in batch mode.
- **FR-4** Forge check: list keys through the API and compare fingerprints.
- **FR-5** SSH rotation is a state machine (7.2). Each step is written to the journal before and after it runs.
- **FR-6** `authorized_keys` edits must keep line options (`from=`, `command=`, `no-pty`, …) when replacing a key, keep unrelated lines, and keep a timestamped backup on the server (`~/.ssh/authorized_keys.keysteward-<timestamp>`).
- **FR-7** OpenPGP expiry extension: extend the primary key and all valid subkeys to a chosen date (default +1 year), then offer to publish.
- **FR-8** OpenPGP subkey replacement: add a new subkey of the same usage, set the old one to expire in N days (default 30) so existing encrypted messages stay readable, then publish.
- **FR-9** Publishing: keys.openpgp.org upload via its VKS API (the user must confirm by email; show that clearly), GitHub/GitLab/Forgejo GPG key APIs, WKD export folder (advanced and direct layout).
- **FR-10** Dry-run mode for every workflow: show the exact actions without doing them.
- **FR-11** Reminders: a daily background check. Notify at 30, 7 and 1 days before expiry. Use the Background portal where it is available. Otherwise offer to install a systemd user timer that runs `key-steward --check-reminders` (section 7.4).
- **FR-12** Import and export of the inventory (JSON) for backup. It must never contain private keys or tokens.

### Non-functional
- **NFR-1** Private key material never leaves GnuPG or `~/.ssh`. Key Steward calls tools. It does not copy private keys around.
- **NFR-2** All network calls are visible in a per-workflow log the user can read.
- **NFR-3** GNOME HIG, keyboard and screen reader support, translations.
- **NFR-4** Works offline for viewing. Only checks and rotations need the network.

---

## 6. UX outline

```
┌ Key Steward ─────────────────────────────────────────────────────────┐
│ Sidebar             │ id_ed25519_work            Ed25519   2 yrs old  │
│ ─────────           │ SHA256:ab12…                                    │
│ ▸ SSH keys (3)      │ ⚠ Not rotated in 2 years                        │
│ ▸ OpenPGP keys (1)  │                                                 │
│ ▸ Reminders         │ Installed at                       Status       │
│                     │  build.example.com  (ssh config)   ✓ verified   │
│                     │  GitHub @me (auth)                 ✓ verified   │
│                     │  GitLab @me (auth)                 ? unverified │
│                     │  [+ Add location]  [Check all]                  │
│                     │                                                 │
│                     │            [ Rotate this key… ]                 │
└──────────────────────────────────────────────────────────────────────┘
```

Rotation wizard (AdwNavigationView pages):
1. **Plan:** new key type (default Ed25519), passphrase, the list of locations (checkboxes), dry-run preview.
2. **Install:** a progress list. Each location shows ✓ / ✗ and a retry button.
3. **Verify:** a test login with the new key at each server. Forge keys are checked through the API.
4. **Remove old:** only for verified locations. Unverified ones are kept and flagged.
5. **Finish:** update `~/.ssh/config` `IdentityFile` lines if the user agrees (show a diff). Archive the old key (move to `~/.ssh/retired/`, never delete without a second confirmation).

---

## 7. Architecture

### 7.1 Components
```
crates/
├── identity-core/   # shared with Send Secret: key parsing, fingerprints, GnuPG wrapper, SSH key types
├── inventory/       # locations, SQLite store, import/export
├── providers/       # one module per location kind: ssh_server, github, gitlab, forgejo, vks, wkd
├── rotation/        # state machines + journal (no UI)
├── reminders/       # background check logic
└── app/             # GTK4 + libadwaita UI
```

Provider trait (sketch):
```rust
#[async_trait]
pub trait Provider {
    fn kind(&self) -> LocationKind;
    async fn list(&self, target: &Target) -> Result<Vec<PublicKeyRef>>;
    async fn add(&self, target: &Target, key: &PublicKey, opts: &AddOpts) -> Result<()>;
    async fn remove(&self, target: &Target, key: &Fingerprint) -> Result<()>;
    async fn verify(&self, target: &Target, key: &KeyRef) -> Result<VerifyStatus>;
}
```

### 7.2 SSH rotation state machine
```
Planned → NewKeyGenerated → Installing(i/n) → Installed → Verifying(i/n)
        → Verified → RemovingOld(i/n) → OldRemoved → ConfigUpdated → Done
Any step → Failed(step, error) → (user: Retry | Skip location | Abort)
Abort after Installed: offer to remove the new key from where it was added.
```
- The journal is stored in SQLite (`rotation_steps` table). The app resumes from the last finished step on restart.
- **Invariant:** the old key is never removed from a location until the new key is verified at **that** location.
- **Invariant:** the old private key is never deleted automatically.

### 7.3 Shared with Send Secret
Send Secret lives in the same repository. Both apps use `crates/identity-core/` at the repo root, see `spec/decisions/0001-identity-core-sharing.md`.

`identity-core` holds OpenPGP and SSH key parsing and fingerprints, the GnuPG wrapper (gpgme) and common error types. Keep it free of UI and network code.

### 7.4 Desktop compatibility

**Rules (MUST)**
- **D-1** Use only public, cross-desktop interfaces: GTK, portals, freedesktop D-Bus specs (Secret Service, Notifications). Never call `org.gnome.Shell.*` private APIs.
- **D-2** Detect features at runtime and fall back cleanly. Do not branch on `XDG_CURRENT_DESKTOP` for behavior.
- **D-3** Never hard-depend on GNOME-only apps or services.

**What the app needs from the desktop, and the fallbacks**
| Need | Standard used | GNOME | Niri | Fallback |
|---|---|---|---|---|
| Token storage | Secret Service (via `oo7`; portal inside Flatpak) | gnome-keyring | gnome-keyring is in Niri's recommended setup ([Niri docs](https://niri-wm.github.io/niri/Important-Software.html)) | KeePassXC's Secret Service. If none: refuse to store tokens and say why. Never store them in plain files. |
| Notifications | Notification portal / `org.freedesktop.Notifications` | Shell | mako or another notification daemon (per Niri docs) | In-app banner on next start. |
| Daily reminders | Background portal | Available | The GTK portal does not implement Background (per the [Arch wiki table](https://wiki.archlinux.org/title/XDG_Desktop_Portal)); check what the GNOME portal does on Niri | systemd user timer, or an XDG autostart entry. |
| ssh-agent / gpg-agent | Their standard sockets | Usually running | Depends on the user's setup | Clear message explaining how to start them. |
| Theme | libadwaita + Settings portal | Native | Follows GNOME's dconf color scheme setting (Niri docs) | n/a |

**Tiers:** tier 1 = GNOME (current stable) and Niri with the recommended portals. Tier 2 = Sway/Hyprland and KDE Plasma (best effort).

---

## 8. Tech stack and decisions

| Decision | Choice | Why |
|---|---|---|
| Language | Rust (stable) | Safety for security-critical code. Good gtk4-rs and crypto ecosystem. |
| UI | gtk4-rs + libadwaita-rs | Native GNOME, GNOME Circle path. |
| OpenPGP backend | GnuPG via `gpgme` crate | Users' keys already live in `~/.gnupg`, and gpg-agent handles passphrases and smartcards. Keep it behind a trait so Sequoia can be added later. |
| SSH keys | `ssh-key` crate for parsing and fingerprints. `ssh-keygen` for generation (respects user defaults, supports `-a` rounds) | Avoid writing private keys ourselves. |
| Remote servers | Call the system `ssh` binary | Respects `~/.ssh/config`, ProxyJump, agent, known_hosts and hardware keys. Do not use a Rust SSH library. |
| HTTP | `reqwest` with rustls | Forge and VKS APIs. |
| Secrets (tokens) | `oo7` crate (Secret Service / portal) | Standard in GNOME Rust apps. Works in Flatpak. |
| Storage | SQLite via `rusqlite` in `$XDG_DATA_HOME/key-steward/` | Journal needs transactions. |
| Async | `tokio` for network, glib main loop for UI. Bridge with `glib::spawn_future_local` / channels | Standard gtk-rs pattern. |
| Packaging | Flatpak with `--filesystem=~/.ssh`, `--filesystem=~/.gnupg` (or xdg-run gnupg socket), `--talk-name` for the ssh-agent socket, `--share=network` | Needs host keys and agent. Document every permission. |
| License | GPL-3.0-or-later (proposed) | GNOME Circle norm. |

---

## 9. Implementation notes

### 9.1 Editing `authorized_keys` on a server
Send a small POSIX `sh` script over `ssh host 'sh -s'` on stdin. Do not build a remote command string with user data in it. The script must:
1. `umask 077`, and create `~/.ssh` if missing.
2. Copy `authorized_keys` to a timestamped backup.
3. Write the new content to a temp file in `~/.ssh/`, then `mv` it over the old file (atomic).
4. Print a checksum so the app can confirm the result.

Compute the new content **locally**: download the current file (`cat`), parse it, add or remove lines, keep options and comments, then upload. This keeps all logic in tested Rust code.

Respect a non-default `AuthorizedKeysFile` only if the user configures it (v1: show a note if the check fails).

### 9.2 Forge APIs (verify exact endpoints and scopes, see 15)
- GitHub: `GET/POST/DELETE /user/keys` (auth), `/user/ssh_signing_keys`, `/user/gpg_keys`. Fine-grained token with the matching permissions.
- GitLab: `/user/keys`, `/user/gpg_keys`. Personal access token with the `api` scope.
- Forgejo/Gitea/Codeberg: `/api/v1/user/keys`, `/api/v1/user/gpg_keys`.
- Store a token per account in Secret Service. Never write tokens to SQLite or logs.

### 9.3 OpenPGP
- Extend expiry: `gpgme` key edit, or `gpg --quick-set-expire <fpr> <date> '*'` for subkeys (verify the exact form).
- New subkey: `gpg --quick-add-key <fpr> ed25519 sign <expiry>` and `cv25519 encr`.
- keys.openpgp.org: VKS `POST /vks/v1/upload`, then `POST /vks/v1/request-verify` for the user's emails. Tell the user to click the email links.
- WKD export: produce `openpgpkey/<domain>/hu/<zbase32(sha1(localpart))>` and `policy` files (advanced method) plus the direct method layout. Show the upload instructions.

### 9.4 Weak key rules (v1)
- RSA < 3072 bits: warning. DSA: error. ECDSA nistp*: info ("Ed25519 preferred"). This includes security keys (`sk-ecdsa-sha2-nistp256`): `sk-ssh-ed25519` is preferred there.
- SSH key file not encrypted: warning (check the `bcrypt` KDF header in the OpenSSH private key format; do not try to decrypt).
- OpenPGP key without an expiry: info.

---

## 10. Security rules (MUST)

- **S-1** Never read private key bytes into Key Steward memory, except to check whether the file is encrypted (header only).
- **S-2** Never delete a private key without two explicit confirmations. Prefer moving it to `~/.ssh/retired/`.
- **S-3** Never remove the old key from a location before the new key is verified there.
- **S-4** Tokens only in Secret Service. Scrub them from error messages and logs.
- **S-5** Use `ssh -o BatchMode=yes` for checks. Never accept new host keys silently: if a host key is unknown, ask the user to connect once in a terminal, or show the fingerprint and ask.
- **S-6** Remote scripts are static files in the repo. User data reaches them only through stdin, never by string interpolation in a command line.
- **S-7** Every workflow shows a dry-run first. The user confirms before any change.
- **S-8** The local database stores configuration and references only: locations, their settings and status, check results, the rotation journal, and keys by fingerprint. It never stores key material (public or private) and never tokens. Keys are always read from their source (`~/.ssh`, GnuPG, the forge). The database file is 0600 in a 0700 dir.

---

## 11. Repository layout

> Changed by decision `spec/decisions/0001-identity-core-sharing.md`: this app lives in a shared repository with the other app. Its crates are in `key-steward/crates/`, the shared crate is `crates/identity-core/`, and specs are in `spec/key-steward/`. The tree below shows the app's own parts.

```
key-steward/
├── Cargo.toml (workspace)
├── crates/ inventory/ providers/ rotation/ reminders/ app/ test-support/
├── remote-scripts/ authorized_keys_apply.sh
├── data/ (desktop, metainfo, icons, gschema)
├── po/
├── build-aux/flatpak/
├── tests/
│   └── mock-forges/     # wiremock-based fake GitHub/GitLab/Forgejo APIs
├── spec/                 # SPEC.md, decisions, milestones (for developers)
└── docs/                 # user documentation
```

`key-steward/crates/test-support` holds test helpers: the test sshd harness, temp `HOME` and `GNUPGHOME`, the real-home guard and mock forge setup. It has `publish = false`. Other crates may use it only under `[dev-dependencies]`. See `spec/key-steward/decisions/0002-ssh-test-servers.md`.

---

## 12. Milestones and acceptance criteria

### M1: Read-only inventory
- Lists SSH keys in `~/.ssh` and OpenPGP keys from GnuPG with all FR-1 fields and warnings.
- Imports hosts from `~/.ssh/config`. Checks servers (FR-3) against the test sshd (section 13) in tests.
- GitHub, GitLab and Forgejo providers `list` against the mock forges.

### M2: SSH rotation
- The full state machine against 2 test sshd servers (section 13) + the mock forges.
- Kill the app at each step: on restart it resumes correctly and never removes the old key early.
- `authorized_keys` options and comments are preserved (fixture tests).

### M3: OpenPGP workflows
- Extend expiry, replace subkey, publish to a mock VKS + mock forges, WKD export matches a known-good layout.
- Revocation certificate reminder.

### M4: Reminders + polish
- Background reminders through the Background portal, or a systemd user timer where the portal is missing. Notifications at 30, 7 and 1 days.
- Passes the tier 1 desktop matrix (13): token storage, notifications, reminders and agent access all work on GNOME and Niri.
- HIG review, translations, Flatpak permissions documented, Flathub submission.

---

## 13. Test plan

- Unit tests: `authorized_keys` parser/writer (options, comments, blank lines, CRLF), fingerprint calculation, WKD hash, state machine transitions.
- Integration: `key-steward/crates/test-support` starts the system `/usr/sbin/sshd` as a normal process, as the user who runs the tests. No root, no containers. One process per server, on `127.0.0.1` and a free port. Each server has its own temp dir under `CARGO_TARGET_TMPDIR` (`<workspace>/target/tmp`, not `/tmp`, so `StrictModes yes` works) with its own `sshd_config`, a fresh host key, `UsePAM no`, `StrictModes yes`, `PerSourcePenalties no`, an absolute `AuthorizedKeysFile` and `SetEnv HOME=<temp server home>`. Run real `ssh` against it with `-F <temp ssh_config>`, `UserKnownHostsFile <temp>`, `GlobalKnownHostsFile /dev/null`, `IdentitiesOnly yes`, `IdentityAgent none` and `BatchMode yes`, with `SSH_AUTH_SOCK` removed and `HOME` set to a temp dir. Not covered: logging in as another user, root-only sshd code paths, and a distro's own `sshd_config`. See `spec/key-steward/decisions/0002-ssh-test-servers.md`.
- These tests run in CI in the same devcontainer image (`openssh-server` and `openssh-clients` are in `.devcontainer/Containerfile`). They are never skipped or marked `#[ignore]`. The harness uses the current user and uid at run time, since CI changes the uid.
- Mock forges with `wiremock`. Record real API responses once and keep them as fixtures (no tokens in fixtures).
- Crash tests: inject a failure after each journal step and assert the invariants (S-3).
- GnuPG tests: use a temporary `GNUPGHOME` with generated test keys. Never touch the developer's real keyring.
- Desktop matrix (manual, record results in the merge request): GNOME; Niri with the recommended portals; Niri without a Secret Service (the app must refuse to store tokens cleanly); Sway. Check token storage, notifications, reminders and agent access.

---

## 14. Instructions for agents

- Never run tests against real servers, real forge accounts or the real `~/.ssh` / `~/.gnupg`. Use the test sshd from `key-steward/crates/test-support`, mocks and a temporary `GNUPGHOME` / `HOME`.
- Keep `identity-core`, `inventory`, `providers` and `rotation` free of GTK.
- Every provider must implement the full trait and have mock tests before the UI uses it.
- Write the journal entry **before** doing a remote action and after it finishes.
- Run `cargo fmt`, `cargo clippy -- -D warnings` and all tests before committing.
- When a security rule (section 10) conflicts with convenience, follow the rule and note the issue in section 16.
- Follow the desktop rules D-1 to D-3 (section 7.4). Every desktop-dependent feature needs a fallback.
- Small pull requests, one milestone at a time.

---

## 15. Facts to verify before relying on them

- [ ] Exact GitHub, GitLab and Forgejo endpoints, token scopes and payload formats for SSH auth keys, SSH signing keys and GPG keys.
  - [x] Read part (M1, checked 2026-11-12 in the official docs; add/remove is still open for M2). Fixtures with fake values: `key-steward/tests/mock-forges/` (`expected.json` lists the fingerprints in each file).
    - **GitHub** ([keys](https://docs.github.com/en/rest/users/keys), [SSH signing keys](https://docs.github.com/en/rest/users/ssh-signing-keys), [GPG keys](https://docs.github.com/en/rest/users/gpg-keys), [pagination](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api)): `GET /user/keys`, `GET /user/ssh_signing_keys`, `GET /user/gpg_keys`. Headers `Accept: application/vnd.github+json`, `Authorization: Bearer <token>`, `X-GitHub-Api-Version: 2026-03-10`. Read scope: classic `read:public_key`, `read:ssh_signing_key`, `read:gpg_key`; fine-grained user permissions "Git SSH keys", "SSH signing keys", "GPG keys" (read). Pagination: `page`, `per_page` (default 30, max 100, larger values are cut to 100 silently); follow `link` `rel="next"`; no `link` header when everything fits on one page. Auth key fields: `id`, `key`, `url`, `title`, `created_at`, `verified`, `read_only`, optional `last_used`. Signing key fields: `id`, `key`, `title`, `created_at`. `key` is `<type> <base64>` with no comment. GPG key fields: `id`, `name`, `primary_key_id`, `key_id` (16 hex long key ID, not the full fingerprint), `public_key`, `emails[]`, `subkeys[]`, `can_sign`, `can_encrypt_comms`, `can_encrypt_storage`, `can_certify`, `created_at`, `expires_at`, `revoked`, `raw_key` (armored key, nullable). For a full fingerprint, parse `raw_key`.
    - **GitLab** ([user SSH and GPG keys](https://docs.gitlab.com/api/user_keys/), [pagination](https://docs.gitlab.com/api/rest/#pagination), [auth](https://docs.gitlab.com/api/rest/authentication/), [scopes](https://docs.gitlab.com/security/tokens/access_token_scopes/)): `GET /api/v4/user/keys`, `GET /api/v4/user/gpg_keys` (the old `user_gpg_keys` docs page is gone; both are on the `user_keys` page). Header `PRIVATE-TOKEN: <token>` (or `Authorization: Bearer <token>`). Offset pagination: `page`, `per_page` (default 20, max 100); headers `link`, `x-next-page`, `x-page`, `x-per-page`, `x-total`, `x-total-pages` (GitLab.com may leave some out, so follow `link` `rel="next"` or `x-next-page`). SSH key fields: `id`, `title`, `key`, `created_at`, `usage_type` (`auth`, `signing`, `auth_and_signing`; default `auth_and_signing`), plus `expires_at` and `last_used_at`. GPG key fields: `id`, `key` (armored), `created_at` only, so the fingerprint comes from parsing `key`. Not in the docs, seen only in GitLab source: `expires_at`/`last_used_at` in list responses ([ssh_key.rb](https://gitlab.com/gitlab-org/gitlab/-/raw/master/lib/api/entities/ssh_key.rb)), that `gpg_keys` paginates and that the `read_user` scope is enough for these GETs ([users.rb](https://gitlab.com/gitlab-org/gitlab/-/raw/master/lib/api/users.rb)). `api` scope works too.
    - **Forgejo/Gitea/Codeberg** ([Codeberg swagger](https://codeberg.org/swagger.v1.json), Forgejo 17, [Gitea swagger](https://gitea.com/swagger.v1.json), [API usage](https://forgejo.org/docs/latest/user/api-usage/), [token scopes](https://forgejo.org/docs/latest/user/token-scope/), [config cheat sheet](https://forgejo.org/docs/latest/admin/config-cheat-sheet/)): `GET /api/v1/user/keys` (query `page`, `limit`, `fingerprint`), `GET /api/v1/user/gpg_keys` (`page`, `limit`). Header `Authorization: token <token>` (`Bearer` also works). Read scope: `read:user`. Pagination: `link` header with `rel="next"`/`"last"` when there is more than one page, `x-total-count`; default page size 30, max 50 (`[api] DEFAULT_PAGING_NUM`, `MAX_RESPONSE_ITEMS`, can differ per instance). No separate SSH signing key endpoint. PublicKey fields: `id`, `key`, `url`, `title`, `fingerprint` (`SHA256:...`, do not trust it, compute from `key`), `created_at`, `read_only`, `key_type`, `user`; Forgejo adds `updated_at` and `verified`, Gitea has `last_used_at` and no `verified`. GPGKey fields: `id`, `primary_key_id` (a string), `key_id`, `public_key`, `emails[]`, `subkeys[]`, `can_sign`, `can_encrypt_comms`, `can_encrypt_storage`, `can_certify`, `verified`, `created_at`, `expires_at`; no `revoked`. The swaggers have no example bodies, so the Forgejo fixtures are built from the schema. Not confirmed: that `/user/keys` and `/user/gpg_keys` really send `link` and `x-total-count` (the docs describe them for list endpoints in general), and what `primary_key_id` holds for a primary key (the fixture uses `""`).
- [x] `ssh -G -F <config> -- <alias>` (OpenSSH 10.5p1, checked 2026-11-12 in the devcontainer; test `imports_hosts_from_config_fixture` in `key-steward/crates/inventory/src/ssh_config.rs`, and [ssh_config(5)](https://man.openbsd.org/ssh_config)). Prints one `keyword value` per line, keywords in lower case (`hostname`, `user`, `port`, one `identityfile` line per file). `identityfile` values are printed as written: `~` and `%` tokens (`%d`, `%h`, `%r`, `%u`) are not expanded. With no `IdentityFile` for the host it lists the defaults (`~/.ssh/id_rsa`, `id_ecdsa`, `id_ecdsa_sk`, `id_ed25519`, `id_ed25519_sk`, `id_mldsa44_ed25519`); an explicit `IdentityFile` replaces that list. An `Include` inside a `Host` block applies only to hosts matching that block. A file given with `-F` counts as a user config, so a relative `Include` path is read from `~/.ssh/`, where `~` comes from passwd, not `$HOME`. `--` before the alias works; an alias like `-oProxyCommand=x` gives "hostname contains invalid characters" and exit 255. `-G` does run `Match exec` commands (checked: a `touch` in `Match exec` ran; test `match_exec_runs_only_with_consent`), so the import refuses a config with `Match exec`, or an `Include` it cannot list, unless the user agreed (test `match_exec_is_refused_by_default`), and every `ssh -G` run has a time limit.
- [x] OpenSSH client messages that the SSH server check reads (OpenSSH 10.5p1, checked 2026-11-12 against the test sshd; tests in `key-steward/crates/providers/tests/ssh_server.rs` and unit tests in `src/ssh_server.rs`). With `-v`: `debug1: Offering public key: <path> <TYPE> SHA256:<fp> explicit|agent`, then `debug1: Server accepts key: <path> <TYPE> SHA256:<fp> explicit|agent` for a key the server takes, and `Authenticated to <host> ([<addr>]:<port>) using "publickey".` on success. `-v` on the command line wins over `LogLevel QUIET` in the config, and `-o FingerprintHash=sha256` wins over `FingerprintHash md5`. A key the server accepts but ssh cannot sign with (passphrase, no agent) is followed by the next key, which can log in. Denied: `<user>@<host>: Permission denied (publickey).`, exit 255. Unknown host key with `StrictHostKeyChecking yes`: `No <TYPE> host key is known for [<host>]:<port> and you have requested strict checking.` then `Host key verification failed.`, exit 255. Changed host key: a banner with `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!`, exit 255. Nothing listening: `ssh: connect to host <host> port <port>: Connection refused`, exit 255. With `-E <file>`, only the main client logs to the file: these lines, "Permission denied" and "Host key verification failed" go there, while a `ProxyJump` ssh (which also runs with `-v`), the server `Banner` and the remote command's stderr stay on stderr (tests `proxyjump_success_on_jump_host_is_not_verified`, `fake_lines_in_banner_are_not_verified`). `-i <key>` also loads `<key>-cert.pub`; a certificate login shows `<TYPE>-CERT` with the key's fingerprint (test `certificate_login_is_not_verified`). `AuthenticationMethods publickey,publickey` logs `Authenticated using "publickey" with partial success.` (test `partial_success_is_error`). `-o IdentityFile=none` does not clear the config's list. `AddKeysToAgent yes` in the config adds the key to the agent unless `-o AddKeysToAgent=no` is given (test `verify_does_not_add_key_to_agent`). Source: observed output; these messages are not a documented interface, so the patterns are kept in one function with tests.
- [ ] keys.openpgp.org VKS API details and rate limits.
- [ ] The exact `gpg --quick-set-expire` syntax for "all subkeys", and the gpgme equivalents.
- [ ] How to reach the host ssh-agent and gpg-agent sockets from Flatpak cleanly. Is `--filesystem=~/.ssh` acceptable for Flathub review?
- [ ] The Background portal API for periodic reminders in the current GNOME, and whether it works on Niri (with the gnome or gtk portal).
- [ ] `oo7` crate status and API in the current version.
- [x] The `gpgme` Rust crate (0.11.0, `gpgme-sys` 0.11.0) builds and works against Fedora 45's gpgme 2.0.1 with GnuPG 2.4.9. It lists keys, user IDs and subkeys in a temp `GNUPGHOME` (checked 2026-11-12, test `gpgme_lists_key_in_temp_home` in `crates/identity-core/tests/gpgme_spike.rs`). The crate's feature flags stop at GPGME 1.18, so newer calls are not wrapped. The crate is dormant (last release 2022), see `spec/decisions/0001-identity-core-sharing.md`.

---

## 16. Open questions for the human

1. Final name and app ID.
2. Flatpak or a host package first? (Flatpak needs broad file access to `~/.ssh` and `~/.gnupg`.)
3. Should "rotate" also offer to move the user to SSH signing for git commits?
4. Default new subkey algorithm: Ed25519/Cv25519 (proposed), or offer post-quantum options when GnuPG supports them?
5. Coordinate with the GNOME maintainers about the future of Seahorse's key features?
6. How to share `identity-core` with Send Secret. Decided: one shared repository. See `spec/decisions/0001-identity-core-sharing.md`.
7. How integration tests get SSH servers. Decided: the system sshd as a plain process, as the test user, and every test runs in CI. See `spec/key-steward/decisions/0002-ssh-test-servers.md`.

Status of each question: `spec/key-steward/decisions/README.md`.

---

## 17. Glossary

- **authorized_keys:** a file on a server that lists the public keys allowed to log in.
- **Forge:** a code hosting site (GitHub, GitLab, Codeberg).
- **Subkey:** an OpenPGP key bound to your main key, used day to day for signing or encryption. It can be rotated without changing your identity.
- **WKD (Web Key Directory):** publishing your OpenPGP key on your email domain so others can find it by email address.
- **VKS:** the keys.openpgp.org API.
- **Journal:** the persistent step log used to resume a rotation safely.

## 18. References

- Seahorse: https://gitlab.gnome.org/GNOME/seahorse
- GnuPG / gpgme: https://gnupg.org/software/gpgme/
- WKD spec: https://wiki.gnupg.org/WKD
- keys.openpgp.org API: https://keys.openpgp.org/about/api
- GitHub REST, user keys: https://docs.github.com/en/rest/users/keys
- GitLab user keys API: https://docs.gitlab.com/ee/api/user_keys.html
- `ssh-key` crate: https://docs.rs/ssh-key
- gtk4-rs book: https://gtk-rs.org/gtk4-rs/stable/latest/book/
- GNOME HIG: https://developer.gnome.org/hig/
