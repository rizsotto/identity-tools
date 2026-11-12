# 0001: How to share identity-core between Key Steward and Send Secret

- Status: deferred (research done, decide when the second app needs the crate)
- Blocks: nothing in M1. Each M1 builds `crates/identity-core` in its own repo.
- SPEC refs: key-manager.md 7.1, 7.3, 8, 11, 16 (Q2: Flatpak or host package first); send-secret.md 7, 8, 11

## Question

Both apps list a crate called `identity-core`: OpenPGP and SSH key parsing, fingerprints, a GnuPG wrapper (via the `gpgme` crate) and common error types. No UI, no network. The apps will live in two separate GitHub repos and aim for Flathub and GNOME Circle.

How should the two repos share this crate? Or should they share it at all?

## Context

### What each app really needs from the core

I read both specs and split the core into parts.

| Part | Key Steward | Send Secret | Shared? |
|---|---|---|---|
| SSH public key parse, type, bits/curve, SHA256 fingerprint (thin layer over the `ssh-key` crate) | Yes (FR-1, keys in `~/.ssh`) | Yes (`.keys` from GitHub/GitLab, FR-2, FR-4) | Yes |
| `authorized_keys` line parser (options, key, comment) | Yes, parse and write back (FR-6, 9.1) | Yes, parse only (`github.com/<user>.keys` is `authorized_keys` lines, 9) | Parser yes, writer no |
| SSH private key "is it encrypted" header check | Yes (9.4) | No | No |
| OpenPGP key summary model (fingerprint, user IDs, created, expiry, algo, subkeys) | Yes (FR-1) | Yes (FR-2, S-6 email match) | Yes |
| List keys in the local GnuPG keyring | Yes (M1) | Yes (resolver step 2, decrypt) | Yes |
| Read keys from bytes without importing them (hostile input, size limit) | Rarely | Yes (S-7, every network lookup) | Mostly Send Secret |
| Edit keys: set expiry, add subkey | Yes (FR-7, FR-8) | No | No |
| Encrypt, sign, decrypt | No (out of scope) | Yes, but in its own `crypto` crate | No |
| WKD hash (z-base32 of SHA-1 of the lowercased local part) | Yes (WKD export, 9.3) | Yes (lookup, 9) | Yes |
| Weak key rules (9.4) | Yes | Could show them, not in spec | Maybe |
| GnuPG context setup (`GNUPGHOME`, Flatpak agent socket, temp keyring for tests) | Yes | Yes | Yes |
| Error types | Yes | Yes | Yes |

The shared part is small. My guess is 500 to 1,500 lines of Rust, mostly thin wrappers over `ssh-key` and `gpgme`, plus a WKD hash and a line parser. This is an estimate, not a measurement.

Two more facts matter:

- **The apps never exchange data.** Key Steward's inventory and Send Secret's TOFU pins are separate SQLite files. There is no IPC between the apps. So there is no wire format or type that must stay the same in both. Sharing is only about not writing the same code twice.
- **Their OpenPGP needs differ.** Key Steward manages the user's own keyring (list, edit expiry, add subkeys, export). Send Secret mostly inspects strangers' keys fetched from the network and encrypts to them. A single "GnuPG wrapper" that tries to serve both will either be a thin common base or grow into a kitchen sink. Keep it thin.

### State of the `gpgme` Rust crate (checked 2026-11-12)

- Last release: `gpgme` 0.11.0 and `gpgme-sys` 0.11.0, on 2022-11-01. No release in four years. MSRV 1.64. License LGPL-2.1. About 29,000 downloads in the last 90 days. ([crates.io API](https://crates.io/api/v1/crates/gpgme))
- Last commit on GitHub: 2024-11-19 (Windows fixes, bitflags 2 shims). Not archived. 13 open issues, the oldest from 2017. One open issue asks for "encrypting data for a public key without importing it" (#46, 2023). ([GitHub](https://github.com/gpg-rs/gpgme), [issues](https://github.com/gpg-rs/gpgme/issues))
- The C library moved on: GPGME 2.0.0 came out on 2025-06-03. It removed old trustlist and attribute functions and changed some timestamp fields from signed to unsigned long. ([GnuPG tracker](https://dev.gnupg.org/transactions/detail/PHID-XACT-TASK-ue65emrpka6yfgc))
- I checked on this machine (Fedora 45, `gpgme-2.0.1`). Every function that `gpgme-sys` 0.11.0 declares still exists in `libgpgme.so.45`, including `gpgme_op_edit`, `gpgme_op_interact` and `gpgme_op_keylist_from_data_start`. So it should still link. I did not build and run it.
- The crate already covers what the specs need: `read_keys` (list keys from data without importing, GPGME 1.14+), `set_expire`, `set_expire_all`, `create_subkey`. Its feature flags stop at GPGME 1.18, so nothing newer than that is exposed.
- Fedora 45 ships `rust-sequoia-openpgp` and `rust-sequoia-gpg-agent`, but `dnf repoquery` found no `rust-gpgme` package. I did not find out why.

Verdict: usable, but dormant. It is fine for v1 if the core hides it behind its own types.

### Alternatives

- **sequoia-openpgp**: 2.4.2 released 2026-10-14, regular releases all through 2026, MSRV 1.85, LGPL-2.0-or-later. Pure Rust. It can parse a key from bytes with no keyring at all, which fits Send Secret's "treat fetched keys as hostile" rule well. ([crates.io](https://crates.io/crates/sequoia-openpgp))
- **sequoia-gpg-agent**: 0.6.2 released 2025-11-13. Talks to `gpg-agent` directly over Assuan, without the `gpg` binary. Signing with an agent-held key is documented. ([docs.rs](https://docs.rs/sequoia-gpg-agent/latest/sequoia_gpg_agent/)) The docs page I read did not say whether it can decrypt or read the public keyring (`pubring.kbx` / keyboxd). Not verified.
- **sequoia-keystore**: 0.7.2 released 2026-02-10. ([crates.io](https://crates.io/crates/sequoia-keystore))

Note: Send Secret's crypto facade sketch already uses `Recipient::OpenPgp(Cert)`. `Cert` is Sequoia's type name, not a gpgme one.

What this means for the core: the core should expose its own small types (`Fingerprint`, `OpenPgpKeySummary`, `SshPublicKey`, `KeyError`) and never leak `gpgme` types in its public API. Then a later switch to Sequoia, for one app or both, is local. The gpgme vs Sequoia choice deserves its own decision record. It does not change the answer below.

### Flathub offline builds

- Flathub builds have no network. All dependencies must be listed as sources in the manifest. ([Flathub requirements](https://docs.flathub.org/docs/for-app-authors/requirements))
- `flatpak-cargo-generator` turns a `Cargo.lock` into a sources file. ([README](https://github.com/flatpak/flatpak-builder-tools/blob/master/cargo/README.md))
- **Git dependencies work.** I read the generator source. For a `git+` entry in `Cargo.lock` it clones the repo at the locked commit, finds the package by name anywhere in the repo (also inside a workspace subfolder), and emits a flatpak `git` source pinned to that `commit`. It also writes the Cargo source replacement config so the build stays offline. ([source](https://github.com/flatpak/flatpak-builder-tools/blob/master/cargo/flatpak-cargo-generator.py)) The git-dep code got fixes as recently as 2026-09-21.
- The README warns that offline builds fail "if bare git dependencies are present in the upstream Cargo.toml". It does not define "bare". I read it as: always pin a `rev` (or `tag`) so the lock file and the manifest agree. Not fully verified.
- crates.io dependencies are the most boring path. They also work with `cargo vendor` tarballs.
- Unrelated to sharing, but worth knowing: gpgme is a C library and it runs the `gpg` binary. I could not confirm that the GNOME runtime ships gpgme or gnupg. Seahorse's and Kleopatra's Flatpak manifests build gpgme themselves, which suggests it is not in the runtime. Each app will likely need gpgme (and maybe gnupg) as a manifest module. Not verified.

### crates.io and git deps

- crates.io refuses to publish a crate that has git dependencies. A dependency can list both `git` and `version`, and the published crate then uses the registry version. ([Cargo book](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html))
- So with option B the apps cannot be published to crates.io. That does not matter for GUI apps. It does matter for distro packagers: Fedora and Debian package Rust crates from crates.io. If host packages come first (key-manager.md 16, Q2), option A becomes more useful.

### GNOME Circle

- I could not read the Circle criteria file directly (GitLab blocked automated fetches). What follows is from the committee's blog and news reports.
- Circle needs an OSI license, use of the GNOME platform, and its quality bar. Apps are expected to be on Flathub. ([GNOME Foundation software policy](https://wiki.gnome.org/Foundation/SoftwarePolicy))
- New submissions are paused for now (May 2026). ([Circle committee update](https://blogs.gnome.org/sophieh/2026/05/29/updates-from-the-circle-committee/))
- Circle adopted the GNOME Shell extensions AI policy for new submissions, enforced from 2026-06-01. AI help is allowed, but the developer must be able to explain the code. Signs of generated code (lots of unnecessary code, inconsistent style, made-up APIs, comments that read like LLM prompts) lead to rejection. ([Circle committee update](https://blogs.gnome.org/sophieh/2026/05/29/updates-from-the-circle-committee/), [Phoronix](https://phoronix.com/news/gnome-circle-no-ai-slop), [Linuxiac](https://linuxiac.com/gnome-circle-adopts-ai-policy-and-stops-new-app-submissions/))
- I found nothing in Circle's rules about how dependencies are sourced. A git dependency or a crates.io dependency should both be fine. Not verified against the primary text.
- I found nothing that says whether two Circle apps can share one monorepo. Not verified. Circle and Flathub both treat each app as its own project with its own metainfo, issue tracker and releases, so separate repos are the safe default.

### AI coding agents

The hard case is a change that touches the core and an app at the same time. For example: add `expiry` to the key summary, then show it in Key Steward.

- In one repo this is one commit and one test run.
- Across repos, the agent needs both checkouts open, a local override so the app builds against the local core, and two commits in order (core first, then the app bumps its pin).
- Cargo supports `[patch]` in `.cargo/config.toml`, with paths relative to that file. It is meant for local use and should not be committed. ([Cargo config](https://doc.rust-lang.org/cargo/reference/config.html))
- Separate repos make the boundary clear. An agent working on Send Secret cannot quietly change the core in a way that breaks Key Steward, because the core change needs its own commit and its own CI.

## Options

### A. Own repo, published to crates.io
Pros:
- The most standard path. Flathub, `cargo vendor` and distro packagers all handle it with no extra steps.
- Semver gives a clear signal when the API breaks.
- Others could reuse it.

Cons:
- Every core change means a release: bump version, changelog, `cargo publish`, then bump the app. This is a lot of process for 500 to 1,500 lines with one maintainer.
- A crates.io release is permanent. Early API churn ends up as a pile of 0.x versions on a public registry.
- A public library invites outside users and issues. That is a support cost.
- Two steps for every cross-cutting change, like B, plus the publish step.

### B. Own repo, git dependency pinned by rev
Pros:
- Works with Flathub. `flatpak-cargo-generator` turns the locked commit into a pinned `git` source (checked in the source code).
- No publishing ritual. A commit on `main` plus a rev bump in the app is enough.
- Each app pins its own rev, so each app releases on its own schedule.
- Clear boundary, its own CI.
- Easy to move to A later: add `version` next to `git`, publish, drop `git`.

Cons:
- Two commits for a cross-cutting change, and the agent must handle a local `[patch]` override.
- Apps cannot be published to crates.io (not needed).
- Distro packagers cannot use it as is. They would need A.
- A third repo to maintain before it has proven its value.

### C. One monorepo with both apps
Pros:
- One commit for a cross-cutting change. Best for AI agents and for refactors.
- One CI, one set of tooling, one checkout.
- No versioning of the core at all.

Cons:
- Goes against the plan of one GitHub repo per app.
- One issue tracker, one star count and one README for two different apps. Each app's metainfo, Flathub page and Circle review point to a repo that is half about something else.
- Release tags need prefixes (`key-steward-1.2.0`, `send-secret-0.4.0`). Release notes and CI get more complex.
- One `Cargo.lock` means a gtk4-rs or libadwaita bump hits both apps at once. Their release cycles get coupled.
- Unknown whether Circle reviewers mind. Not verified.

### D. Copy into each repo and let them diverge
Pros:
- Zero coordination. Each app shapes its core around its own needs (they differ, see the table).
- The shared part is small and the apps share no data, so drift does not break anything between them.

Cons:
- Bug fixes in parsing (hostile input from the network, S-7) must be made twice. Easy to forget one.
- The WKD hash and the fingerprint format must match GnuPG's. Two copies means two places to get it wrong.
- An agent fixing a bug in one repo will not know about the other copy.

### E. Start inside one repo, extract later
Pros:
- No extra repo while only one app exists. Core and app change in one commit during the phase when the API changes most.
- The core's real shape comes from real use, not guesses.
- Extraction with history is a known, small job (`git filter-repo --subdirectory-filter`).

Cons:
- Needs a clear trigger, or extraction never happens and you end up with D.
- If both apps start at the same time, there is no "one repo" phase.
- The first app's needs can bend the core. Mitigated by the table above: only the shared rows go in.

## Preferred option and why

**E, then B.** Build `identity-core` as a crate inside the first app's workspace. Extract it into its own repo, consumed as a git dependency pinned by rev, on the day the second app needs any of it. Move to crates.io (A) only when a named trigger fires.

Why:

1. **The overlap is small and the apps share no data.** Sharing is worth having for the security-sensitive parsing (SSH keys, `authorized_keys` lines, WKD hash, untrusted OpenPGP keys). It is not worth the overhead of a public library from day one.
2. **The API will change most during the first M1.** In E that churn is one commit at a time in one repo. In A or B it would be two commits per change across two repos, with nobody else depending on it yet.
3. **B is the cheapest form of real sharing that Flathub accepts.** I checked the generator source: git deps become pinned `git` sources and build offline. No publishing step, each app keeps its own release cadence, and moving to A later is a small change.
4. **Separate repos match the plan and how Flathub and Circle see apps.** C would buy easier agent work at the cost of mixing two products in one repo. Two commits per cross-cutting change is a fair price.
5. **D is the fallback, not the plan.** If after Send Secret M2 the shared crate is under about 300 lines, or most changes only serve one app, stop sharing and copy. Write a short follow-up record if that happens.

Which app first: whichever starts first. If both start together, put it in Key Steward. Its M1 (read-only inventory) uses most of the shared rows: SSH parsing, fingerprints, GnuPG key listing, weak key rules. Send Secret M1 is mostly its own `crypto` crate (age and gpgme encrypt/decrypt).

### Rules for the core (all phases)

- Public API uses only the core's own types. No `gpgme::*` or `ssh_key::*` types in public signatures. This keeps the gpgme vs Sequoia question open (see Context).
- Only the rows marked "Yes" in the table go in. Key editing stays in Key Steward. Encrypt/decrypt stays in Send Secret's `crypto`. The `authorized_keys` writer stays in Key Steward.
- No GTK, no network, no async runtime. Sync functions only. The apps choose their own threading.
- Same license as the apps: GPL-3.0-or-later. Reconsider (LGPL or MIT/Apache) only if moving to crates.io.
- Size limit checks (S-7) live in the core, so both apps get them.

### Triggers

- **Extract (E to B):** the first time the second app needs one function from the core. Do not let the second app depend on the first app's repo, even though Cargo and the generator would allow it.
- **Publish (B to A):** any one of these: a distro packager asks; host packages are chosen before Flatpak (key-manager.md 16, Q2); a third project wants to use it; or the API has not had a breaking change across two releases of both apps.
- **Stop sharing (B to D):** the core is under about 300 lines, or most core changes serve only one app, after Send Secret M2.

### Setup steps

Phase 1, inside the first app (say Key Steward):

1. Create `crates/identity-core/` in the workspace, as the spec already shows. Give it its own `README.md` saying it will move out, and listing the rules above.
2. In `identity-core/Cargo.toml` do not use `workspace = true` inheritance for anything except lints. This makes extraction a copy, not a rewrite. (The generator can normalize inherited fields, but it is one less thing to break.)
3. Put its tests (fixtures, temp `GNUPGHOME`) inside `crates/identity-core/tests/`, not in the top-level `tests/`, so they move with it.
4. In the app's agent instructions (section 14), add: "Changes to `identity-core` must follow its README rules. Do not add app-specific code to it."

Phase 2, extraction (when the second app starts):

1. `git filter-repo --subdirectory-filter crates/identity-core` on a fresh clone. Push to a new public repo `identity-core` under the same GitHub owner.
2. Add a `Cargo.toml` with `[package]` (it is a single crate, no workspace), `LICENSE`, `README.md`, and CI: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test` with a temp `GNUPGHOME`, on the same MSRV as the apps.
3. Tag `v0.1.0`. Tags are for humans. The pin is the commit.
4. In both apps:
   ```toml
   identity-core = { git = "https://github.com/OWNER/identity-core", rev = "<full 40-char commit hash>" }
   ```
   Remove `crates/identity-core/` from the first app.
5. Local dev and agent setup: keep the three checkouts side by side, for example `~/Code/keys/{identity-core,key-steward,send-secret}`. In each app add a git-ignored `.cargo/config.toml`:
   ```toml
   [patch."https://github.com/OWNER/identity-core"]
   identity-core = { path = "../identity-core" }
   ```
   Add `.cargo/config.toml` to `.gitignore`. It must never reach CI or Flathub, because the Flathub build writes its own Cargo config.
6. Agent workflow for a cross-cutting change: open the agent with both repos as working directories. Change the core, run its tests. Change the app, run its tests (the `[patch]` makes the app use the local core). Commit and push the core first. Then in the app, set the new `rev`, run `cargo update -p identity-core`, and commit. Write this as a short section in each repo's agent instructions.
7. CI in each app builds against the pinned rev, never against core `main`. Optional later: a scheduled job in the core repo that builds both apps' `main` against core `main`, to catch breakage early.
8. Flathub: regenerate `cargo-sources.json` with `flatpak-cargo-generator` at each app release. Check that it contains a `git` source for `identity-core` with the pinned `commit`. Test with `flatpak-builder` and no network before submitting.

Phase 3, only if a publish trigger fires: change the dependency to `{ git = "...", rev = "...", version = "0.x" }`, publish to crates.io, then drop `git` and `rev`.

### Not verified

- Whether "bare git dependencies" in the generator README means unpinned ones. I assume yes.
- Whether the GNOME runtime includes gpgme or gnupg. Probably not.
- Whether `gpgme` 0.11.0 builds and works against GPGME 2.0. Symbols match on Fedora 45. I did not build it.
- Why Fedora 45 has no `rust-gpgme` package.
- Whether `sequoia-gpg-agent` can decrypt and read the GnuPG public keyring.
- The exact current wording of the GNOME Circle criteria, including anything about monorepos or dependency sources. I read only secondary sources.
- The 500 to 1,500 line size of the shared part is my estimate from the specs.

## Sources

- crates.io API, `gpgme`: https://crates.io/api/v1/crates/gpgme (checked 2026-11-12)
- crates.io API, `sequoia-openpgp`, `sequoia-gpg-agent`, `sequoia-keystore`, `ssh-key`, `age` (same date): https://crates.io/crates/sequoia-openpgp , https://crates.io/crates/sequoia-gpg-agent , https://crates.io/crates/sequoia-keystore
- gpg-rs/gpgme repo and issues: https://github.com/gpg-rs/gpgme , https://github.com/gpg-rs/gpgme/issues
- `gpgme` 0.11.0 and `gpgme-sys` 0.11.0 source (downloaded from static.crates.io, read locally)
- GPGME 2.0.0 release notes: https://dev.gnupg.org/transactions/detail/PHID-XACT-TASK-ue65emrpka6yfgc
- sequoia-gpg-agent docs: https://docs.rs/sequoia-gpg-agent/latest/sequoia_gpg_agent/
- flatpak-cargo-generator README: https://github.com/flatpak/flatpak-builder-tools/blob/master/cargo/README.md
- flatpak-cargo-generator source: https://github.com/flatpak/flatpak-builder-tools/blob/master/cargo/flatpak-cargo-generator.py
- Flathub requirements: https://docs.flathub.org/docs/for-app-authors/requirements
- Cargo, specifying dependencies (git deps, crates.io rule, multiple locations): https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html
- Cargo, configuration (`[patch]` in config): https://doc.rust-lang.org/cargo/reference/config.html
- GNOME Circle committee update, May 2026: https://blogs.gnome.org/sophieh/2026/05/29/updates-from-the-circle-committee/
- GNOME Foundation software policy: https://wiki.gnome.org/Foundation/SoftwarePolicy
- Phoronix on the Circle AI policy: https://phoronix.com/news/gnome-circle-no-ai-slop
- Linuxiac on the Circle AI policy: https://linuxiac.com/gnome-circle-adopts-ai-policy-and-stops-new-app-submissions/
- Seahorse Flatpak manifest builds gpgme (2021): https://lists.gnome.org/archives/commits-list/2021-September/msg10054.html
- Local checks on Fedora 45: `nm -D /usr/lib64/libgpgme.so.45` against `gpgme-sys` declarations; `dnf repoquery` for `rust-gpgme*` and `rust-sequoia-*`

## Human decision

(empty)
