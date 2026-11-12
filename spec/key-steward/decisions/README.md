# Decisions

One file per decision. Copy `../../decisions/0000-template.md` to the next free number.
Repo-wide decisions (like 0001, sharing identity-core) are in `spec/decisions/`. The
process is in `../../workflow.md`, "Blocked on a decision".

## Records

| ID | Title | Status | Blocks |
|---|---|---|---|
| [0002](0002-ssh-test-servers.md) | How integration tests get real SSH servers | accepted 2026-11-12: option A, sshd as the test user, all tests in CI | nothing (T10 implements it) |

## Pending (no record yet)

From SPEC section 16 and the M2 plan. None of these block M1 or M2. Open a
record when the milestone that needs it starts.

| SPEC 16 item | Question | Status |
|---|---|---|
| 1 | Final name and app ID | pending, blocks the first GTK window and M4 (Flathub). Not M2: M2 is headless (CLI) |
| 2 | Flatpak or host package first | pending, blocks M4 (also affects how M2 reaches the agent sockets) |
| 2 | Inside Flatpak, oo7 keeps tokens in its file backend (an encrypted file in the sandbox, key from the Secret portal), not in the Secret Service itself. Does that meet S-4? (SPEC 15, `oo7` item) | pending, blocks M4 |
| 3 | Offer to move to SSH signing for git during rotation | deferred: not offered in M2 (safe default, not in the M2 criteria). Blocks the GUI rotation wizard |
| 4 | Default new subkey algorithm, post-quantum options | pending, blocks M3 |
| 5 | Talk to GNOME maintainers about Seahorse | pending, blocks nothing (before M4 release) |
| M2 plan | New key passphrase in the GUI: `ssh-keygen` on a pty, or an askpass helper. The M2 CLI lets `ssh-keygen` ask on the terminal, so Key Steward never sees it | deferred, blocks the GUI rotation wizard |
| M2 plan | Non-default `AuthorizedKeysFile` on a server (SPEC 9.1). M2 refuses the server in pre-flight if the old key is not in `~/.ssh/authorized_keys` | deferred, blocks nothing yet |
