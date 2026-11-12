# Decisions

One file per decision. Copy `../../decisions/0000-template.md` to the next free number.
Repo-wide decisions (like 0001, sharing identity-core) are in `spec/decisions/`. The
process is in `../../workflow.md`, "Blocked on a decision".

## Records

| ID | Title | Status | Blocks |
|---|---|---|---|
| [0002](0002-ssh-test-servers.md) | How integration tests get real SSH servers | accepted 2026-11-12: option A, sshd as the test user, all tests in CI | nothing (T10 implements it) |

## Pending (no record yet)

From SPEC section 16. None of these block M1. Open a record when the milestone
that needs it starts.

| SPEC 16 item | Question | Status |
|---|---|---|
| 1 | Final name and app ID | pending, blocks M2 (first GTK window needs an app ID) and M4 (Flathub) |
| 2 | Flatpak or host package first | pending, blocks M4 (also affects how M2 reaches the agent sockets) |
| 3 | Offer to move to SSH signing for git during rotation | pending, blocks M2 |
| 4 | Default new subkey algorithm, post-quantum options | pending, blocks M3 |
| 5 | Talk to GNOME maintainers about Seahorse | pending, blocks nothing (before M4 release) |
