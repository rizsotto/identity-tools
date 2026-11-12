# Decisions

One file per decision. Copy `0000-template.md` to the next free number. The
process is in `../workflow.md`, "Blocked on a decision".

## Records

| ID | Title | Status | Blocks |
|---|---|---|---|
| [0001](0001-identity-core-sharing.md) | How to share identity-core with Send Secret | deferred | when the second app needs the crate (M1 builds it in this repo) |
| [0002](0002-ssh-test-servers.md) | How integration tests get real SSH servers | proposed | M1 T10, M2 |

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
