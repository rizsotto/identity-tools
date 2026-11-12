# Decisions

One file per decision. Copy `../../decisions/0000-template.md` to the next free number.
Repo-wide decisions (like 0001, sharing identity-core) are in `spec/decisions/`.
See "Blocked on a decision" in `../../workflow.md`.

## Records

| No. | Title | Status | Blocks |
|---|---|---|---|
| [0002](0002-mixed-recipients.md) | Mixed OpenPGP and age recipients (SPEC 16 q2) | accepted (2026-11-12): one message per recipient | nothing (built in M1) |

## Pending (SPEC section 16, no record yet)

Make a record when work reaches the milestone it blocks.

| SPEC 16 | Question | Status |
|---|---|---|
| 1 | Final name and app ID | pending, blocks M3 (app ID in desktop file, gschema, metainfo). M1 uses the working name `send-secret`. |
| 3 | Optional SSH signature in age mode in v1 | pending, blocks M3. Section 4 lists it as "Later", so M1 and M2 build no signing for age. |
| 4 | Default clipboard clear time (proposed 60 s) | pending, blocks M3 |
| 5 | Web decryptor early? | pending, blocks M4 (roadmap only, not in v1 scope) |
