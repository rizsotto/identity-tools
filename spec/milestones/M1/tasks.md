# M1 tasks

One task per branch (`m1/tNN-short-name`), one PR each, under about 400 lines.
Test first. "Needs" lists tasks that must be merged first. Tasks with no open
needs can run in parallel.

| ID | Task | Needs | Test |
|---|---|---|---|
| T01 | Spike: verify F1 (`age` crate SSH, armor, multi-recipient, key types). Tick SPEC 15 item 1 with a link. Fix plan.md if wrong. | none | Spike notes in the PR. Tiny throwaway test, not merged. |
| T02 | Spike: verify F2 (gpgme crate vs gpgme 2.0) and F3 (encrypt to key file without import). Add both to SPEC 15 and tick them. | none | Spike notes in the PR. Open a decision record if either fails. |
| T03 | Fixture script `tests/fixtures/gen.sh` and the generated keys. | none | `tests/fixtures/check.sh` (or a cargo test) asserts every expected file exists and has the right type and mode. |
| T04 | `TestEnv` harness in `crates/cli/tests/common/`: temp `HOME`, `GNUPGHOME`, XDG dirs, run helpers for our binary, `gpg`, `age`. | T03 | `harness_isolates_home`: runs `gpg --list-keys` in the env and checks it sees only fixture keys. |
| T05 | `identity-core`: parse age and SSH public keys, SSH fingerprints, 1 MB limit, unsupported kinds marked. | T01, T03 | Unit tests: each fixture parses; ECDSA and `sk-` marked unsupported; 1 MB + 1 byte rejected; garbage rejected. |
| T06 | `identity-core`: gpgme context wrapper with explicit home, OpenPGP key parse and fingerprint. | T02, T03 | `gpg_wrapper_uses_given_home`, `openpgp_fingerprint_matches_gpg` (compare with `gpg --with-colons`). |
| T07 | `crypto`: `detect_format` and error types. | none | Unit tests on the first bytes of each fixture ciphertext and on junk. |
| T08a | `crypto`: age backend, encrypt and decrypt, x25519 and SSH Ed25519/RSA, armor, multiple recipients, streaming. | T05, T07 | Round trip per key type; two recipients each decrypt alone; armored and binary. |
| T08b | `crypto`: OpenPGP backend, sign and encrypt, decrypt and verify, signer info. | T06, T07 | Round trip in temp `GNUPGHOME`; signer fingerprint reported; tampered input fails. |
| T09 | `crypto`: facade `encrypt`/`decrypt`, format choice, mixed recipients error (interim, decision 0002), encrypt-to-self incl. age self identity at mode 0600. | T08a, T08b | `mixed_recipients_rejected`, `self_identity_created_0600`, `to_self_can_decrypt` per format. |
| T10 | `cli`: `encrypt` and `decrypt` subcommands as in plan.md. | T09 | `assert_cmd` tests: usage errors exit 2; skipped key note on stderr; signer on stderr. |
| T11 | Interop tests: ours to `gpg`/`age` and back, every key type, armored and binary, multiple recipients. | T04, T10 | `interop_*` tests in `crates/cli/tests/interop.rs`. |
| T12 | Security tests: no plaintext on disk (scan temp `HOME` for the marker), no plaintext in logs or errors, oversized key rejected via CLI. | T11 | `no_plaintext_on_disk`, `no_plaintext_in_stderr`, `cli_rejects_huge_key`. |
| T13 | CI: make sure the devcontainer has `gpg` and `age`, run interop tests, fail if they are skipped. | T11 | CI run on the PR shows interop tests ran. |
| T14 | Accept M1: tick every box in `spec.md` with evidence. Update SPEC.md. | all | Review only. |

## Parallel lanes

- Start at once: T01, T02, T03, T07.
- After T03: T04. After T01+T03: T05. After T02+T03: T06.
- T08a and T08b run in parallel.
- T09 is the join point. Its mixed-recipient part follows decision 0002 once
  accepted. The interim error is enough to continue.
