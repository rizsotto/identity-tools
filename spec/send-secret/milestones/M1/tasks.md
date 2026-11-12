# M1 tasks

One task per branch (`m1/tNN-short-name`), one PR each, under about 400 lines.
Test first. "Needs" lists tasks that must be merged first. Tasks with no open
needs can run in parallel.

| ID | Task | Needs | Test |
|---|---|---|---|
| T01 | Spike: verify F1 (`age` crate SSH, armor, multi-recipient, key types). Tick SPEC 15 item 1 with a link. Fix plan.md if wrong. | none | Spike notes in the PR. Tiny throwaway test, not merged. |
| T02 | Spike: verify F2 (gpgme crate vs gpgme 2.0) and F3 (encrypt to key file without import). Add both to SPEC 15 and tick them. **Done in core lane, commit 5bcadcd (F3 needs one `unsafe` call into `gpgme-sys`, see SPEC 15); review fixes f6aeae3.** | none | Spike notes in the PR. Open a decision record if either fails. |
| T03 | Fixture script `tests/fixtures/gen.sh` and the generated keys. | none | `tests/fixtures/check.sh` (or a cargo test) asserts every expected file exists and has the right type and mode. |
| T04 | `TestEnv` harness in `crates/cli/tests/common/`: temp `HOME`, `GNUPGHOME`, XDG dirs, run helpers for our binary, `gpg`, `age`. | T03 | `harness_isolates_home`: runs `gpg --list-keys` in the env and checks it sees only fixture keys. |
| T05 | `identity-core`: parse age and SSH public keys, SSH fingerprints, 1 MB limit, unsupported kinds marked. **Done in core lane, commit fcc4d96 (`identity_core::parse_public_keys`, `PublicKey::is_age_recipient`); review fixes cd93b65.** | T01, T03 | Unit tests: each fixture parses; ECDSA and `sk-` marked unsupported; 1 MB + 1 byte rejected; garbage rejected. |
| T06 | `identity-core`: gpgme context wrapper with explicit home, OpenPGP key parse and fingerprint. | T02, T03 | `gpg_wrapper_uses_given_home`, `openpgp_fingerprint_matches_gpg` (compare with `gpg --with-colons`). |
| T07 | `crypto`: `detect_format` and error types. | none | Unit tests on the first bytes of each fixture ciphertext and on junk. |
| T08a | `crypto`: age backend, encrypt and decrypt, x25519 and SSH Ed25519/RSA, armor, several keys in one message (one person's devices, FR-4), streaming. | T05, T07 | Round trip per key type; two keys in one message each decrypt alone; armored and binary. |
| T08b | `crypto`: OpenPGP backend, sign and encrypt, decrypt and verify, signer info. | T06, T07 | Round trip in temp `GNUPGHOME`; signer fingerprint reported; tampered input fails. |
| T09 | `crypto`: facade `plan`, `encrypt`, `encrypt_each` and `decrypt` as in plan.md. One message per recipient (decision 0002), format per recipient (FR-3), forced format, encrypt-to-self in every message incl. age self identity at mode 0600. | T08a, T08b | `plan_one_message_per_person`, `plan_prefers_openpgp_per_person`, `plan_mixed_set_gives_both_formats`, `plan_forced_format_names_unreachable`, `plan_no_usable_key_names_person`, `encrypt_rejects_wrong_format_keys`, `encrypt_each_one_result_per_recipient`, `recipient_cannot_open_others_message`, `self_identity_created_0600`, `to_self_in_every_message` per format. |
| T10 | `cli`: `encrypt` and `decrypt` subcommands as in plan.md, incl. one output per recipient and the output naming. | T09 | `assert_cmd` tests: usage errors exit 2; skipped key note on stderr; signer on stderr; `several_recipients_write_base_label_files`, `output_ext_matches_format_and_armor`, `several_recipients_without_o_exit_2`, `several_recipients_with_stdin_exit_2`, `duplicate_labels_exit_2`, `unreachable_recipient_writes_nothing`, `stderr_lists_outputs`. |
| T11 | Interop tests: ours to `gpg`/`age` and back, every key type, armored and binary, several recipients (one OpenPGP and one age recipient in one run). | T04, T10 | `interop_*` tests in `crates/cli/tests/interop.rs`, incl. `interop_per_recipient_outputs`: each output opens with `gpg` or `age` for its own recipient only, and the sender opens all. |
| T12 | Security tests: no plaintext on disk (scan temp `HOME` for the marker), no plaintext in logs or errors, oversized key rejected via CLI. | T11 | `no_plaintext_on_disk`, `no_plaintext_in_stderr`, `cli_rejects_huge_key`. |
| T13 | CI: make sure the devcontainer has `gpg` and `age`, run interop tests, fail if they are skipped. | T11 | CI run on the PR shows interop tests ran. |
| T14 | Accept M1: tick every box in `spec.md` with evidence. Update SPEC.md. | all | Review only. |

## Parallel lanes

- Start at once: T01, T02, T03, T07.
- After T03: T04. After T01+T03: T05. After T02+T03: T06.
- T08a and T08b run in parallel.
- T09 is the join point. It builds one message per recipient (decision
  0002, accepted).
