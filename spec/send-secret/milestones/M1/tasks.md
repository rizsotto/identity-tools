# M1 tasks

One task per branch (`m1/tNN-short-name`), one PR each, under about 400 lines.
Test first. "Needs" lists tasks that must be merged first. Tasks with no open
needs can run in parallel.

| ID | Task | Needs | Test |
|---|---|---|---|
| T01 (done) | Spike: verify F1 (`age` crate SSH, armor, multi-recipient, key types). Tick SPEC 15 item 1 with a link. Fix plan.md if wrong. | none | Spike notes in the PR. Tiny throwaway test, not merged. |
| T02 | Spike: verify F2 (gpgme crate vs gpgme 2.0) and F3 (encrypt to key file without import). Add both to SPEC 15 and tick them. **Done in core lane, commit 5bcadcd (F3 needs one `unsafe` call into `gpgme-sys`, see SPEC 15); review fixes f6aeae3.** | none | Spike notes in the PR. Open a decision record if either fails. |
| T03 (done) | Fixture script `tests/fixtures/gen.sh` and the generated keys. | none | `tests/fixtures/check.sh` (or a cargo test) asserts every expected file exists and has the right type and mode. |
| T04 (done) | `TestEnv` harness in `crates/cli/tests/common/`: temp `HOME`, `GNUPGHOME`, XDG dirs, run helpers for our binary, `gpg`, `age`. | T03 | `harness_isolates_home`: runs `gpg --list-keys` in the env and checks it sees only fixture keys. |
| T05 | `identity-core`: parse age and SSH public keys, SSH fingerprints, 1 MB limit, unsupported kinds marked. **Done in core lane, commit fcc4d96 (`identity_core::parse_public_keys`, `PublicKey::is_age_recipient`); review fixes cd93b65.** | T01, T03 | Unit tests: each fixture parses; ECDSA and `sk-` marked unsupported; 1 MB + 1 byte rejected; garbage rejected. |
| T06 | `identity-core`: gpgme context wrapper with explicit home, OpenPGP key parse and fingerprint. **Done in core lane (round 2): `Gpg`, `OpenPgpBackend` (incl. `default_secret_key`), `crypto::RecipientFile` (F3, moved to `crypto` after review). The `unsafe` encrypt call belongs to T08b, see plan.md.** | T02, T03 | `gpg_wrapper_uses_given_home`, `openpgp_fingerprint_matches_gpg` (compare with `gpg --with-colons`). |
| T07 (done) | `crypto`: `detect_format` and error types. | none | Unit tests on the first bytes of each fixture ciphertext and on junk. |
| T08a (done) | `crypto`: age backend, encrypt and decrypt, x25519 and SSH Ed25519/RSA, armor, several keys in one message (one person's devices, FR-4), streaming. SSH RSA outside 2048 to 4096 bits is skipped with a note (SPEC 15 item 1). Decrypt starts at `Detection::start` and copes with text after the END line. | T05, T07 | Round trip per key type; two keys in one message each decrypt alone; armored and binary; `ssh_rsa_outside_2048_4096_skipped_with_note` (fixtures `ssh/kim_rsa1024.pub`, `ssh/ivan_rsa8192.pub`); `decrypt_armor_in_backticks_with_bom`. |
| T08b (done) | `crypto`: OpenPGP backend, sign and encrypt, decrypt and verify, signer info. `GPGME_ENCRYPT_NO_ENCRYPT_TO`. Armored and binary output, gpg's armor unchanged (decision 0003). | T06, T07 | Round trip in temp `GNUPGHOME`; signer fingerprint reported; tampered input fails; `default_key_without_encryption_subkey_cannot_encrypt`. |
| T09 (done) | `crypto`: facade `plan`, `encrypt`, `encrypt_each` and `decrypt` as in plan.md. **Age parts round 2, OpenPGP parts round 3 (`crypto/tests/openpgp.rs`).** One message per recipient (decision 0002), format per recipient (FR-3), forced format, `self_plan` and the separate self copy (FR-12) incl. age X25519 self identity at mode 0600, no sender key in recipient messages (S-8). | T08a, T08b | `plan_one_message_per_person`, `plan_prefers_openpgp_per_person`, `plan_mixed_set_gives_both_formats`, `plan_forced_format_names_unreachable`, `plan_no_usable_key_names_person`, `encrypt_rejects_wrong_format_keys`, `encrypt_each_one_result_per_recipient`, `recipient_cannot_open_others_message`, `self_identity_created_0600`, `self_plan_format_rule`, `self_plan_falls_back_to_age_with_note` (no secret key; secret key without encryption subkey), `self_plan_forced_openpgp_without_key_errors`, `self_key_settled_before_any_output`, `self_copy_opens_with_sender_key` per format, `recipient_message_has_no_sender_key` per format, `encrypt_to_in_gpg_conf_ignored`. |
| T10 (done) | `cli`: `encrypt` and `decrypt` subcommands as in plan.md, incl. one output per recipient and the output naming. | T09 | `assert_cmd` tests: usage errors exit 2; skipped key note on stderr; signer on stderr; `several_recipients_write_base_label_files`, `output_ext_matches_format_and_armor`, `several_recipients_without_o_exit_2`, `several_recipients_with_stdin_exit_2`, `duplicate_labels_exit_2`, `unreachable_recipient_writes_nothing`, `stderr_lists_outputs`, `self_copy_written_next_to_outputs`, `self_copy_base_strips_ext`, `no_self_copy_flag`, `self_copy_needs_files_note`, `self_label_reserved_exit_2`, `self_copy_fallback_note_on_stderr`, `forced_openpgp_self_copy_without_key_writes_nothing` (exit 1, stderr suggests `--no-self-copy`), `ssh_rsa_outside_2048_4096_skipped_with_note` (stderr note for `multi.keys`), `decrypt_error_removes_output_file` (damaged input with `-o`: no file left, exit 1), `decrypt_output_file_created_0600_no_temp`, `decrypt_error_on_stdout_says_discard` (exit 1, stderr "output incomplete, discard it"), `decrypt_second_message_note`, `relative_xdg_config_home_ignored`, `encrypt_refuses_existing_output` (an existing output or self copy file: exit 1, nothing written), `self_copy_note_not_printed_when_run_fails`. |
| T11 (done) | Interop tests: ours to `gpg`/`age` and back, every key type, armored and binary, several recipients (one OpenPGP and one age recipient in one run). | T04, T10 | `interop_*` tests in `crates/cli/tests/interop.rs`, incl. `interop_per_recipient_outputs`: each output opens with `gpg` or `age` for its own recipient only, the self copy opens with the sender's key, and no recipient output lists the sender's key ID or opens with the sender's identity (`interop_no_sender_key_in_recipient_output`). Decision 0003 was accepted as "keep gpg's armor", so this is `interop_armor_is_gpgs_own` (gpg.conf `comment` kept, plain `gpg --decrypt` opens it). `gpg --verify` does not take a signed and encrypted message, so the signature is checked with `gpg --decrypt` and with `gpg --unwrap --decrypt` then `gpg --verify`. |
| T12 (done) | Security tests: no plaintext on disk (scan temp `HOME` for the marker), no plaintext in logs or errors, oversized key rejected via CLI. | T11 | `no_plaintext_on_disk`, `no_plaintext_in_stderr`, `cli_rejects_huge_key`. |
| T13 (done) | CI: make sure the devcontainer has `gpg` and `age`, run interop tests, fail if they are skipped. | T11 | CI run on the PR shows interop tests ran. `.github/ci/check-tests-ran.sh` reads the `cargo test` log and fails unless `interop.rs` and `security.rs` ran with at least their known test count and no test anywhere was ignored. `interop_tools_present` fails if `gpg` or `age` is missing. |
| T14 | Accept M1: tick every box in `spec.md` with evidence. Update SPEC.md. | all | Review only. |

## Parallel lanes

- Start at once: T01, T02, T03, T07.
- After T03: T04. After T01+T03: T05. After T02+T03: T06.
- T08a and T08b run in parallel.
- T09 is the join point. It builds one message per recipient (decision
  0002, accepted).

## Notes for the core lane (identity-core)

- SSH RSA size: identity-core marks `ssh-rsa` keys as supported
  (`SshKind::Rsa`) whatever their size. Only the age backend rejects RSA
  outside 2048 to 4096 bits (`age` crate limit, SPEC 15 item 1). Keep it
  that way, or add the size so the caller can show it. Either way, do not
  drop such keys silently. Fixtures: `ssh/kim_rsa1024.pub` (too small),
  `ssh/ivan_rsa8192.pub` (too big), both also in `ssh/multi.keys`.
- T06: the self copy needs "default secret key that can encrypt" (gpg.conf
  `default-key`, else the first secret key, with a valid encryption
  subkey). The gpgme wrapper should expose enough to answer that (decision
  0002, FR-12).
- OpenPGP fixture user IDs now end in `(test fixture)`, for example
  `Alice Example (test fixture) <alice@example.org>`.
