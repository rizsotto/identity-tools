# M1: Crypto core and CLI

Slice of `spec/send-secret/SPEC.md` section 12 (M1). The spec wins if this file differs.

## Goal

A `send-secret` CLI that encrypts and decrypts with OpenPGP and age, and
interoperates with `gpg` and Go `age`. No network, no UI, no TOFU store yet.

## Acceptance criteria

- [x] `send-secret encrypt --to-key alice.pub -i msg.txt` and
  `send-secret decrypt` work for OpenPGP.
  Refs: [FR-3](../../SPEC.md#functional), [FR-7](../../SPEC.md#functional)
  Evidence: `cli.rs` `several_recipients_write_base_label_files` (`-i msg.txt`, alice's
  `.gpg` opened by our `decrypt`), `signer_on_stderr` (stdin/stdout round trip),
  `self_copy_written_next_to_outputs`; `crypto/tests/openpgp.rs`
  `openpgp_round_trip_signed_armored_and_binary`.
- [x] The same works for age with x25519 recipients.
  Refs: FR-3, FR-7
  Evidence: `cli.rs` `several_recipients_write_base_label_files` (dave),
  `decrypt_output_file_created_0600_no_temp`; `age_backend.rs` `round_trip_x25519_ed25519_rsa`.
- [x] The same works for age with SSH Ed25519 recipients.
  Refs: FR-3, FR-4, FR-7
  Evidence: `cli.rs` `several_recipients_write_base_label_files` (erin_ed25519);
  `security.rs` `ssh_passphrase_never_echoed` (protected key, passphrase on a tty);
  `age_backend.rs` `round_trip_x25519_ed25519_rsa`.
- [x] The same works for age with SSH RSA recipients.
  Refs: FR-3, FR-4, FR-7
  Evidence: `cli.rs` `ssh_rsa_outside_2048_4096_skipped_with_note` (our encrypt to
  `multi.keys`, our decrypt with `frank_rsa` alone); `age_backend.rs`
  `round_trip_x25519_ed25519_rsa`.
- [x] Unsupported SSH key types (ECDSA, `sk-` keys) and SSH RSA keys
  outside 2048 to 4096 bits (the `age` crate limit) are skipped with a
  note. Refs: FR-4
  Evidence: `cli.rs` `ssh_rsa_outside_2048_4096_skipped_with_note` (stderr names RSA 1024,
  RSA 8192, ECDSA, `sk-ssh-ed25519`; the good keys still open it); `age_backend.rs`
  `ssh_rsa_outside_2048_4096_skipped_with_note`, `ecdsa_and_sk_keys_skipped_with_note`.
- [x] Interop: files from our CLI decrypt with `gpg`, and `gpg` output
  decrypts with our CLI.
  Evidence: `interop.rs` `interop_openpgp_ours_to_gpg` (alice Ed25519/Cv25519 and bob-rsa,
  signed, also `--unwrap` + `gpg --verify`), `interop_openpgp_unsigned_ours_to_gpg`,
  `interop_openpgp_gpg_to_ours` (signed and unsigned).
- [x] Interop: files from our CLI decrypt with Go `age`, and Go `age` output
  decrypts with our CLI. For each of x25519, SSH Ed25519, SSH RSA.
  Evidence: `interop.rs` `interop_age_ours_to_age`, `interop_age_age_to_ours` (x25519,
  SSH Ed25519, SSH RSA 2048, 3072, 4096), `interop_age_to_ours_default_ssh_identities`.
- [x] Both armored text and binary output interoperate.
  Evidence: every `interop_*_ours_to_*` and `*_to_ours` test above loops over armored and
  binary and checks the first bytes; `interop_per_recipient_outputs` (both).
- [x] Several `--to-key` files give one message per recipient, always,
  even when all share a format. Each recipient can decrypt their own
  message and cannot decrypt the others'.
  Refs: UC-8, [FR-11](../../SPEC.md#functional),
  decision [0002](../../decisions/0002-mixed-recipients.md)
  Evidence: `interop.rs` `interop_no_sender_key_in_recipient_output` (two OpenPGP
  recipients give two files, each lists only its own key ID; two age recipients give two
  files with one stanza each), `interop_per_recipient_outputs` (other keys fail); `cli.rs`
  `several_recipients_write_base_label_files` (dave's key does not open erin's file);
  `facade.rs` `recipient_cannot_open_others_message`, `plan.rs` `plan_one_message_per_person`.
- [x] Each message uses that recipient's format: OpenPGP if their key file
  has an OpenPGP key, else age. A mix of OpenPGP and age recipients works
  and gives OpenPGP and age outputs. `--format` forces one format; a
  recipient with no key in it is an error that names them. Refs: FR-3, FR-11
  Evidence: `plan.rs` `plan_prefers_openpgp_per_person`, `plan_mixed_set_gives_both_formats`,
  `plan_forced_format_names_unreachable` (forced age picks alice's SSH key; bob named);
  `cli.rs` `several_recipients_write_base_label_files` (mixed set gives `.gpg` and `.age`),
  `unreachable_recipient_writes_nothing` ("erin_ed25519 has no usable OpenPGP key", exit 1);
  `crypto/tests/openpgp.rs` `encrypt_each_mixed_openpgp_and_age`.
- [x] Output naming: with one recipient, `-o OUT` is the exact file, or
  stdout if `-o` is not given. With several recipients, `-o BASE` is
  required and writes `BASE.<label>.asc` (armored OpenPGP),
  `BASE.<label>.gpg` (binary OpenPGP) or `BASE.<label>.age`. The label is
  the key file name without its extension. Stdout or stdin with several
  recipients is a usage error (exit 2). Stderr lists each output and who
  it is for. Refs: FR-11
  Evidence: `cli.rs` `several_recipients_write_base_label_files`,
  `output_ext_matches_format_and_armor` (`.asc`/`.gpg`/`.age`, labels from file names),
  `several_recipients_without_o_exit_2`, `several_recipients_with_stdin_exit_2`,
  `stderr_lists_outputs`, `self_copy_needs_files_note` (one recipient, no `-o`: stdout);
  `interop.rs` tests write the exact `-o OUT` file.
- [x] A key file with several keys of the chosen format (for example an
  `authorized_keys` list) gives one message that each of those keys can
  open. Refs: FR-4
  Evidence: `cli.rs` `ssh_rsa_outside_2048_4096_skipped_with_note` (`multi.keys`, erin and
  frank each open the one message); `age_backend.rs`
  `multi_keys_file_uses_supported_keys_and_skips_the_rest`; `crypto/tests/openpgp.rs`
  `key_file_with_two_keys_gives_one_message_both_open`.
- [x] No recipient's message holds the sender's key: an OpenPGP message
  lists only that recipient's key IDs (also when gpg.conf has
  `encrypt-to`), and an age message has no stanza for the sender.
  Refs: [S-8](../../SPEC.md#10-security-rules-must), decision 0002
  (encrypt-to-self sub-decision)
  Evidence: `interop.rs` `interop_no_sender_key_in_recipient_output` (gpg.conf
  `encrypt-to` set; `gpg --list-packets` shows only the recipient's key IDs; age files have
  no stanza the sender's identity opens); `crypto/tests/openpgp.rs`
  `encrypt_to_in_gpg_conf_ignored`, `recipient_message_has_no_sender_key`,
  `gpg_conf_options_that_add_keys_are_refused`; `facade.rs` `recipient_message_has_no_sender_key`.
- [x] Armored OpenPGP output is gpg's own standard armor, unchanged, and
  plain `gpg --decrypt` opens it. Refs: S-8,
  decision [0003](../../decisions/0003-openpgp-armor-headers.md)
  Evidence: `interop.rs` `interop_armor_is_gpgs_own` (gpg.conf `comment` and
  `emit-version` lines kept, plain `gpg --decrypt` and `--dearmor` open it).
- [x] Self copy: a separate message encrypted only to the sender, on by
  default, `--no-self-copy` skips it. OpenPGP uses the user's default
  secret key. age uses the user's own native X25519 identity (created on
  first use, mode 0600), never an SSH key. Format: `--format` if given,
  else OpenPGP if the user's default secret key can encrypt, else age with
  a note on stderr. The self key is settled before any output is written:
  a forced format with no usable self key exits 1 and writes nothing.
  Written to
  `BASE.self.<ext>` next to the per-recipient files. With one recipient,
  BASE is OUT without a trailing `.asc`, `.gpg` or `.age`. The self copy
  needs `-i FILE` and `-o`; without them it is not written and stderr says
  why (exit 0). A key file labeled `self` is a usage error (exit 2).
  Refs: [FR-12](../../SPEC.md#functional), section 9, decision 0002
  Evidence: `cli.rs` `self_copy_written_next_to_outputs`, `no_self_copy_flag`,
  `self_copy_fallback_note_on_stderr` (age, note, identity mode 0600),
  `forced_openpgp_self_copy_without_key_writes_nothing`, `self_copy_base_strips_ext`,
  `self_copy_needs_files_note`, `self_label_reserved_exit_2`; `crypto/tests/openpgp.rs`
  `self_copy_uses_default_key_not_another_secret_key` (added in T14),
  `self_copy_opens_with_sender_key`; `plan.rs` `self_plan_format_rule`,
  `self_plan_falls_back_to_age_with_note`; `facade.rs` `self_key_settled_before_any_output`;
  `self_identity.rs` `self_identity_created_0600`, `ssh_key_or_junk_is_refused`;
  `interop.rs` `interop_self_copy_age_opens_with_age` (one X25519 stanza, no SSH stanza),
  `interop_per_recipient_outputs` (OpenPGP self copy opens with the sender's key only).
- [x] OpenPGP output is signed inside the encryption (sign and encrypt in
  one operation), and decrypt reports the verified signer.
  Refs: UC-7, FR-7, section 9 ("Signing")
  Evidence: `interop.rs` `interop_openpgp_ours_to_gpg` (`gpg --unwrap --decrypt` keeps the
  signed message that was inside the encryption, `gpg --verify` gives VALIDSIG of the sender),
  `interop_openpgp_gpg_to_ours` and `cli.rs` `signer_on_stderr` ("signed by <fpr> (good
  signature"); `crypto/tests/openpgp.rs` `openpgp_round_trip_signed_armored_and_binary`.
- [x] Decrypt detects the format (OpenPGP armor, age armor, binary), also
  when the armor follows a UTF-8 BOM, blank lines, triple backticks or a
  header line. Refs: FR-7
  Evidence: `detect.rs` `armor_after_utf8_bom`, `armor_after_leading_blank_lines`,
  `armor_inside_triple_backticks`, `armor_after_header_line`, `detects_*_fixture`;
  `facade.rs` `decrypt_armor_in_backticks_with_bom`, `decrypt_after_header_line_and_blank_lines`,
  `decrypt_binary_fixture`; `crypto/tests/openpgp.rs`
  `decrypts_gpg_fixture_in_backticks_and_notes_second_message`.
- [ ] No plaintext in temp files. Files stream from source to output. Plaintext
  buffers are zeroed. Refs: [S-4](../../SPEC.md#10-security-rules-must),
  [S-5](../../SPEC.md#10-security-rules-must), FR-8, NFR-3
  Not ticked. No temp files: `security.rs` `no_plaintext_on_disk` (strace of every
  created file, marker scan of HOME, temp dir, `/var/tmp`, `/dev/shm`). Streaming:
  `age_backend.rs` `large_input_streams`, `encrypt_each` opens the input once per message.
  Zeroing has no test and can not be asserted by one; review shows our own buffers are
  `Zeroizing` (`age_backend.rs` `copy_plaintext`, `cli` `read_secret`, the passphrase).
  Open: the `age` crate's `StreamWriter` keeps up to 64 KiB of plaintext unzeroed (SPEC 16
  question 7, needs the human), and OpenPGP plaintext passes through gpgme's and gpg's own
  buffers, which we can not zero (added to SPEC 16 question 7).
- [x] Keys over 1 MB are rejected. Refs: [S-7](../../SPEC.md#10-security-rules-must)
  Evidence: `security.rs` `cli_rejects_huge_key` (age line, armored OpenPGP and junk at
  1,000,001 bytes exit 1 and write nothing; 1,000,000 works); `plan.rs`
  `openpgp_cert_over_1mb_is_refused`; identity-core `input_over_one_mb_is_rejected`.
- [x] Nothing logs plaintext, ciphertext or passphrases. Refs: S-5
  Evidence: no logging crate in `crypto`, `cli` or `identity-core`, so stderr is the only
  log. `security.rs` `no_plaintext_in_stderr` (more than 20 runs incl. failures and junk holding the
  marker), `no_ciphertext_in_stderr` and `ssh_passphrase_never_echoed` (both added in T14).
  OpenPGP passphrases go to gpg-agent's pinentry and never reach our binary.
- [x] All tests use a temp `GNUPGHOME`, temp `HOME` and generated fixture keys.
  Refs: SPEC section 13, section 14
  Evidence: `harness.rs` `harness_isolates_home`, `harness_passes_only_its_own_env`;
  `fixtures.rs` (all keys from `tests/fixtures/gen.sh`). T14 fixed two helpers that ran
  `gpg --show-keys` in the real home. Check: the full `cargo test --workspace` with `HOME`
  set to an empty dir (and `GNUPGHOME` unset) leaves that dir empty (2026-11-12).
- [x] `cargo fmt`, `cargo clippy -D warnings` and all tests (including
  interop) pass in CI.
  Evidence (2026-11-12, devcontainer, CI sequence): selftest ok, `cargo fmt --check` ok,
  `cargo clippy --locked --workspace --all-targets -D warnings` ok, `cargo test --locked
  --workspace`: 306 passed, 0 failed, 0 ignored in 41 binaries; `check-tests-ran.sh`:
  interop.rs 11, security.rs 8.

## Acceptance (T14, 2026-11-12)

Not accepted yet. 21 of 22 boxes ticked. The zeroing part of the S-4/S-5
box waits for the human's answer to SPEC 16 question 7. No box needs a
real desktop session.

## Out of scope for M1

Key lookup (M2), TOFU (M2), GTK app (M3), clipboard (M3), Files integration
(M4), the "how to open" header text (FR-6, M3).
