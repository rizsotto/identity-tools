# M1: Read-only inventory

Source: [SPEC 12, M1](../../SPEC.md#m1-read-only-inventory). Nothing in M1
changes a key, a server or a forge account.

## Requirements in scope

- [FR-1](../../SPEC.md#functional) key list fields
- [FR-2](../../SPEC.md#functional) location model
- [FR-3](../../SPEC.md#functional) SSH server check
- [FR-4](../../SPEC.md#functional) forge check (list and compare fingerprints)
- [NFR-1](../../SPEC.md#non-functional) private keys stay in GnuPG and `~/.ssh`
- [NFR-2](../../SPEC.md#non-functional) network calls are logged per workflow
- [NFR-4](../../SPEC.md#non-functional) viewing works offline
- [S-1](../../SPEC.md#10-security-rules-must) header-only check of private key files
- [S-4](../../SPEC.md#10-security-rules-must) tokens never in logs or errors
- [S-5](../../SPEC.md#10-security-rules-must) BatchMode, no silent host key accept
- [SPEC 9.4](../../SPEC.md#94-weak-key-rules-v1) weak key rules
- Use cases UC-1, UC-2 (check part), UC-7

Out of scope for M1: any add or remove, rotation, journal, reminders, UI,
import/export (FR-12), VKS and WKD providers.

## Acceptance criteria

Tick each box with evidence: a test name or command output.

### Keys

- [x] Lists SSH keys from an SSH dir (temp `HOME` in tests) with all FR-1
      fields: comment, type, bits or curve, fingerprint, created, expiry,
      location count, warnings. ([FR-1](../../SPEC.md#functional))
      Evidence: `inventory/tests/key_list.rs` `key_list_has_all_fr1_fields`,
      `providers/tests/m1_acceptance.rs` `m1_acceptance` (every FR-1 field of
      two SSH rows, file date as "created", counts 7 and 3),
      `identity-core/tests/ssh_scan.rs` `scan_temp_ssh_dir`.
- [x] Lists OpenPGP keys from GnuPG (temp `GNUPGHOME` in tests) with all FR-1
      fields, including subkeys and their expiry. ([FR-1](../../SPEC.md#functional))
      Evidence: `key_list_has_all_fr1_fields` (Alice with Cv25519 subkey and
      both expiries, Bob without expiry, Carol without secret key not listed),
      `m1_acceptance`, `identity-core/tests/openpgp.rs`
      `lists_keys_and_subkeys_in_temp_gnupghome`.
- [x] Weak key warnings follow SPEC 9.4: RSA < 3072 warning, DSA error, ECDSA
      nistp* info, unencrypted SSH private key warning, OpenPGP key with no
      expiry info. ([9.4](../../SPEC.md#94-weak-key-rules-v1))
      Evidence: `identity-core` `weak::tests::weak_key_rules_table` (RSA
      1024/2048 warning, DSA error, ECDSA nistp256/521 and sk-ecdsa info,
      unencrypted warning, OpenPGP no expiry info); end to end in
      `key_list_has_all_fr1_fields` (also a weak subkey) and `m1_acceptance`.
- [x] The unencrypted check reads only the private key file header. No private
      key bytes are parsed or kept. ([S-1](../../SPEC.md#10-security-rules-must),
      [NFR-1](../../SPEC.md#non-functional))
      Evidence: `private_header::tests::stops_reading_after_the_header` (reads
      at most the header bytes), `identity-core/tests/private_header.rs`
      `detects_encrypted_and_plain_keys`, `unknown_format_is_not_unencrypted`.
      The SSH check passes the key to `ssh` by a symlink and never opens it
      (`ssh_server::tests::workdir_is_private_and_links_the_key`).
- [x] Listing keys needs no network. ([NFR-4](../../SPEC.md#non-functional))
      Evidence (static, no runtime test): `cargo tree -p inventory -e normal`
      has no HTTP, socket or async crate (only `identity-core`, `gpgme`,
      `rusqlite`, `ssh-key` and their deps; run 2026-11-12); GnuPG listing uses
      gpgme's default local keylist mode (`ctx.keys()`, `ctx.secret_keys()`, no
      extern mode); `KeyList::load` only reads files and GnuPG. `m1_acceptance`
      lists keys before any check runs.

### Locations

- [x] Locations are stored in SQLite with kind, target, key, status
      (`verified`, `unverified`, `missing`, `error`) and `last_checked`.
      ([FR-2](../../SPEC.md#functional))
      Evidence: `store::tests::migrations_apply_on_empty_db`,
      `location_roundtrip`, `database_is_private`; `m1_acceptance` reopens the
      database file and reads every status and `last_checked`.
- [x] No token column or token value in the database.
      ([S-4](../../SPEC.md#10-security-rules-must))
      Evidence: `store::tests::schema_has_no_token_column`,
      `schema_has_no_key_material`; `m1_acceptance` scans the database file
      bytes for the token after all checks.
- [x] Imports hosts from an SSH config file (with `Include`, skipping wildcard
      patterns) as `unverified` SSH server locations.
      ([UC-2](../../SPEC.md#2-users-and-use-cases))
      Evidence: `ssh_config::tests::imports_hosts_from_config_fixture`,
      `host_aliases_follow_include_and_skip_wildcards`,
      `match_exec_is_refused_by_default`; `m1_acceptance` (absolute `Include`,
      `Host *.example.invalid !skip` skipped, host without a key reported, three
      `unverified` locations).

### Checks

- [x] SSH server check runs `ssh -o BatchMode=yes -o IdentitiesOnly=yes -i <key>
      -o ConnectTimeout=10 <host> true` against the test sshd. Exit 0 gives
      `verified`. A key that is not installed gives `missing`.
      ([FR-3](../../SPEC.md#functional))
      Evidence: `providers/tests/ssh_server.rs` `verify_ok_against_test_sshd`,
      `verify_missing_key`; `ssh_server::tests::verify_args_are_fixed_and_safe`;
      `m1_acceptance` (alpha `verified`, beta `missing`). Note: by the T12
      decision the command is `ssh -v -E <log> -F <temp config> ... <host> true`
      with the key pinned in the temp config instead of `-i`, as SPEC FR-3 now
      says; `BatchMode`, `IdentitiesOnly`, `ConnectTimeout=10` are kept.
- [x] A key that is not installed gives `missing` even when the ssh config
      holds another key that logs in. Exit 0 alone is not enough. (Decision
      [0002](../../decisions/0002-ssh-test-servers.md), side finding; fix
      chosen in T12: the `ssh -v` fingerprint check, see `plan.md`.) ([S-3](../../SPEC.md#10-security-rules-must))
      Evidence: `verify_missing_key_with_second_valid_key_in_config`, plus the
      T12 attack tests (`proxyjump_success_on_jump_host_is_not_verified`,
      `certificate_login_is_not_verified`,
      `mismatched_pub_with_pem_key_in_config_is_not_verified`,
      `two_hop_proxyjump_is_not_verified`).
- [x] An unknown host key gives `error` with a clear reason. It is never
      accepted. ([S-5](../../SPEC.md#10-security-rules-must))
      Evidence: `unknown_host_key_is_error`, `changed_host_key_is_error`,
      `check_host_ip_does_not_write_known_hosts`; `m1_acceptance` (gamma:
      `error` "The host key is not known...", known_hosts unchanged, no new
      known_hosts file).
- [x] GitHub provider `list` returns SSH auth keys, SSH signing keys and GPG
      keys from the mock forge. ([FR-4](../../SPEC.md#functional))
      Evidence: `providers/tests/github.rs` `github_list_against_mock` (auth
      keys over 2 pages, signing keys, GPG key fingerprint from `raw_key`).
- [x] GitLab provider `list` does the same, with a configurable base URL for
      self-hosted instances. ([FR-4](../../SPEC.md#functional))
      Evidence: `gitlab_list_against_mock` (base URL `<mock>/gitlab/`,
      `usage_type` auth/signing/both, `x-next-page`),
      `gitlab_refuses_plain_http_and_ssh_targets`.
- [x] Forgejo provider `list` does the same (Gitea and Codeberg use it too).
      ([FR-4](../../SPEC.md#functional))
      Evidence: `forgejo_list_against_mock` (2 pages by `link`, GPG primary key
      packet), `forgejo_ignores_server_fingerprint_field`.
- [x] Forge `verify` compares fingerprints from `list` with the local key.
      ([FR-4](../../SPEC.md#functional))
      Evidence: `github_verify_by_fingerprint`, `gitlab_verify_by_fingerprint`,
      `forgejo_verify_by_fingerprint`, `check.rs` `check_all_updates_status`;
      `m1_acceptance` (verified and missing per purpose on all three forges,
      with a wrong Forgejo `fingerprint` field).
- [x] Every network call (ssh and HTTP) goes into a per-workflow log the user
      can read. ([NFR-2](../../SPEC.md#non-functional))
      Evidence: `netlog::tests::netlog_records_entry`, the `*_list_against_mock`
      tests (one entry per request), `m1_acceptance` (one entry per ssh check,
      and per forge the logged entries equal the requests wiremock received).
- [x] A test proves tokens do not appear in logs or error text.
      ([S-4](../../SPEC.md#10-security-rules-must))
      Evidence: `http_client.rs` `token_never_in_error_or_log`,
      `http::tests::scrubs_plain_and_encoded_token`,
      `github_errors_hold_no_token`, the `*_token_owner_must_be_target_account`
      tests, `token::tests::token_debug_hides_value`; `m1_acceptance` (a 401
      that echoes the token: not in the status, the log or the database).

### Process

- [ ] SPEC 15 facts that M1 uses are ticked in SPEC.md with links (see
      `plan.md`).
      Gap: the "Token owner" note of fact 1 is not fully checked. Docs checked
      2026-11-12 (see SPEC 15): GitLab `read_user` grants `GET /user`; GitHub
      classic tokens without `user` scopes get the public profile with `login`
      (implied by the docs, not stated for the read key scopes); GitHub
      fine-grained tokens and Forgejo `read:user` for `GET /user` are not stated
      in the docs. Also not confirmed: that Forgejo `/user/keys` and
      `/user/gpg_keys` really send `link` (the provider stops after page 1
      without it). The oo7 fact is ticked, but a real GNOME Keyring session is
      not checked (T18 manual check). Other M1 facts (gpgme, `ssh -G`, OpenSSH
      messages, fact 1 read part) are ticked with sources.
- [x] No test touches the real `~/.ssh`, `~/.gnupg`, a real server or a real
      forge. ([SPEC 14](../../SPEC.md#14-instructions-for-agents))
      Evidence: `guard::tests::guard_rejects_real_home`; `TempHome` and
      `TempGnupgHome` refuse the real home; every `SshServer` in tests gets
      `with_config`, `with_known_hosts` and `with_home`; no test calls
      `Gpg::user_default`, `OpenPgpReader::user_default` or reads `$HOME`; forge
      tests use wiremock (GitHub with `with_api_url`), and the few non-mock URLs
      are refused before any request
      (`gitlab_refuses_plain_http_and_ssh_targets`,
      `github_errors_hold_no_token`); the D-Bus test uses a private peer.
- [ ] `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`
      and `cargo test --workspace` pass in the devcontainer and in CI.
      Devcontainer: passed 2026-11-12 on 2aa1d1d (full CI sequence: selftest,
      fmt, clippy `--locked -D warnings`, `cargo test --locked --workspace`, 304
      tests, 0 failed, 0 ignored, `check-tests-ran.sh` ok). Gap: GitHub CI has
      not run on this branch (not pushed); tick when the PR run is green.
- [x] The sshd tests run in GitHub CI. No test is `#[ignore]` or skipped.
      ([SPEC 13](../../SPEC.md#13-test-plan))
      Evidence: T10 harness run 43155272129 in GitHub CI; CI runs `cargo test
      --locked --workspace`, so `ssh_server.rs`, `check.rs` and `m1_acceptance`
      run there too; no `#[ignore]` in the repo (grep), and
      `.github/ci/check-tests-ran.sh` fails CI on any ignored test.
