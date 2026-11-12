# M1 tasks

Each task is one branch (`m1/tNN-short-name`) and one PR, under about 400
lines. Write the named test first. "Needs" lists tasks that must be merged
first. Tasks with no open "Needs" can run in parallel.

Parallel start: T01a, T01b, T02, T10 have no dependencies. Start T10 early:
every SSH task waits for its harness to pass in GitHub CI.

| ID | Task | Crate | Needs | Test |
|---|---|---|---|---|
| T01a | Spike: `gpgme` crate against Fedora 45 gpgme 2.0.x. List keys in a temp `GNUPGHOME`. Record result in SPEC 15. **Done in core lane, commit 5bcadcd.** | identity-core | none | `gpgme_lists_key_in_temp_home` |
| T01b | **Done.** Verify forge read endpoints, pagination and fields (SPEC 15 fact 1, read part). Tick in SPEC with links. Add JSON fixtures with fake values. | spec, tests/mock-forges | none | none (spec and fixtures) |
| T02 | Core types: `Fingerprint`, `KeyAlgo`, `PublicKey`, errors. Parse SSH `.pub` with `ssh-key`, SHA256 fingerprint. **Done in core lane, commit fcc4d96; review fixes cd93b65.** | identity-core | none | `ssh_fingerprint_matches_ssh_keygen` |
| T03 | Private key header check (S-1): OpenSSH v1, PEM, PKCS#8, unknown. **Done in core lane, commit 0e72904; review fixes in commit "M1 T03 review: cap bytes read".** | identity-core | T02 | `detects_encrypted_and_plain_keys`, `unknown_format_is_not_unencrypted` |
| T04 | SSH dir scan: pair `.pub` with private file, file date, header check. Dir is a parameter. **Done in core lane (round 2), `identity_core::scan_ssh_dir`.** | identity-core | T02, T03 | `scan_temp_ssh_dir` |
| T05 | `OpenPgpBackend` trait and gpgme impl: keys, subkeys, algo, created, expiry. **Done in core lane (round 2), `identity_core::{Gpg, OpenPgpBackend}`.** | identity-core | T01a, T02 | `lists_keys_and_subkeys_in_temp_gnupghome` |
| T06 | Weak key rules (SPEC 9.4) as a pure function over `PublicKey` plus header result. **Done in core lane, commit e068440; review fixes 26b5c60.** | identity-core | T02 | `weak_key_rules_table` |
| T07 | **Done, key-steward lane round 2, commit a732614.** Location model and SQLite store with migrations. No token fields. | inventory | T02 | `migrations_apply_on_empty_db`, `location_roundtrip`, `schema_has_no_token_column` |
| T08 | **Done, key-steward lane round 3, commit 03099c9; review fix 83e239e.** `KeyList`: join scanned SSH and OpenPGP keys with location counts and warnings (FR-1 rows). | inventory | T04, T05, T06, T07 | `key_list_has_all_fr1_fields` |
| T09 | **Done, commit ff58d05.** SSH config import: aliases from `Host` (with `Include`, skip wildcards), resolve with `ssh -G -F`. Store as `unverified`. | inventory | T07 | `imports_hosts_from_config_fixture` |
| T10 | **Done.** `key-steward/crates/test-support`; 12 harness tests pass in the devcontainer and in GitHub CI, run 43155272129 (https://github.com/rizsotto/identity-tools/actions/runs/43155272129), commit c7f64d4. | test-support | none | `harness_sshd_accepts_test_key`, `guard_rejects_real_home`, the other harness tests in 0002 step 8 |
| T11 | **Done, commit 2939d93.** `Provider` trait, `Target` (in `inventory`, re-exported), `VerifyStatus`, `NetLog`, `TokenSource` (in-memory impl). `add`/`remove` return `NotYet`. | providers | T07 | `netlog_records_entry`, `in_memory_token_source` |
| T12 | **Done, commit d560854.** `ssh_server` verify (FR-3, S-5): arg builder, stderr mapping, NetLog. Open item decided: the `ssh -v` fingerprint check (`plan.md`, "Open item for T12"). | providers | T10 (harness green in CI), T11 | `verify_ok_against_test_sshd`, `verify_missing_key`, `verify_missing_key_with_second_valid_key_in_config`, `unknown_host_key_is_error` |
| T13 | **Done, commit 329c003.** Shared HTTP client: base URL, auth header, pagination helper, NetLog, token scrubbing in errors. | providers | T11 | `token_never_in_error_or_log` |
| T14 | **Done, commit 3f84c43; review fixes 5ee1ad7, 4905d98.** GitHub `list` and `verify` (auth, signing, GPG keys). | providers | T01b, T13 | `github_list_against_mock`, `github_verify_by_fingerprint` |
| T15 | **Done, commit bf3882d; review fix 4905d98.** GitLab `list` and `verify`, self-hosted base URL. | providers | T01b, T13 | `gitlab_list_against_mock`, `gitlab_verify_by_fingerprint` |
| T16 | **Done, commit eb00577; review fixes 5ee1ad7, 4905d98.** Forgejo `list` and `verify` (Gitea, Codeberg). | providers | T01b, T13 | `forgejo_list_against_mock`, `forgejo_verify_by_fingerprint` |
| T17 | **Done, commit 6af4114, `providers::CheckRunner`.** Check runner: verify all locations of a key, write status and `last_checked` to the store. Lives in `providers` (or `rotation`): `providers` depends on `inventory`, so it cannot go in `inventory`. | providers | T08, T12, T14 | `check_all_updates_status` |
| T18 | **Done, commit 2ba03f6, `providers::SecretServiceTokens`; manual GNOME check still open.** `oo7` `TokenSource` impl. Verify SPEC 15 fact 6 first. Refuse cleanly when no Secret Service. | providers | T11 | `no_secret_service_gives_clear_error` (unit), manual check on GNOME |
| T19 | **Test done, commit 2aa1d1d; acceptance check: 19 of 21 boxes ticked, M1 not accepted yet (gaps in `spec.md`: GitHub CI run on the PR, the `GET /user` scope and Forgejo `link` facts).** M1 acceptance: end-to-end test, tick every box in `spec.md` with evidence, update SPEC.md. | all | T01a to T18 | `m1_acceptance` |

## Parallel lanes (after their "Needs" merge)

- Keys: T02 then T03, T06 (parallel), then T04. T05 after T01a.
- Store: T07 then T09, T11.
- Network: T11 then T13, then T14, T15, T16 in parallel. T18 any time after T11.
- SSH: T10 (green in GitHub CI) then T12, then T17. M2 rotation tests also
  need T10.

## Notes for M2

- Rotation must refuse when the old and new key fingerprints are equal.
  Otherwise "the new key is verified" would be true of the old key, and
  removing "the old key" would remove the only key (S-3). (Third review of
  T12.)
