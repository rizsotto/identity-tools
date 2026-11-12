# M1 tasks

Each task is one branch (`m1/tNN-short-name`) and one PR, under about 400
lines. Write the named test first. "Needs" lists tasks that must be merged
first. Tasks with no open "Needs" can run in parallel.

Parallel start: T01a, T01b, T02, T10 have no dependencies.

| ID | Task | Crate | Needs | Test |
|---|---|---|---|---|
| T01a | Spike: `gpgme` crate against Fedora 45 gpgme 2.0.x. List keys in a temp `GNUPGHOME`. Record result in SPEC 15. | identity-core | none | `gpgme_lists_key_in_temp_home` |
| T01b | Verify forge read endpoints, pagination and fields (SPEC 15 fact 1, read part). Tick in SPEC with links. Add JSON fixtures with fake values. | spec, tests/mock-forges | none | none (spec and fixtures) |
| T02 | Core types: `Fingerprint`, `KeyAlgo`, `PublicKey`, errors. Parse SSH `.pub` with `ssh-key`, SHA256 fingerprint. | identity-core | none | `ssh_fingerprint_matches_ssh_keygen` |
| T03 | Private key header check (S-1): OpenSSH v1, PEM, PKCS#8, unknown. | identity-core | T02 | `detects_encrypted_and_plain_keys`, `unknown_format_is_not_unencrypted` |
| T04 | SSH dir scan: pair `.pub` with private file, file date, header check. Dir is a parameter. | identity-core | T02, T03 | `scan_temp_ssh_dir` |
| T05 | `OpenPgpBackend` trait and gpgme impl: keys, subkeys, algo, created, expiry. | identity-core | T01a, T02 | `lists_keys_and_subkeys_in_temp_gnupghome` |
| T06 | Weak key rules (SPEC 9.4) as a pure function over `PublicKey` plus header result. | identity-core | T02 | `weak_key_rules_table` |
| T07 | Location model and SQLite store with migrations. No token fields. | inventory | T02 | `migrations_apply_on_empty_db`, `location_roundtrip`, `schema_has_no_token_column` |
| T08 | `KeyList`: join scanned SSH and OpenPGP keys with location counts and warnings (FR-1 rows). | inventory | T04, T05, T06, T07 | `key_list_has_all_fr1_fields` |
| T09 | SSH config import: aliases from `Host` (with `Include`, skip wildcards), resolve with `ssh -G -F`. Store as `unverified`. | inventory | T07 | `imports_hosts_from_config_fixture` |
| T10 | Test support: sshd harness (random port, temp `HostKey`, temp `known_hosts`), temp `HOME`/`GNUPGHOME` helpers, real-home guard. Needs human OK on the proposed SPEC change in `plan.md` and on `crates/test-support`. Update SPEC 11 and 13 in the same PR. | test-support | none (human OK) | `harness_sshd_accepts_test_key`, `guard_rejects_real_home` |
| T11 | `Provider` trait, `Target`, `VerifyStatus`, `NetLog`, `TokenSource` (in-memory impl). `add`/`remove` return `NotYet`. | providers | T07 | `netlog_records_entry`, `in_memory_token_source` |
| T12 | `ssh_server` verify (FR-3, S-5): arg builder, stderr mapping, NetLog. Note: `-i` adds to the IdentityFile list from `~/.ssh/config`, so verify can pass with the old key. See decision 0002; needs a fix and a test that fails first. | providers | T10, T11 | `verify_ok_against_test_sshd`, `verify_missing_key`, `unknown_host_key_is_error` |
| T13 | Shared HTTP client: base URL, auth header, pagination helper, NetLog, token scrubbing in errors. | providers | T11 | `token_never_in_error_or_log` |
| T14 | GitHub `list` and `verify` (auth, signing, GPG keys). | providers | T01b, T13 | `github_list_against_mock`, `github_verify_by_fingerprint` |
| T15 | GitLab `list` and `verify`, self-hosted base URL. | providers | T01b, T13 | `gitlab_list_against_mock`, `gitlab_verify_by_fingerprint` |
| T16 | Forgejo `list` and `verify` (Gitea, Codeberg). | providers | T01b, T13 | `forgejo_list_against_mock`, `forgejo_verify_by_fingerprint` |
| T17 | Check runner: verify all locations of a key, write status and `last_checked` to the store. | inventory, providers | T08, T12, T14 | `check_all_updates_status` |
| T18 | `oo7` `TokenSource` impl. Verify SPEC 15 fact 6 first. Refuse cleanly when no Secret Service. | providers | T11 | `no_secret_service_gives_clear_error` (unit), manual check on GNOME |
| T19 | M1 acceptance: end-to-end test, tick every box in `spec.md` with evidence, update SPEC.md. | all | T01a to T18 | `m1_acceptance` |

## Parallel lanes (after their "Needs" merge)

- Keys: T02 then T03, T06 (parallel), then T04. T05 after T01a.
- Store: T07 then T09, T11.
- Network: T11 then T13, then T14, T15, T16 in parallel. T18 any time after T11.
- SSH: T10 then T12.
