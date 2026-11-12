# M2 tasks

Each task is one branch (`m2/tNN-short-name`) and one PR, under about 400
changed lines. Write the named test first. "Needs" lists tasks that must be
merged first. Design and reasons: `plan.md`.

Can start now (no open "Needs"): T01, T02, T03a, T03b, T04, T09, T10, T14.

| ID | Task | Crate | Needs | Test |
|---|---|---|---|---|
| T01 | `authorized_keys` parser and editor, pure: raw lines with endings, options with quotes, fingerprint via `identity-core`, `cert-authority` skipped, `add_like`, `remove(keep)`, 1 MB cap. Fixture files in `key-steward/tests/authorized-keys/`. | providers | none | `fixtures_add_like`, `fixtures_remove_keeps_other_bytes`, `remove_refuses_without_new_key`, `add_refuses_without_old_key`, `add_is_idempotent` |
| T02 | Remote scripts `authorized_keys_read.sh` and `authorized_keys_apply.sh` (replace the stub), the bootstrap command builder, POSIX `cksum` in Rust. Add `dash busybox` to the Containerfile. Scripts run locally (no ssh) under bash, dash and busybox. | providers, remote-scripts, .devcontainer | none | `scripts_under_three_shells`, `apply_refuses_changed_file`, `apply_refuses_symlink`, `apply_makes_backup_and_0600`, `bootstrap_has_no_quotes`, `cksum_matches_posix_tool` |
| T03a | test-support: `Sshd::start_named(base, alias)` and `ClientConfig::new(&[&Sshd])` (one client config and `known_hosts` for several servers). | test-support | none | `two_servers_in_one_config`, `client_config_has_no_real_home_paths` |
| T03b | test-support: `FakeForge` (GitHub, GitLab, Forgejo flavours) on wiremock with shared state: `GET /user`, paged list, `POST`, `DELETE`, documented codes, request record, faults (lose response, 500, 403). Seeds from `tests/mock-forges/`. | test-support | none | `fake_forge_add_list_delete` (per flavour), `fake_forge_lost_response_applies` |
| T04 | Provider trait change: `AddOpts { purpose, title, like }`, `RemoveOpts { purpose, keep }`, `remove(target, fpr, opts)`. Update all stubs and SPEC 7.1. `HttpClient::post_json`, `delete` with NetLog and scrubbing. | providers | none | `post_and_delete_are_logged_and_scrubbed`, existing tests pass |
| T05 | `ssh_server` read path: generated config pinned to a given login key (reuse `build_config`), run the read script with the bootstrap, marker check, `list`. Refuse forced command and symlink. | providers | T01, T02, T04 | `list_against_test_sshd`, `forced_command_is_refused`, `symlink_is_refused` |
| T06 | `ssh_server` `add` and `remove`: read, edit, apply with `cksum` compare, confirm. Login with `like` key for add and `keep` key for remove. Fixtures end to end. | providers | T05 | `fixtures_end_to_end_against_sshd`, `concurrent_change_writes_nothing`, `remove_logs_in_with_new_key`, `strict_modes_accepts_result` |
| T07 | GitHub `add`/`remove` (auth and signing), owner check, idempotent by list, lost response, 401/403 advice. | providers | T03b, T04 | `github_add_remove_against_fake`, `github_lost_response_no_duplicate`, `github_write_errors_hold_no_token` |
| T08 | GitLab and Forgejo `add`/`remove`: GitLab `usage_type` copied from the old key, self-hosted base URL; Forgejo. Same checks as T07. Split in two PRs if over 400 lines. | providers | T03b, T04 | `gitlab_add_remove_against_fake`, `forgejo_add_remove_against_fake`, `*_lost_response_no_duplicate` |
| T09 | Journal: migration 2 (`rotations`, `rotation_locations`, `rotation_steps`, one open rotation index), journal API in `inventory`, `Store::remove`, `detail` scrubber. | inventory | none | `migration_2_applies`, `second_open_rotation_refused`, `journal_roundtrip`, `detail_drops_key_blobs` |
| T10 | Key generation and retire: `ssh-keygen` in a temp dir in the ssh dir, no-replace links to `new_path`, terminal or `--no-passphrase`, recovery rules, move to `~/.ssh/retired/` without overwrite. Never opens the private file. | rotation | none | `generate_makes_pair`, `generate_never_overwrites`, `recover_half_generated_key`, `retire_moves_without_overwrite` |
| T11 | Plan and pre-flight (dry-run): find old key, load locations, verify old key, SSH `list` with marker, forge `list`, render actions (text and JSON). Refuse same fingerprint. Writes nothing. | rotation | T05, T09, T10 | `plan_lists_every_action`, `plan_changes_nothing`, `same_fingerprint_is_refused`, `old_key_not_in_file_is_refused` |
| T12 | Engine, happy path and S-3 gate: steps with journal before and after, per-location phases, `may_remove_old` (fresh verify, remote object rule, keep check), location rows follow steps, `Hooks` trait. Mock providers only. Update SPEC 7.2. | rotation | T04, T09, T10 | `rotation_runs_all_steps_with_mocks`, `remove_only_after_fresh_verify`, `gitlab_shared_key_waits_for_both_purposes` |
| T13 | Engine, failure and resume: retry, skip, abort, rollback with its gate, journal replay, settling `start` without end by listing, local `flock`. Exhaustive crash test with mock providers. | rotation | T12 | `crash_resume_at_every_point_mocks`, `rollback_never_touches_old_removed_location`, `skip_keeps_old_key_and_no_retire`, `second_process_is_refused` |
| T14 | Config update, pure plus apply: find `IdentityFile` lines equal to `old_path` (M1 expansion), replace value only, diff, backup, temp file and rename, keep mode. Engine hook-up is one call in T15. | rotation | none | `config_update_replaces_only_matching_value`, `config_update_keeps_other_bytes`, `config_update_lists_unknown_tokens` |
| T15 | Integration: full rotation against 2 test sshd and 3 fake forges, config step wired in; crash at every journal point and resume; invariant checker hook; non-default `AuthorizedKeysFile` server; lost responses; database scan. | rotation (tests) | T03a, T03b, T06, T07, T08, T11, T13, T14 | `full_rotation_two_servers_three_forges`, `crash_resume_at_every_point` (split by step kind), `new_key_not_verified_keeps_old_key`, `config_updated_before_removal_and_only_when_all_verified`, `rollback_restores_config_first`, `database_has_no_key_material_after_rotation` |
| T16 | CLI: `rotate plan/start/status/resume/retry/skip/abort/log`, `locations list/import-ssh-config/add-forge/check`, global path options, `--ssh-program`. Two real `kill -9` tests with an ssh wrapper. | app | T13, T11 (T15 for the kill tests' fixtures if shared) | `cli_plan_is_dry_run`, `cli_start_needs_yes`, `cli_kill_after_install_then_resume`, `cli_kill_after_remove_then_resume` |
| T17 | M2 acceptance: tick every box in `spec.md` with evidence, update SPEC.md, list the human checks still open. | all | T01 to T16 | none new |

## Parallel lanes (after their "Needs" merge)

- SSH: T01 and T02 in parallel, then T05 (also needs T04), then T06.
- Forges: T03b and T04 in parallel, then T07 and T08 in parallel.
- Core: T09 and T10 in parallel, then T12 (needs T04), then T13.
- Local files: T14 any time.
- Join: T11 after T05, T09, T10. T15 after the SSH, forge and core lanes.
  T16 after T13 and T11. T17 last.
- T03a any time before T15.

## Notes

- T04 touches every provider file. Merge it early, before T05, T07, T08,
  to avoid conflicts.
- T12 and T13 test with mock providers so they do not wait for the SSH and
  forge lanes. T15 is where real sshd and fake forges meet the engine.
- The crash tests in T15 start many sshd processes. Record the CI time in
  the PR; if it is too slow, share one server pair per test function and
  reset its `authorized_keys` between points.
