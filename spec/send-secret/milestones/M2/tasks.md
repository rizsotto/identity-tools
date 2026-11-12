# M2 tasks

One task per branch (`m2/tNN-short-name`), one PR each, under about 400
changed lines. Test first. "Needs" lists tasks that must be merged first.
Tasks with no open needs can run in parallel. Design: `plan.md`.

**Read-back lane:** decision 0004 is being built now (sender's key in each
recipient's message, no self copy file). It changes `crates/cli/src/main.rs`
`encrypt()` and the `crypto` facade. M2 tasks marked **RB** touch
`main.rs` and must start only after that lane is merged into `main`. No M2
task touches `crypto`.

| ID | Task | Needs | Test |
|---|---|---|---|
| T01 | Fixtures: extend `send-secret/tests/fixtures/gen.sh` with `alice-new`, `mallory-other`, `olivia-two-uids`, `rita-revoked-uid`, `eve-expired`, binary and concatenated exports for WKD, and `tests/mock-sources/` canned files (`github-empty.gpg`, junk, HTML). Update the fixtures README table. | none | Extend `crates/cli/tests/fixtures.rs`: every new file exists, has the right type, user IDs and expiry as `gpg --show-keys` reports them (temp home). |
| T02 | identity-core: `wkd` module. `wkd_hash(local_part) -> String` (ASCII-only lower case, SHA-1, z-base-32 per RFC 6189 5.1.6), `WkdUrls::for_address(&str) -> Result<{advanced, direct}>` (domain lower case, `l=` unchanged and percent-escaped). Uses the `sha1` crate (RustCrypto), no own SHA-1. | none | Vectors table in plan.md; `wkd_matches_gpg_wks_client` runs `gpg-wks-client --print-wkd-hash` on them and on 20 generated addresses; the draft's two example URLs exactly. Both apps' tests pass. |
| T03 | identity-core: `UserId::has_email(&str)` (valid, not revoked, ASCII case-insensitive whole-address match), `Gpg::export_key(fpr) -> Vec<u8>` (1 MB cap), `Gpg::split_keys(bytes) -> Vec<(OpenPgpKey, Vec<u8>)>` (throwaway 0700 home, gpg.conf `no-autostart`, at most 32 keys, deleted after; user keyring untouched). | none (T01 for fixtures `olivia`, `rita`; can use M1 fixtures first) | `has_email` cases incl. revoked user ID, upper case, `<>` forms; `export_key_gives_one_key`; `split_keys_concatenated_two_keys`; `split_keys_leaves_keyring_untouched` (list keys before/after); over 1 MB and over 32 keys refused. Both apps' tests pass. |
| T04 | resolver: `Query`, `parse_query`, `contact_key`, `QueryError` (plan.md "Queries"). Pure. | none | Table test of good and bad inputs: emails (upper case, `+`, non-ASCII local part, IDN domain refused, IP literal refused), GitHub names (39 chars ok, 40 not, `--`, leading `-`), GitLab names (`.keys` suffix, `..`, `/`), `gitlab:host:port/user`, userinfo refused, fingerprints with spaces, contact names. |
| T05 | resolver: `Net` HTTP layer part 1: reqwest + rustls client, `get` with deadline, 1 MB cap (Content-Length and streamed), manual redirects (https only, max 5), User-Agent, `with_mock_origins` (loopback only, unknown host fails), `NetLog`. Adds tokio, reqwest, url, wiremock (dev). | none | wiremock: 200, 404, slow (timeout), 1,000,001 bytes with and without Content-Length, redirect https followed and logged, redirect to http refused, loop stops at 5, 401 is an error, non-loopback mock target refused, request to an unmapped host fails without a connection. |
| T06 | resolver: `Net` part 2: `host_has_address` (getaddrinfo via `dns-lookup`, or `libc` wrapper if its API does not expose the EAI code; check first), `resolve_to_addrs` hand-off, 429/403 rate limit mapping with `Retry-After`, per-host cooldown, DNS check logged. | T05 | `localhost_has_address` (real getaddrinfo, `/etc/hosts` only); mock map answers; 429 with and without `Retry-After`; cooldown skips the host and says so; `x-ratelimit-remaining: 0` with 403. |
| T07 | resolver: model and trait: `KeySource`, `Found`, `FoundKey`, `KeyBytes`, `Source`, `Rejected`, `SourceError`, `Resolver::resolve` (parallel, per-source timeout, `Mode`), merge by fingerprint and SPEC 4 order. | T04 | Fake in-memory sources: merge of one fingerprint from three sources, order by rank, a timing-out source gives `Timeout` while others return, `LocalOnly` never builds a `Net`, unusable keys kept with notes. |
| T08 | resolver: GitHub and GitLab sources (`.keys` with `parse_public_keys`, GitHub `.gpg` with `split_keys` in `spawn_blocking`, zero keys is "no key"). | T03, T05, T07 (T01 for mock files) | wiremock: `multi.keys` gives usable keys and skip notes (ECDSA, `sk-`, RSA 1024, RSA 8192); `.gpg` empty; `.gpg` expired key unusable; `.keys` 404 + `.gpg` ok; both 404 is NotFound; junk; oversized; 429; `gitlab:host/user` asks the mapped host; exact request paths. |
| T09 | resolver: WKD source (DNS check, advanced then direct, no fallback on 404/timeout/TLS, binary or armored, several keys, S-6 check, matching user IDs only in `shown_user_ids`). | T02, T03, T06, T07, T01 | Two wiremock servers (`openpgpkey.example.org`, `example.org`): advanced used when the host is mapped, direct when not, advanced 404 and timeout do not fall back, alice binary and armored found, alice+mallory blob gives one key and one `EmailMismatch`, rita's revoked user ID rejected, olivia shows only the matching user ID, oversized, redirect. |
| T10 | resolver: keys.openpgp.org source (by-email, 404, 429, S-6). Base URL `https://keys.openpgp.org`, mapped in tests. | T03, T06, T07 | wiremock: exact path for `a+b@example.org`; found; 404 NotFound; 429 RateLimited with retry_after; mallory served for alice rejected; junk; oversized. |
| T11 | resolver: GnuPG keyring source and pasted source. | T03, T07 | Temp `GNUPGHOME` with fixtures: email match, fingerprint match, revoked user ID not matched, bytes are one key; pasted armored, binary, SSH lines, age line, junk, over 1 MB. |
| T12 | trust: store file, modes and schema (plan.md "Where and file modes", tables). `Store::open`, migrations, `PRAGMA user_version`, `busy_timeout`. Adds rusqlite. | none | `store_created_0700_0600`, `loose_dir_tightened`, `loose_file_refused`, `symlinked_dir_or_file_refused`, `schema_too_new_refused`, `no_wal_files`. |
| T13 | trust: TOFU logic: `verdict`, `pin_first_use`, `accept_change` (full fingerprints only), `narrow`, `history`, contact names, keys stored once, keyring keys without bytes, unused key rows deleted. | T12 | `first_use_pins`, `same_key_is_same`, `changed_key_is_changed`, `accept_change_needs_full_fingerprint`, `accepted_change_keeps_history`, `narrowed_shrinks_pin_and_logs`, `unusable_keys_do_not_count`, `two_contacts_one_key_row`, `keyring_key_has_no_bytes`, `unpinned_key_row_removed`. |
| T14 | resolver: contacts source (reads `trust::Store`) and `Resolver::standard(cfg, net, store, gpg)` with all seven sources. Integration test with every source mocked. | T08, T09, T10, T11, T13 | `all_sources_merged_and_ordered` (plan.md "Merge and order"); `pinned_contact_local_only_makes_no_request` (NetLog empty). |
| T15 | cli: lib target (`cli/src/lib.rs`) with `lookup` module and `Env`; `send-secret lookup` and `contacts` subcommands (output as plan.md "CLI"), `--verbose`, `--accept-new`, `--accept`, `--accept-change`, `--name`. Touches `main.rs` only to add the two subcommands to `Cmd` and dispatch (a few lines). | T14. Rebase on the read-back lane if it has merged; if not, keep the `main.rs` edit to the `Cmd` enum and `main()` match. | In-process with mock `Net`: output has source next to fingerprint (S-3), states, skip notes, rejected reasons, request log; accept flows store pins; conflicting sources refuse `--accept-new`; `contacts QUERY` shows history. Process test: `lookup` of a pinned contact needs no `Net`. |
| T16 **RB** | cli: `encrypt --to QUERY` (repeatable, mixed with `--to-key`), labels from the canonical query, `--accept-new`, `--refresh`, Changed blocks before any output, conversion to `crypto::Person`. | T15, read-back lane merged | In-process: new without flag writes nothing and lists candidates; with `--accept-new` pins and the message opens with the recipient key and with the sender key; `--refresh` with a changed mock key exits 1, writes nothing, prints old and new fingerprints with sources; `--to` + `--to-key` give one message each (FR-11); `github:` recipient with SSH keys gives one age message all usable keys open. |
| T17 **RB** | Security tests: `s1_no_network_after_lookup` and `s1_strace_check_catches_inet_socket`; `lookup_never_prints_key_bytes`; no plaintext marker in stderr for `--to` runs; trust store has no plaintext marker after encrypt. Add the S-1 test to `check-tests-ran.sh` counts. | T16 | The tests themselves (plan.md "S-1"). |
| T18 | Accept M2: tick every box in `spec.md` with evidence, update SPEC 12 and 15. | all | Review only. |

## Parallel lanes

- **Start at once (no needs):** T01, T02, T03, T04, T05, T12. Six lanes.
  T02 and T03 both touch identity-core: run them in one core lane, one
  after the other, to avoid conflicts in `lib.rs`.
- After T04: T07. After T05: T06. After T12: T13.
- After T03+T05+T07: T08. After T02+T03+T06+T07: T09. After T03+T06+T07:
  T10. After T03+T07: T11. These four run in parallel.
- T14 is the join point for the resolver.
- T15 can run before the read-back lane merges (tiny `main.rs` edit).
- T16 and T17 wait for the read-back lane (they change `encrypt()` and its
  tests).

## Notes

- identity-core changes (T02, T03) must keep Key Steward's tests green.
  Keep them free of Send Secret logic: WKD hash, export and split are
  generic.
- No task adds a key source or format outside SPEC 4.
- Every network test uses `Net::with_mock_origins`. A review should reject
  any test that builds `Net::new` and calls `lookup`.
