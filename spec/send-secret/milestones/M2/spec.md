# M2: Resolver and trust

Slice of `spec/send-secret/SPEC.md` section 12 (M2). The spec wins if this file differs.

## Goal

Find a recipient's keys from a short query (`alice@example.org`,
`github:alice`, `gitlab:alice`, a contact name, a fingerprint, a pasted key),
show where each key came from, remember the keys the user accepts (TOFU),
and block encryption when a remembered key changes. The `send-secret` CLI
gets `lookup` and `encrypt --to QUERY`. No GTK (M3).

SPEC section 12, M2:

- All sources in 4 work against the mocks, merged and ordered.
- WKD hash tests against known vectors from the GnuPG wiki/spec.
- TOFU: first use, same key, changed key (blocked), accepted change (history kept).

## Acceptance criteria

### Query

- [ ] The query type is detected: email, `github:user`, `gitlab:user`,
  `gitlab:host/user`, contact name, fingerprint. Bad user names, hosts and
  addresses are refused with a clear error and never reach a URL.
  Refs: [FR-1](../../SPEC.md#functional), [S-7](../../SPEC.md#10-security-rules-must)

### Sources (SPEC 4, all against local mocks)

- [ ] Local contacts: a pinned contact resolves from the trust store with no
  network request. Refs: SPEC 4 item 1, FR-5
- [ ] Local GnuPG keyring: keys whose valid user ID has the queried email, or
  whose fingerprint is the query, are found (temp `GNUPGHOME`). Not imported
  anywhere. Refs: SPEC 4 item 2
- [ ] WKD: advanced URL first; direct URL only when `openpgpkey.<domain>` has
  no address. A 404, timeout or TLS error on the advanced host does not fall
  back. Binary and armored answers, several concatenated keys.
  Refs: SPEC 4 item 3, SPEC 9 ("WKD")
- [ ] WKD hash and URLs match known vectors (draft-koch-openpgp-webkey-service
  example `Joe.Doe@Example.ORG` gives `iy9q119eutrkn8s1mk4r39qejnbu3n5q`) and
  `gpg-wks-client --print-wkd-hash` for a list of addresses, including
  upper case and non-ASCII local parts. Refs: SPEC 12 M2, SPEC 13
- [ ] keys.openpgp.org: `GET /vks/v1/by-email/<percent-encoded email>`; 404 is
  "not found"; 429 is "rate limited", never retried in a loop.
  Refs: SPEC 4 item 4, SPEC 9
- [ ] S-6: a WKD or keys.openpgp.org key with no valid (not revoked, not
  invalid) user ID for the queried email is rejected, and the reason is shown.
  Only matching user IDs are shown for those keys.
  Refs: [S-6](../../SPEC.md#10-security-rules-must)
- [ ] GitHub: `github.com/<user>.keys` (SSH) and `github.com/<user>.gpg`
  (OpenPGP, may hold no key). Refs: SPEC 4 item 5, UC-2, FR-4
- [ ] GitLab: `gitlab.com/<user>.keys` and `<host>/<user>.keys` for
  `gitlab:host/user`, https only. Refs: SPEC 4 item 6, FR-1
- [ ] Unsupported SSH keys in a `.keys` list (ECDSA, `sk-`, RSA outside 2048 to
  4096 bits) are listed with a skip note, the rest are used.
  Refs: [FR-4](../../SPEC.md#functional)
- [ ] Pasted key: armored or binary OpenPGP, SSH lines, age recipients.
  Refs: SPEC 4 item 7
- [ ] Every network source handles: not found, timeout (5 s per source, SPEC 7),
  malformed data, oversized data (over 1,000,000 bytes rejected while
  reading), rate limits (429, and GitHub's 403/429 with rate limit headers),
  redirects (https only, at most 5). Refs: SPEC 14, S-7, SPEC 13 "Mocks"
- [ ] No test makes a real network request or a real DNS query. Every network
  test uses local mock servers. Refs: SPEC 13, SPEC 14

### Merge and show

- [ ] Results from all sources merge by fingerprint and are ordered by SPEC 4
  source order. A key found by two sources lists both sources.
  Refs: SPEC 4, SPEC 7, SPEC 12 M2
- [ ] Each candidate shows: source (URL or keyring path) next to the
  fingerprint, key type, full and short fingerprint, creation date (OpenPGP),
  and state pinned, new or changed. Refs: [FR-2](../../SPEC.md#functional),
  [S-3](../../SPEC.md#10-security-rules-must)
- [ ] Every DNS check and HTTP request of a lookup is listed (`lookup
  --verbose`), with its outcome. Refs: [NFR-2](../../SPEC.md#non-functional)

### Trust (TOFU)

- [ ] First use: a new contact's keys are shown and used only after an
  explicit accept (`--accept-new`, or `lookup --accept`). The pin is stored.
  Refs: UC-4, [FR-5](../../SPEC.md#functional)
- [ ] Same key: a lookup that finds only pinned keys encrypts with no prompt.
  Refs: FR-5, NFR-1
- [ ] Changed key: a lookup that finds a key not in the pin blocks encryption
  (exit 1, writes nothing). The error shows old and new fingerprints, each
  with its source. Refs: [S-2](../../SPEC.md#10-security-rules-must), FR-5, S-3
- [ ] Accepted change: only `--accept-change <full new fingerprint>` (the "I
  verified the new key" action) replaces the pin. History keeps the old and
  new fingerprints, the time and the source of each accepted change.
  Refs: FR-5, S-2
- [ ] The store is `$XDG_DATA_HOME/send-secret/trust.sqlite3`, dir 0700, file
  0600; symlinks and loose modes are refused or fixed as plan.md says. Public
  key bytes are stored once per fingerprint and only for keys that are not in
  the GnuPG keyring; history holds fingerprints, not keys. Refs: SPEC 8
  "Storage", human rule (plan.md "Trust store")

### CLI

- [ ] `send-secret lookup QUERY` prints the candidates (FR-2, S-3).
  `send-secret encrypt --to QUERY` works for email, `github:`, `gitlab:` and
  contact queries, mixes with `--to-key`, and gives one message per recipient
  (FR-11) with the sender's key (FR-12, decision 0004).
  Refs: UC-2, UC-3, FR-1, FR-11, FR-12

### Security

- [ ] S-1: after a lookup, encrypt and decrypt to the pinned contact run with
  no network: `strace` shows no `AF_INET`/`AF_INET6` socket. A control test
  shows the check catches a socket. Refs: [S-1](../../SPEC.md#10-security-rules-must)
- [ ] Fetched keys are parsed only by identity-core and gpgme (no own packet
  parser), with the 1 MB limit, and never imported into the user's keyring.
  Refs: S-7, section 14
- [ ] Nothing logs plaintext, ciphertext, passphrases or key bytes; errors
  never echo fetched data. Refs: [S-5](../../SPEC.md#10-security-rules-must)
- [ ] `cargo fmt`, `cargo clippy -D warnings` and all tests (both apps, since
  identity-core changes) pass in CI.

## Out of scope for M2

GTK app, key change banner and dialog (M3). Background refresh of pinned
contacts (deferred, see `decisions/README.md`). GitLab `.gpg` and
keys.openpgp.org by fingerprint (not in SPEC 4). A config file for GitLab
hosts (the CLI takes `gitlab:host/user` directly). Deleting contacts.
