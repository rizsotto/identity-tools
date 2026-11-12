# Test fixtures

Test keys for OpenPGP, age and SSH live here.

- `gen.sh` generates every fixture. Run it inside the devcontainer from the
  repo root: `send-secret/tests/fixtures/gen.sh`. Commit the output.
  Regenerate only with the script.
- Never put real people's keys here. Never put your own keys here.
- These keys are for tests only and are public: the private keys are in
  this repo on purpose. They protect nothing. Never use them for real
  data, and never trust them outside the tests. OpenPGP user IDs say
  `(test fixture)`, and every address is `@example.org`.
- `crates/cli/tests/fixtures.rs` checks that every file exists and has the
  right type.
- Git does not keep 0600 modes. Tests that need a private key copy it into
  their temp dir and set the mode there.

## Files

The passphrase for every protected key is `fixture-passphrase`.

| File | What |
|---|---|
| `openpgp/alice.asc`, `.sec.asc` | Ed25519 + Cv25519, no passphrase |
| `openpgp/bob-rsa.asc`, `.sec.asc` | RSA 3072 + RSA 3072, no passphrase |
| `openpgp/sender.asc`, `.sec.asc` | Ed25519 + Cv25519, no passphrase. The sending user. |
| `openpgp/carol-pw.asc`, `.sec.asc` | Ed25519 + Cv25519, with passphrase (agent path) |
| `age/dave.txt`, `dave.pub` | age x25519 identity and recipient |
| `ssh/erin_ed25519`, `.pub` | SSH Ed25519, no passphrase |
| `ssh/frank_rsa`, `.pub` | SSH RSA 3072, no passphrase |
| `ssh/grace_ed25519_pw`, `.pub` | SSH Ed25519, with passphrase |
| `ssh/heidi_ecdsa`, `.pub` | SSH ECDSA P-256, not an age recipient |
| `ssh/ivan_rsa8192.pub` | SSH RSA 8192, too big for the `age` crate (public key only) |
| `ssh/kim_rsa1024.pub` | SSH RSA 1024, too small for the `age` crate (public key only) |
| `ssh/judy_sk.pub` | Fake `sk-ssh-ed25519` line, no private key exists |
| `ssh/multi.keys` | erin, frank, heidi, judy, ivan and kim public keys, like a GitHub `.keys` list |
| `ciphertext/openpgp-armored.asc`, `openpgp-binary.gpg` | `gpg` output for alice |
| `ciphertext/age-armored.age`, `age-binary.age` | Go `age` output for dave |

The sample message in every ciphertext is `Send Secret fixture message`.
