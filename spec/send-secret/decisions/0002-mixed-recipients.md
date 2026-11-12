# 0002: Mixed OpenPGP and age recipients

- Status: accepted (2026-11-12)
- Blocks: nothing now. M1 builds it (one message per recipient).
- SPEC refs: section 16 question 2, section 7 (crypto facade), FR-3, FR-11, UC-8

## Question

One output cannot hold both OpenPGP and age recipients. When the user picks a
mix (for example Alice has an OpenPGP key and Bob has only SSH keys), should
we produce two outputs, or force one format for everyone (and drop or refuse
the recipients that do not fit)?

Why it touches M1: the M1 CLI takes several `--to-key` files, so a user can
pass a mix. The answer also decides the facade shape: `encrypt` returns one
`Output` (force one format) or a list of outputs (two outputs). Encrypt-to-self
is part of this too, since the sender may need a key in both formats.

The old interim rule (refuse a mixed set with an error) is gone. See "Human
decision" at the end.

## Context

**When a mix happens.** Only with several people (UC-8). One person is never
a "mix": if one person has keys in both formats, FR-3 picks one. A mix needs
at least one person who can only be reached by OpenPGP and another who can
only be reached by age. Typical case: `bob@example.org` found by WKD (UC-3,
OpenPGP only) plus `github:alice` with only SSH keys (UC-2).

**Who can be reached by what.**

- People found by email (WKD, keys.openpgp.org) have OpenPGP keys. They
  usually have no age key we can find.
- People found by `github:` / `gitlab:` have SSH keys in most cases. Some also
  publish OpenPGP keys at `github.com/<user>.gpg`. Those keys are mostly made
  for commit signing and may have no encryption subkey, so they may not work
  as OpenPGP recipients. (Unverified: how often this is true.)
- So neither format reaches everyone. Forcing one format drops real users.

**No bridge from OpenPGP keys to age.** I found no tool or plugin that lets a
normal OpenPGP key (in a GnuPG keyring) act as an age recipient. The
awesome-age plugin list has plugins for YubiKey/PIV, Secure Enclave, TPM,
TKey, FIDO2, Trezor, Shamir sharing and a few others, but nothing for
OpenPGP or GnuPG. The closest is `age-plugin-openpgp-card`, which works only
for keys on an OpenPGP smart card, installs only via `cargo`, and has had no
release since October 2024 as far as I found. Even if a bridge existed, the
recipient would have to install that plugin plus age, which breaks the
"three clicks" goal. Plugins are also outside SPEC section 4 (formats and
sources are fixed for v1).

**Mixing limits exist inside age too.** age itself refuses some mixes: an
scrypt (passphrase) stanza must be alone, and a file cannot be encrypted to
both post-quantum and classic keys. The `age` crate (0.12.1) models this with
recipient "labels" and returns `EncryptError::IncompatibleRecipients` when
labels do not match. So "group recipients into compatible sets" is a general
idea, not only an OpenPGP vs age problem. v1 does not use post-quantum age
keys, but the design should not block them later.

**What the recipient must install.** OpenPGP recipients already have GnuPG
or a mail client with OpenPGP (Thunderbird, Kleopatra), since they made a key.
age recipients need `age`, `rage` or Send Secret. Their SSH private key
already exists. Neither group needs anything new if they get their own
format.

**Signing differs.** OpenPGP output is signed (UC-7). age output is not
(section 4). With two outputs, the OpenPGP recipient can check the sender and
the age recipient cannot. The UI must not suggest both are signed.

**Encrypt-to-self.** Section 4 says the sender is always added (on by
default). The sender has an age identity for sure (made on first run,
section 9). The sender may have no OpenPGP secret key. With two outputs the
sender goes into both, so both stay readable by the sender, as long as the
sender has an OpenPGP key. (The "sender has no OpenPGP key" case exists even
without a mix. It is not decided here.)

**Metadata.**

- OpenPGP: every public-key encrypted session key packet names the recipient
  key (8-byte key ID in v3, full fingerprint in v6), unless it is sent as an
  "anonymous recipient" (RFC 9580, 5.1). gpgme can hide all key IDs with
  `GPGME_ENCRYPT_THROW_KEYIDS` (since gpgme 1.8.0). It is all or nothing, and
  decrypting gets slower, since every secret key must be tried.
- age X25519: the stanza does not name the recipient. A file cannot be linked
  to a native recipient without the identity.
- age SSH: the stanza carries a tag (first 4 bytes of SHA-256 of the SSH
  public key). The age man page says a file "can be linked to the SSH public
  key it was encrypted to". Since GitHub keys are public, anyone can match an
  SSH-encrypted secret to a GitHub user.
- Two outputs leak nothing extra about recipients. Each output names only its
  own group. An observer who sees both pasted in one channel learns there were
  two groups.

**How other tools handle it.**

- Kleopatra: mixing OpenPGP and S/MIME recipients gives "two separate
  encrypted files with mutually exclusive recipients". A GnuPG developer
  called this "misleading" and planned to disable the mix (GnuPG T8324, July
  2026). A QA note on a 5.1.0 beta in the same ticket says combined
  encryption for different protocols "still works". So the closest desktop
  precedent does two outputs, and its own team finds it confusing when it is
  not made clear.
- Thunderbird: needs a usable key for every recipient and cannot send one
  email with mixed technology (OpenPGP plus S/MIME). (From the Mozilla
  support article as shown in search results. I could not load the page
  itself, it needs JavaScript.)
- sops: one file, and by default "SOPS encrypts the data key for a file with
  each of the master keys" (age, PGP, KMS and more). This works because sops
  has its own container format. Plain `gpg` or `age` cannot open a sops file.
  We cannot copy this without inventing a format (section 14: no own crypto)
  and making recipients install our app.

**Target user.** Non-expert, "three clicks" for a known contact (NFR-1).
Most sends are to one person, where no mix can happen. The mix is a rare,
multi-person case. It must not add steps to the common case, and it must
never drop a recipient without saying so.

## Options

### A. Two outputs, one per format
Always split a mixed set into an OpenPGP output and an age output.
Pros:
- Everyone gets a secret they can open with tools they already have.
- No recipient is dropped. No format conversion, no plugins.
- Same as Kleopatra's behavior for OpenPGP plus S/MIME.
- No extra metadata leak.
Cons:
- Two blobs to send. The user must send the right one to the right person.
  Sending the wrong one is not a security problem (they just cannot open it),
  but it is a support problem.
- Kleopatra's own team calls the silent two-file result "misleading". The UI
  must make the split very visible.
- Different guarantees per output (OpenPGP signed, age not).
- Two outputs from one input stream. Easy for a file (open it twice). For
  stdin or pasted text, the input must be read once and fed to two
  encryptors, or held in zeroized memory. No temp files (S-4).
- If A is used even when one format would reach everyone, it makes needless
  extra outputs.

### B. Force age for everyone
Pros:
- One output. Simple format, small armor.
- age X25519 recipients are not named in the output.
Cons:
- OpenPGP-only recipients cannot be reached. No maintained bridge exists for
  normal OpenPGP keys (see Context). These are exactly the people found by
  email (UC-3).
- Loses signing (UC-7) for everyone.
- SSH stanzas link the output to public GitHub keys anyway.

### C. Force OpenPGP for everyone
Pros:
- One output. Signed for everyone.
- Recipients' tools (gpg, Thunderbird, Kleopatra) are common.
Cons:
- SSH-only recipients cannot be reached. That breaks UC-2 for anyone in a
  multi-person send.
- Key IDs of all recipients show in the output (unless all key IDs are
  thrown away, which slows decrypt).

### D. Refuse the mix and explain, let the user split
Pros:
- Simple and honest. No surprise outputs.
- Already built as the interim rule.
Cons:
- The user must redo the send in two rounds, choosing who goes in which. For
  a non-expert this is harder than A, not easier. It is A with more clicks.
- Fine for scripts and the CLI, poor for the app.

### E. One format per message by a clear rule, split only when needed
Rule, applied to people (not single keys):
1. If one format reaches every person, use it. If both do, follow FR-3:
   OpenPGP (it signs).
2. If no single format reaches every person, split into the smallest set of
   outputs (two today): OpenPGP for those who only have OpenPGP, and the
   preferred format (FR-3) for the rest.
3. A person who can be reached by no format (for example only ECDSA or `sk-`
   SSH keys) is an error that names that person. Never drop them silently.
4. The user can force a format. People who cannot be reached in it are an
   error that names them.

How the split is shown: the app says so before encrypting ("Alice and Bob
cannot share one format. Send Secret will make two messages.") and shows two
results, each with its own copy button and the people it is for. The FR-6
header in each output also names its recipients.
Pros:
- One output in every case where one is possible. The rare mix still works.
- Reaches everyone, with no plugins or new tools for recipients.
- Clear, testable rule. Follows FR-3.
- The grouping idea also covers future age limits (post-quantum vs classic).
- Learns from Kleopatra: the split is explicit, not a silent second file.
Cons:
- More logic than A or D: a planning step and a "person" concept in the CLI.
- Same two-blob and stdin issues as A, but only in the rare mixed case.
- With rule 2, a person with both formats may land in the age group, where
  output is not signed. (Alternative: put such people in the OpenPGP group.
  Either works. FR-3 order is the simpler rule.)

### F. Own envelope that holds both (like sops)
Pros:
- One output.
Cons:
- New format. Breaks interop with plain `gpg` and `age` (M1 acceptance) and
  section 14 (no own crypto). Recipients must install Send Secret. Rejected.

## Preferred option and why

> Research note, kept for the record. The human picked a different answer:
> one message per recipient, always. See "Human decision" below. The M1 and
> M3 sketches in this section are replaced by that section.

**E, with the split (A) as its fallback. The CLI refuses the split unless
asked (D-style), the app does the split with a clear notice.**

Why:
- B and C drop real users. No OpenPGP-to-age bridge exists for normal keys,
  and SSH keys cannot be OpenPGP recipients.
- D is A with more work for the user. For a non-expert it is worse.
- Plain A makes two outputs even when one would do.
- E gives one output whenever possible, which is almost always, and still
  reaches everyone in the rare mixed case. The split is explicit, which is
  the lesson from Kleopatra.
- For the CLI, scripts should not get surprise extra files. So the CLI fails
  on a split by default and does it only with a flag.

### What it means for the M1 facade

`encrypt` keeps returning one output. It only takes recipients of one format.
A new pure function plans the outputs. The caller (CLI now, app in M3) runs
`encrypt` once per planned output. This keeps streaming simple inside
`crypto` and means the return type does not become a list.

Sketch (names are a draft):

```rust
pub enum Format { OpenPgp, Age }

/// One person. In M1, one `--to-key` file. May hold keys of both formats.
pub struct Person { pub label: String, pub keys: Vec<Recipient> }

/// One output: one format, its keys, and who it is for.
pub struct OutputPlan { pub format: Format, pub people: Vec<String>, pub keys: Vec<Recipient> }

pub enum Plan { Single(OutputPlan), Split(Vec<OutputPlan>) }

pub fn plan(people: &[Person], force: Option<Format>) -> Result<Plan, PlanError>;
// PlanError::Unreachable { people: Vec<String>, format: Option<Format> }

pub fn encrypt(input: impl Read, output: impl Write,
               plan: &OutputPlan, opts: &EncryptOpts) -> Result<()>;
// Still refuses keys of the wrong format (Error::MixedFormats) as a guard.
```

- `opts.to_self` adds the sender key of that output's format. In a split,
  the sender is in both outputs.
- `Plan::Split` is never produced when `force` is set. A forced format either
  covers everyone or returns `Unreachable`.
- `plan` does no I/O and no crypto, so it is easy to unit test.
- T09 tests change: `mixed_recipients_rejected` becomes `plan_*` tests
  (single OpenPGP, single age, both-capable picks OpenPGP, split, unreachable
  person, forced format) plus `encrypt_rejects_wrong_format_keys`.

### What it means for the M1 CLI

```
send-secret encrypt --to-key FILE [--to-key FILE ...] [-i IN] [-o OUT]
                    [--armor] [--no-self] [--no-sign] [--format openpgp|age]
                    [--split]
```

- Each `--to-key FILE` is one person. The label is the file name.
- `--format` now forces the format (plan.md said it only checks). People who
  cannot be reached in it give exit 1 and are named on stderr.
- Mixed set without `--split`: exit 1. Stderr names who needs which format
  and suggests `--split` or two runs. This is today's interim error, kept as
  the default.
- With `--split`: `-i FILE` (a regular file) and `-o BASE` are required, so
  the input can be read twice and no plaintext is buffered. Writes
  `BASE.asc` or `BASE.gpg` (OpenPGP) and `BASE.age`. Prints to stderr which
  people are in which file. Stdin input with `--split` is a usage error
  (exit 2) in M1.
- Interop tests (T11) add: a split run, then each output opens with `gpg` or
  `age` for its own people only, and the sender opens both.

### What it means for M3 (for later, not M1)

- Send flow shows the split notice and two results with per-people labels.
- Pasted text can be encrypted twice from the zeroized in-memory buffer the
  app already holds. Large files are opened twice.
- The age result must not show a signature line.

## Sources

- age man page (SSH linkability, plugins, post-quantum mixing, SSH caveats):
  https://man.archlinux.org/man/age.1.en.txt
- age format spec (X25519 stanza, scrypt must be alone, tagged recipients
  "offer less privacy"): https://github.com/C2SP/C2SP/blob/main/age.md
  (https://age-encryption.org/v1 redirects here)
- `age` crate 0.12.1, `EncryptError::IncompatibleRecipients`, labels:
  https://docs.rs/age/latest/age/enum.EncryptError.html ,
  https://docs.rs/age/latest/age/
- age SSH tag in the `age` crate source:
  https://docs.rs/crate/age/0.9.0/source/src/ssh.rs
- awesome-age plugin list (no OpenPGP plugin):
  https://github.com/FiloSottile/awesome-age
- age-plugin-openpgp-card: https://lib.rs/crates/age-plugin-openpgp-card
- Filippo Valsorda on age plugins: https://words.filippo.io/age-plugins/
- RFC 9580, section 5.1 (PKESK key ID / fingerprint, anonymous recipient):
  https://www.rfc-editor.org/rfc/rfc9580.html
- gpgme `GPGME_ENCRYPT_THROW_KEYIDS`:
  https://lists.gnupg.org/pipermail/gnupg-commits/2017-March/013522.html ,
  https://lists.gnupg.org/pipermail/gnupg-devel/2017-March/032696.html
- Kleopatra mixed OpenPGP/S/MIME gives two files, plan to disable:
  https://dev.gnupg.org/T8324
- Thunderbird "cannot encrypt" help (all recipients need keys, no mixed
  technology): https://support.mozilla.org/en-US/kb/thunderbird-help-cannot-encrypt
  (not loaded directly, needs JavaScript; content taken from search results)
- sops key groups ("encrypts the data key for a file with each of the master
  keys"): https://getsops.io/docs/usage/identities/key-groups/

Unverified, check before relying on it:
- How many GitHub `.gpg` keys have an encryption subkey (affects how often a
  mix happens).
- That no OpenPGP-to-age bridge exists at all. I only checked awesome-age and
  web search.
- Kleopatra's current release behavior. T8324 shows the plan and a beta, not
  a final release.
- Thunderbird quote (page not loaded directly).
- Whether the `age` crate's labels would ever flag SSH plus X25519 as
  incompatible (they should not; age says native, SSH and plugin keys mix).
  T01 can check this.
- Whether the Rust `gpgme` crate exposes `THROW_KEYIDS` (only relevant if we
  later hide key IDs).

## Human decision

> "generate separate messages for each recipient"

Date: 2026-11-12. This is close to option A, but split by person, not by
format. It is not one of the listed options as written.

### How it was applied

1. **One message per recipient, always.** Every recipient gets their own
   message: their own output file, or their own clipboard block in the app.
   This holds even when all recipients share a format. There is no "mixed
   set" case any more, so the old interim refusal is gone.
2. **Format per recipient.** Each message uses the best format for that
   recipient by FR-3: OpenPGP if the recipient has an OpenPGP key, else age.
   A forced format (`--format`) applies to all; a recipient with no key in
   that format is an error that names them. A recipient with no usable key
   at all is an error that names them. Nobody is dropped silently.
3. **Privacy gain.** A message names only its own recipient (and the
   sender, see below). Recipients cannot see who else got the secret. This
   fixes the metadata issue in Context: no shared OpenPGP key ID list, and
   no SSH tags of other people.
4. **One person's several keys stay in one message.** If one recipient has
   several keys of the chosen format (FR-4, for example a GitHub `.keys`
   list), they all go into that recipient's message, so any of their devices
   can open it.
5. **Signing differs per message.** OpenPGP messages are signed, age
   messages are not. Each result shows its own sign status.

### Sub-decision: encrypt-to-self (applied default, confirm)

**Applied default, please confirm.** The sender's own key is added to every
per-recipient message, in that message's format: the default OpenPGP secret
key for OpenPGP messages, the sender's age identity for age messages
(SPEC section 4, section 9). `--no-self` turns it off for all messages.

Why: SPEC section 4 says always add the sender (on by default), and nothing
in the spec argues against it here. It does not hurt privacy: an OpenPGP
message is signed by the sender anyway, and age X25519 stanzas do not name
the key. The cost is one extra stanza per message.

Not decided here (it exists without this decision too): what to do when the
sender has no OpenPGP secret key and a recipient gets OpenPGP.

### What it means for M1

- Facade: `encrypt` makes one message for one recipient (plus the sender).
  `encrypt_each` runs it for every recipient and returns one result per
  recipient. See `milestones/M1/plan.md`.
- CLI: several `--to-key` files give one output per recipient.
  `-o BASE` writes `BASE.<label>.asc` (armored OpenPGP), `BASE.<label>.gpg`
  (binary OpenPGP) or `BASE.<label>.age`. The label is the key file name
  without its extension. Stdout is allowed only with one recipient. Stdin
  with several recipients is a usage error in M1 (the input must be read
  once per message, and we do not buffer it).

### What it means for M3

- The Send flow shows one result per recipient, each with its own copy
  button, the recipient's name and the format. Only OpenPGP results show a
  signature line.
- Pasted text is encrypted once per recipient from the zeroized in-memory
  buffer the app already holds. Files are opened once per recipient.
- The label comes from the contact name or the key's user ID.
