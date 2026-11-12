# 0004: Sender's key goes into each recipient's message

- Status: accepted (2026-11-12)
- Supersedes: the encrypt-to-self sub-decision of [0002](0002-mixed-recipients.md)
  (the separate self copy). The rest of 0002 stands: one message per recipient.
- SPEC refs: FR-12, S-8, section 4, section 9, M1 acceptance

## Question

How does the sender read back what they sent? M1 built a separate self copy
(`BASE.self.<ext>`), encrypted only to the sender, so that a recipient's
message did not name the sender. The human was asked again, with this use
case: send an API key to a teammate, keep no plaintext copy anywhere, and be
able to read it back with one of my keys.

## Options

1. **Add the sender's key to each recipient's message.** One message per
   recipient that both the recipient and the sender can open. Read back from
   wherever the message was sent (chat history, mail). No extra file. The
   message shows the sender's key ID (OpenPGP) or an X25519 stanza (age), so
   a leaked message can be linked to the sender.
2. **Separate self copy (what M1 built).** The recipient's message names only
   the recipient. An extra encrypted file stays on the sender's machine.
3. **No read-back.**

## Human decision

> "option 1 is acceptable. and to retrospect, sending message to my team mate
> that we can both open is also acceptable ... it is okay to infer that i was
> the sender of the encrypted message."

Option 1.

## How it is applied

1. **Each recipient's message holds that recipient's keys plus the sender's
   key.** No one else's. One message per recipient stays (0002).
2. **OpenPGP:** the sender's default secret key (the same key that signs) is
   added as a recipient. `GPGME_ENCRYPT_NO_ENCRYPT_TO` stays on, and gpg.conf
   `recipient`, `hidden-recipient`, `recipient-file`, `hidden-recipient-file`
   and `local-user` are still refused. They could add keys of other people,
   so the sender's key is added by us, explicitly, never through gpg.conf.
3. **age:** the sender's native X25519 identity (made on first use, 0600) is
   added as one more X25519 stanza. Never an SSH key of the sender.
4. **On by default. `--no-self` turns it off** (the message then holds only the
   recipient's keys).
5. **Sender has no key in the message's format.** This can only happen for
   OpenPGP (the age identity is always there). The message is still made,
   without the sender, and stderr says which recipient's message the sender
   can not read back. Exit 0. A forced `--format openpgp` follows the same
   rule. Never a silent drop of the recipient.
6. **No self copy file.** `BASE.self.<ext>` is no longer written. The label
   `self` is no longer reserved.
7. **No plaintext on disk** (S-4) is unchanged.
