# Send Secret

Encrypt a message or a file for one person, in three clicks.

Type who it is for: an email, `github:alice` or a saved contact. Send Secret
finds their public key and shows where it came from. Paste your text or drop
a file. Copy the result into Slack or email. The same app opens secrets sent
to you.

It uses OpenPGP (through GnuPG) and age. It is a GTK4 and libadwaita app for
GNOME and other Linux desktops.

## Status

Pre-alpha. We are at the spec stage. There is no working code yet.

## Develop

See the [root README](../README.md).

## Docs

- [Spec](../spec/send-secret/SPEC.md): what we build and the rules.
- [Workflow](../spec/workflow.md): how we work, spec first.
- [Decisions](../spec/send-secret/decisions/README.md): open and settled questions.
- [Milestone M1](../spec/send-secret/milestones/M1/spec.md): crypto core and CLI.
- [CLAUDE.md](CLAUDE.md): rules for coding agents.

## License

GPL-3.0-or-later. See [LICENSE](../LICENSE).
