# Key Steward

A Linux desktop app to manage your SSH and OpenPGP keys and rotate them safely.
Built with Rust, GTK4 and libadwaita. GNOME first, Niri also tier 1.

## What it does

- Keeps a list of your keys and every place each one is installed: servers,
  GitHub, GitLab, Forgejo and Codeberg, keys.openpgp.org, your WKD.
- Rotates keys in a safe order. It adds the new key, tests it, and only then
  removes the old one. Every step is logged, so a crash never locks you out.
- Reminds you before keys expire. Extending OpenPGP expiry is one click.

Working name. It may change.

## Status

Pre-alpha. Spec stage. There is no working code yet.

## Develop

See the [root README](../README.md).

## Docs

- [Spec](../spec/key-steward/SPEC.md): what we build and the rules.
- [Workflow](../spec/workflow.md): how work goes from spec to code.
- [Current milestone: M1](../spec/key-steward/milestones/M1/): read-only inventory.
- [Decisions](../spec/key-steward/decisions/README.md): open and settled questions.
- [Notes for coding agents](CLAUDE.md).

## License

GPL-3.0-or-later. See [LICENSE](../LICENSE).
