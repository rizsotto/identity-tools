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

All work happens in a devcontainer. It has Rust, GTK4, libadwaita, GnuPG and
age.

- **VS Code:** install the Dev Containers extension, open this folder, and
  pick "Reopen in Container".
- **Command line with podman:**

  ```sh
  devcontainer up --workspace-folder . --docker-path podman
  devcontainer exec --workspace-folder . --docker-path podman bash
  ```

Inside the container:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
xvfb-run -a cargo test --workspace
```

## Docs

- [Spec](spec/SPEC.md): what we build and the rules.
- [Workflow](spec/workflow.md): how we work, spec first.
- [Decisions](spec/decisions/README.md): open and settled questions.
- [Milestone M1](spec/milestones/M1/spec.md): crypto core and CLI.
- [CLAUDE.md](CLAUDE.md): rules for coding agents.

Sibling project: Key Steward, a key manager. The two share the
`identity-core` crate.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
