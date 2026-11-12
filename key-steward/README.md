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

All work happens in a devcontainer (Fedora, Rust, GTK4, GnuPG, OpenSSH).

- VS Code: install the Dev Containers extension, open this folder, then pick
  "Reopen in Container".
- CLI with podman:

  ```sh
  devcontainer up --workspace-folder . --docker-path podman
  devcontainer exec --workspace-folder . --docker-path podman bash
  ```

Inside the container:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Docs

- [Spec](spec/SPEC.md): what we build and the rules.
- [Workflow](spec/workflow.md): how work goes from spec to code.
- [Current milestone: M1](spec/milestones/M1/): read-only inventory.
- [Decisions](spec/decisions/README.md): open and settled questions.
- [Notes for coding agents](CLAUDE.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
