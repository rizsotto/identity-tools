# identity-tools

Two Linux desktop apps that make keys and private messages easy to handle:

- [Key Steward](key-steward/README.md): manage your SSH and OpenPGP keys,
  and rotate them safely.
- [Send Secret](send-secret/README.md): encrypt a message or a file for one
  person, in three clicks.

Both are Rust, GTK4 and libadwaita apps. They share the `identity-core`
crate (key parsing, fingerprints, GnuPG wrapper). Working names; the repo
name may change too.

## Status

Pre-alpha. Spec stage. There is no working code yet.

## Layout

```
crates/identity-core/   shared crate
key-steward/            Key Steward crates, data, tests
send-secret/            Send Secret crates, data, tests
spec/                   specs, milestones and decisions (for developers)
  workflow.md           how work goes from spec to code
  decisions/            repo-wide decisions
  key-steward/          Key Steward spec, milestones, decisions
  send-secret/          Send Secret spec, milestones, decisions
```

## Develop

All work happens in a devcontainer (Fedora, Rust).

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

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
