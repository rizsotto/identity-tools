# 0002: How integration tests get real SSH servers

- Status: accepted (option A, 2026-11-12)
- Blocks: nothing now. Blocked M1 T10 and M2 (rotation tests against 2 servers, kill-and-resume tests) until accepted.
- SPEC refs: section 16 item 7, sections 11, 12, 13, 14, FR-3, S-3, S-5

## Question

How should integration tests get real SSH servers? SPEC 11 and 13 say Docker
sshd containers in `tests/docker/` (now `key-steward/tests/docker/`). The M1 plan proposes running the system
`sshd` as a plain unprivileged process instead. Where should the test helpers
live: a new `key-steward/crates/test-support` crate, or a `tests/common/` module in each
crate?

## Context

- Key Steward calls the system `ssh` binary (SPEC 8). The tests should run
  that same binary against a real OpenSSH `sshd`.
- M1 T12 needs one server for `verify` (ok, missing key, unknown host key).
- M2 needs 2 servers, `authorized_keys` edits through `sh -s` (SPEC 9.1), and
  kill-and-resume tests for the state machine (SPEC 7.2, 12).
- Tests must never touch the real `~/.ssh` (SPEC 14). This applies on both
  sides: the client config and the server side `~/.ssh` that the remote script
  edits.
- The devcontainer is Fedora 45, run locally by rootless podman with
  `--userns=keep-id` and `label=disable`. The image starts minimal (Rust
  only). `openssh-server` and `openssh-clients` are not installed yet; T10
  adds them. The `dev` user has passwordless sudo.
- CI builds the same `.devcontainer/Containerfile` through `devcontainers/ci`
  on `ubuntu-latest`, with Docker, using `.github/ci/devcontainer.json`. That
  file has no `runArgs`, so `--userns=keep-id` is not passed in CI.
- Root `CLAUDE.md`: every test runs in CI. No test is skipped or ignored
  because it needs a server or a tool.
- Fedora 45 ships OpenSSH 10.5p1 (checked: `openssh-server-10.5p1-1.fc45`).

### Experiment (done 2026-11-12)

In a throwaway `fedora:45` container, as a non-root user, with
`openssh-server` 10.5p1. Scripts are in the session scratchpad, not in the
repo. Results:

| Check | Result |
|---|---|
| Non-root `sshd -D -e -f <cfg>`, `UsePAM no`, `PidFile none`, own `HostKey`, `ListenAddress 127.0.0.1` | Works |
| Absolute `AuthorizedKeysFile` outside the real home | Works |
| `StrictModes yes` with the temp dir under `/tmp` | Fails: "bad ownership or modes for directory /tmp". sshd walks up to `/` because the file is not in the login user's real home |
| `StrictModes yes` with the temp dir under a user-owned 755 path | Works |
| `StrictModes yes` and a group-writable `authorized_keys` | Refused. Good: this catches a real lockout bug in our remote script |
| 3 sshd processes on 3 ports at once | Works |
| `SetEnv HOME=<temp>` in `sshd_config` | Works. `$HOME` and `~` in the session point at the temp dir. `sh -s` script with `mkdir -p ~/.ssh` wrote only to the temp dir. No real `~/.ssh` was created |
| Session working directory | The real home from passwd (`/home/dev`), not `$HOME`. Remote scripts must not use relative paths |
| Login as another user (`root`) | Refused. A non-root sshd can only log in its own user |
| `kill -9` sshd, start again on the same port | Works at once |
| Second sshd on a used port | Exits with "Bind to port ... failed: Address already in use" |
| Readiness | sshd prints "Server listening on 127.0.0.1 port N." on stderr at the default log level |
| inetd mode: `ProxyCommand=/usr/sbin/sshd -i -f <cfg>` | Works, no port needed |
| Speed | sshd start is a few ms. 20 sequential `ssh ... true` took 2.4 s (about 120 ms each) |
| Unknown host key with `StrictHostKeyChecking yes` | "Host key verification failed.", exit 255 |
| Nested podman in the devcontainer setup (`--userns=keep-id`) | Fails out of the box (no subuid range). With a subuid range and setuid `newuidmap` it still fails: "write to uid_map failed: Operation not permitted" |
| Nested podman with Red Hat's recipe (`quay.io/podman/stable`, `--user podman`, `--device /dev/fuse`, no keep-id) | Works |

### Side finding that matters for T12 and S-3

`-i <key>` (or `-o IdentityFile=<key>`) adds to the `IdentityFile` list from
the config. It does not replace it, and `IdentityFile=none` does not clear it.
With `IdentitiesOnly yes`, ssh still tries the config's key. In the test, `ssh
-F cfg -i bad host` logged in with the config's `good` key and exited 0. So
"exit 0" does not prove that the new key is on the server. A `verify` built
that way could report the new key as verified while only the old key works.
Then S-3 would remove the old key and lock the user out. `ssh -v` prints
`Server accepts key: <path> ED25519 SHA256:... explicit`, which names the key
that worked. T12 should check that fingerprint, and the harness needs a test
where the config holds a second valid key.

## Options

### A. sshd as a plain unprivileged process

Each test starts `/usr/sbin/sshd -D -e -f <cfg>` as the test user, on
`127.0.0.1` and a free port, with a temp host key, temp `authorized_keys` and
`SetEnv HOME` pointing at a temp server home. The client uses a temp ssh
config. Variant: inetd mode through `ProxyCommand` (no port, no daemon).

Pros:
- Real OpenSSH `sshd`, the same version as the client. Verified above.
- Works the same in the devcontainer, in CI (same image) and on a dev host
  with `openssh-server`. No container runtime, socket or privilege needed.
- Fast: no image pull, ms startup. Each test gets its own server, so tests run
  in parallel without shared state.
- Kill and restart on the same port is trivial, which M2 needs.
- `StrictModes yes` checks the modes our remote script leaves behind.
- Wide prior art (see Sources): OpenSSH's own regress suite, Go's
  `x/crypto/ssh` tests, `wezterm-ssh` and `distant-ssh2` in Rust, curl's test
  suite.

Cons:
- Only one login user: the user running the tests.
- No root-only code paths in sshd (privilege drop to the user, chroot, PAM).
- Not a distro's `sshd_config` defaults. We write our own config.
- The server side "home" is faked with `SetEnv HOME`. The session still starts
  in the real home dir, and `%h` in sshd config means the real home.
- Small port race (pick a free port, release it, sshd binds it). Needs a
  retry. The inetd variant has no race but puts a `ProxyCommand` in the test
  config, which real users rarely have, and cannot test timeouts on TCP.
- `StrictModes yes` needs a temp dir whose parents are not group or world
  writable, so not `/tmp`.

### B. Nested containers

B1: podman inside the rootless podman devcontainer. B2: mount the host
podman (or Docker) socket into the devcontainer and use `testcontainers-rs`.
B3: a GitHub Actions service container, as `openssh-rs` does with
`linuxserver/openssh-server`.

Pros:
- A real distro sshd running as root, with its own users and real homes. The
  server side `~/.ssh` is isolated for free.
- Can test a different login user and distro defaults.

Cons:
- B1 failed with the current devcontainer flags (see experiment). It worked
  only with a different image, `--user podman` and `--device /dev/fuse`. That
  means changing the devcontainer, and it is unverified with `--userns=keep-id`.
- B2 gives the tests control of the host container runtime. Sibling
  containers are not on the devcontainer's `127.0.0.1`. Local runtime is
  podman, CI runtime is likely Docker. Rootless podman needs the Ryuk reaper
  turned off (per Testcontainers docs). `testcontainers-rs` with podman is
  unverified.
- B3 works only in CI, not in the devcontainer, so local runs differ.
- Slower: image pull and seconds per container start. More moving parts, so
  more flaky.
- M2 kill-and-resume needs container stop and start, which is slower and more
  fragile than a process.

### C. Both: process locally, containers in CI

Pros:
- Fast local loop, plus distro realism in CI.

Cons:
- Two harnesses to build and keep in sync. A test can pass locally and fail in
  CI, or the other way round.
- CI still needs B's socket or nesting setup inside `devcontainers/ci`.
- M1 and M2 do not need anything that only containers give.

### D. A pure Rust SSH server as a fake (for example `russh` server)

Pros:
- In process, fast, no system binary. Easy fault injection (drop the
  connection mid-transfer).

Cons:
- Not OpenSSH. We would have to write `exec`, a shell for `sh -s`, and
  `authorized_keys` parsing with options (`from=`, `restrict`, comments).
  Then the tests check our fake, not the server users run.
- The key M2 claim, "the new key logs in at this server", is about OpenSSH
  behaviour. A fake cannot prove it.
- Goes against the spirit of SPEC 8 (no Rust SSH library). Fault injection is
  better done in the app at journal steps, as SPEC 13 already says.

### The `test-support` crate question

Option 1: `key-steward/crates/test-support`, `publish = false`, used only as a
dev-dependency. Option 2: a `tests/common/mod.rs` in each crate that needs
it.

- The sshd harness is needed by `providers` (T12), `rotation` (M2) and
  `inventory` (T17 check runner). Temp `HOME`/`GNUPGHOME` and the guard are
  needed in almost every crate.
- `tests/common/` is per crate. Sharing it means copies or `#[path]` tricks,
  and it cannot be used from unit tests in `src/`.
- A helper crate is the normal Rust pattern for this. Cargo itself has
  `crates/cargo-test-support`. The workspace already includes `key-steward/crates/*`, so
  no `Cargo.toml` change at the root.
- Risk: someone adds it as a normal dependency. Rule: only under
  `[dev-dependencies]`. A reviewer checks it.
- `CARGO_TARGET_TMPDIR` is set only when compiling integration tests, so the
  helper crate cannot read it itself. The test passes it in, for example
  `Sshd::start(env!("CARGO_TARGET_TMPDIR"))`.

Choice: Option 1.

## Preferred option and why

**A: sshd as a plain unprivileged process, with helpers in
`key-steward/crates/test-support`.**

Why: it runs the real OpenSSH server and client that users run, it works the
same in the devcontainer and CI with no extra privileges, and it is fast and
simple to kill and restart for M2. Everything M1 and M2 need was checked in
the experiment. What it does not cover (other login users, root sshd paths,
distro defaults) is not used by M1 or M2. If a later milestone needs it, add
an opt-in CI job then (a service container or a root sshd via the
devcontainer's sudo), as a new decision.

### Steps (T10)

1. Create `key-steward/crates/test-support` with `publish = false`. Dependencies:
   `tempfile`, and `libc` if step 6 uses `PR_SET_PDEATHSIG`. Other crates add
   it under `[dev-dependencies]` only.
2. `Sshd::start(base_dir)` makes a temp dir under `base_dir` (tests pass
   `env!("CARGO_TARGET_TMPDIR")`, which is `<workspace>/target/tmp`). Before
   starting, check that no parent dir is group or world writable and that
   each is owned by root or the current user. If one fails, fail with a
   message that names that dir, its owner and its mode. Refuse to run as
   root, with a clear message (a root sshd wants the privsep user).
3. In that dir: `ssh-keygen -q -t ed25519 -N '' -f hostkey`, a client key, a
   server home `srvhome/.ssh` (0700) with `authorized_keys` (0600), and this
   `sshd_config`:

   ```
   ListenAddress 127.0.0.1:<port>
   HostKey <dir>/hostkey
   PidFile none
   UsePAM no
   StrictModes yes
   AuthorizedKeysFile <dir>/srvhome/.ssh/authorized_keys
   SetEnv HOME=<dir>/srvhome
   AuthenticationMethods publickey
   PasswordAuthentication no
   KbdInteractiveAuthentication no
   PerSourcePenalties no
   LogLevel VERBOSE
   ```

   `AuthorizedKeysFile` must equal `$HOME/.ssh/authorized_keys` of the
   session, so the file our remote script edits is the file sshd reads.
   `PerSourcePenalties no` (OpenSSH 9.8+) stops sshd from blocking
   `127.0.0.1` after the tests' deliberate failed logins (curl's test suite
   sets it too).
4. Port: bind `127.0.0.1:0`, read the port, close, start sshd with it. Read
   stderr until `Server listening on 127.0.0.1 port N.` (timeout 5 s). If
   stderr says `Address already in use`, pick a new port and retry, up to 5
   times.
5. Client side: write `known_hosts` with `[127.0.0.1]:<port> <hostkey.pub>`
   and an `ssh_config`:

   ```
   Host <alias>
     HostName 127.0.0.1
     Port <port>
     User <current user>
     IdentitiesOnly yes
     IdentityAgent none
     UserKnownHostsFile <dir>/known_hosts
     GlobalKnownHostsFile /dev/null
     StrictHostKeyChecking yes
     BatchMode yes
     ConnectTimeout 5
   ```

   Do not put `IdentityFile` in the default config: tests pass the key they
   mean (see the side finding). Every `ssh` the tests run (and the app under
   test) gets `-F <dir>/ssh_config`, which also skips `/etc/ssh/ssh_config`.
   Remove `SSH_AUTH_SOCK` and set `HOME` to a temp dir in the child's
   environment. `User` is the current user from `getpwuid(geteuid())`, never
   a fixed name or uid: in CI the uid differs (see "Running in CI").
6. `Drop` kills sshd and waits. Also offer `stop()` and `restart()` on the
   same port for M2. To avoid stray sshd after an abort, set
   `PR_SET_PDEATHSIG` in `pre_exec` (Linux only; not tested yet).
7. Fail loudly if `/usr/sbin/sshd` or `ssh` is missing. Do not skip the
   test. No `#[ignore]`.
8. Tests in the crate:
   - `harness_sshd_accepts_test_key`
   - `guard_rejects_real_home`
   - `harness_server_home_is_temp` (`ssh host 'echo $HOME'` equals the temp
     server home)
   - `harness_two_servers_at_once`
   - `harness_restart_on_same_port`
   - `harness_strict_modes_rejects_group_writable_file`
   - `harness_ssh_config_has_no_real_home_paths` (`ssh -G -F <cfg> <alias>`
     output has no path under the real home)
   - `harness_failed_logins_do_not_block` (about 10 logins with a wrong key,
     then a login with the right key works; checks `PerSourcePenalties no`)
   - `harness_no_stray_sshd_after_parent_dies` (only if step 6 uses
     `PR_SET_PDEATHSIG`; see "Not verified")
9. Add a note for T12: a test where the config holds a second valid key, and
   `verify` of a missing key must still return `Missing`. The fix is open, see
   M1 `plan.md`, "ssh_server verify".
10. Delete the empty `key-steward/tests/docker/`. Apply the SPEC text change below in the
    same PR. Point SPEC 16 item 7 at this record. (The SPEC text was applied
    when this record was accepted. T10 keeps it true.)
11. Add `openssh-server openssh-clients` to `.devcontainer/Containerfile`.
    Done means: the harness tests pass in the GitHub CI run of the T10 PR,
    not only locally. Link the run in the PR and tick the CI checks below.

### Proposed SPEC.md text change

Applied to SPEC.md on 2026-11-12, with the paths moved to `key-steward/`, the
`identity-core` entry dropped from the app tree (it lives in `crates/` at the
repo root), and a line that these tests run in CI. The text below is the
original proposal.

Section 11, replace the layout lines with:

```
├── crates/ identity-core/ inventory/ providers/ rotation/ reminders/ app/ test-support/
├── remote-scripts/ authorized_keys_apply.sh
├── data/ (desktop, metainfo, icons, gschema)
├── po/
├── build-aux/flatpak/
├── tests/
│   └── mock-forges/     # wiremock-based fake GitHub/GitLab/Forgejo APIs
└── spec/
```

and add after the block:

> `key-steward/crates/test-support` holds test helpers: the test sshd harness, temp `HOME`
> and `GNUPGHOME`, the real-home guard and mock forge setup. It has
> `publish = false`. Other crates may use it only under `[dev-dependencies]`.

Section 12, M1: replace "Checks servers (FR-3) against the Docker sshd in
tests." with:

> Checks servers (FR-3) against the test sshd (section 13) in tests.

Section 12, M2: replace "The full state machine against 2 Docker sshd servers
+ the mock forges." with:

> The full state machine against 2 test sshd servers (section 13) + the mock
> forges.

Section 13, replace the "Integration:" bullet with:

> - Integration: `key-steward/crates/test-support` starts the system `/usr/sbin/sshd` as a
>   normal process, as the user who runs the tests. One process per server, on
>   `127.0.0.1` and a free port. Each server has its own temp dir under
>   `CARGO_TARGET_TMPDIR` (not `/tmp`, so `StrictModes yes` works) with its own
>   `sshd_config`, a fresh host key, `UsePAM no`, `StrictModes yes`,
>   `PerSourcePenalties no`, an absolute `AuthorizedKeysFile` and
>   `SetEnv HOME=<temp server home>`. Run real `ssh` against it with
>   `-F <temp ssh_config>`, `UserKnownHostsFile <temp>`,
>   `GlobalKnownHostsFile /dev/null`, `IdentitiesOnly yes`,
>   `IdentityAgent none` and `BatchMode yes`, with `SSH_AUTH_SOCK` removed.
>   Not covered: logging in as another user, root-only sshd code paths, and a
>   distro's own `sshd_config`. See `spec/key-steward/decisions/0002-ssh-test-servers.md`.

Section 14, first bullet: replace "Use Docker, mocks and a temporary
`GNUPGHOME` / `HOME`." with:

> Use the test sshd from `key-steward/crates/test-support`, mocks and a temporary
> `GNUPGHOME` / `HOME`.

Section 16, item 7: replace with:

> 7. How integration tests get SSH servers. See
>    `spec/key-steward/decisions/0002-ssh-test-servers.md`.

### Running in CI (hard requirement)

Every sshd test runs in CI in the same devcontainer image. No `#[ignore]`, no
"skip if sshd is missing". What that needs:

- `openssh-server` and `openssh-clients` in `.devcontainer/Containerfile`,
  added in T10. They are in the M1 plan's package list.
- Temp dirs outside `/tmp`, because of `StrictModes yes`. Use
  `CARGO_TARGET_TMPDIR`, which is `<workspace>/target/tmp`. In CI the
  workspace is the bind mounted checkout.
- A temp `HOME` for every child process. OpenSSH finds `~` from passwd, not
  `$HOME`, so also pass `-F`, `UserKnownHostsFile` and
  `GlobalKnownHostsFile /dev/null` every time. The real-home guard compares
  against the passwd home, not a fixed `/home/dev`.
- The uid differs. Locally `--userns=keep-id` maps the host user to `dev`
  (uid 1000 in the image). In CI, `devcontainers/ci` uses the devcontainer
  CLI, which by default changes the `remoteUser` uid and gid to match the
  host user that owns the checkout (on GitHub runners this is likely 1001).
  The harness must use the current uid and name at run time.

### Not verified, and the check for each

Each item becomes a check in the T10 PR. Record the result here or in the PR.

- [ ] Tests run as `dev`, not root, in CI. Check: the harness refuses root
      (step 2). Print `id` once in the T10 CI run.
- [ ] The uid update in CI happens and `dev` owns the checkout. Check: in the
      T10 CI run print `id -u`, `getent passwd dev` and
      `stat -c '%u %g %a %n'` of the workspace and `target/tmp`.
- [ ] Every parent dir of `<workspace>/target/tmp` in CI is owned by root or
      `dev` and is not group or world writable. Check: step 2's check, which
      names the bad dir. If it fails, options (pick in the T10 PR, not now):
      `chmod go-w` on the bad dir in `runCmd` before `cargo test`; or a base
      dir made in the Containerfile and chowned to `dev` in
      `postCreateCommand`. Do not use the real home.
- [ ] sshd binds `127.0.0.1` inside the Docker container in CI. Check:
      `harness_sshd_accepts_test_key` passes in CI.
- [ ] The passwd home of `dev` exists in CI (the sshd session starts there).
      Check: `harness_server_home_is_temp` passes in CI and its stderr has no
      "Could not chdir to home directory".
- [ ] `PerSourcePenalties no` is needed and works. It was not seen to trigger
      in the experiment. Check: `harness_failed_logins_do_not_block`.
- [ ] `PR_SET_PDEATHSIG` cleanup. Not tried. Note: it fires when the parent
      thread ends, not the process, and cargo runs tests on threads. Check:
      `harness_no_stray_sshd_after_parent_dies`, or drop the idea and rely on
      `Drop`.
- [ ] Load: tried 3 servers at once and 20 sequential connections, not dozens
      of tests in parallel. Check: the full suite in CI with default test
      threads. Note the time in the PR.
- [ ] Parsing `Server accepts key` from `ssh -v` as the T12 fix is only a
      suggestion. T12 confirms the exact text, or picks another option (see
      M1 `plan.md`).

No longer relevant, because option A was chosen: nested podman with
`--userns=keep-id` (B1) and `testcontainers-rs` against podman (B2). The old
worry that Docker rejects `--userns=keep-id` does not apply: the CI config
has no `runArgs`.

## Sources

- OpenSSH regress suite, runs sshd as the invoking user with `StrictModes no`,
  `AuthorizedKeysFile $OBJ/authorized_keys_%u`, and a `ProxyCommand` with
  `sshd -i`:
  https://github.com/openssh/openssh-portable/blob/master/regress/test-exec.sh
- Go `x/crypto/ssh` tests, run the system sshd in inetd mode (`-f cfg -i -e`)
  as the current user, skip when root:
  https://github.com/golang/crypto/blob/master/ssh/test/test_unix_test.go
- `wezterm-ssh` (Rust) test fixture, spawns `/usr/sbin/sshd` on a free port
  with `StrictModes no` and temp keys, notes the port race:
  https://docs.rs/crate/wezterm-ssh/0.4.0/source/tests/sshd.rs
- `distant-ssh2` (Rust), same pattern:
  https://rust-digger.code-maven.com/src/distant-ssh2-0.20.0/tests/sshd/mod.rs
- curl test suite (Python), spawns sshd with its own `AuthorizedKeysFile`,
  `ListenAddress 127.0.0.1:<port>`, retries on port failure, sets
  `PerSourcePenalties no` for OpenSSH 9.8+:
  https://github.com/curl/curl/blob/master/tests/http/testenv/sshd.py
- `openssh-rs` (Rust) CI, uses a GitHub Actions service container
  `linuxserver/openssh-server` (option B3):
  https://github.com/openssh-rust/openssh/blob/master/.github/workflows/test.yml
- libssh tests, run OpenSSH sshd as non-root with cwrap (nss_wrapper,
  uid_wrapper, socket_wrapper) to fake users and root. Shows the cost of
  faking more users; it later broke with newer OpenSSH privsep:
  https://blog.cryptomilk.org/2015/09/24/libssh-in-the-matrix/
- Red Hat, Podman inside a container (rootless needs `--user podman`,
  `--device /dev/fuse`, `label=disable`):
  https://www.redhat.com/en/blog/podman-inside-container
- Testcontainers, container runtime requirements (podman socket, Ryuk off for
  rootless): https://java.testcontainers.org/supported_docker_environment/
- Cargo's own test helper crate:
  https://github.com/rust-lang/cargo/tree/master/crates/cargo-test-support
- `CARGO_TARGET_TMPDIR` (set only for integration tests and benches):
  https://doc.rust-lang.org/cargo/reference/environment-variables.html
- Rust book, `tests/common/mod.rs` pattern:
  https://doc.rust-lang.org/book/ch11-03-test-organization.html
- Local experiment: `fedora:45` container, `openssh-server-10.5p1-1.fc45`,
  podman 6.1.3, 2026-11-12.

## Human decision

Date: 2026-11-12. Quote:

> make it possible to run as user. ensure all tests can be run in CI.

How it was applied:

- Option A accepted: the real sshd runs as the unprivileged test user. No
  root, no nested containers. The `key-steward/crates/test-support` crate is
  kept.
- "All tests run in CI" is a hard rule: no `#[ignore]`, no skip if missing.
  See "Running in CI" and the checks under "Not verified".
- T10 is done only when the harness tests pass in GitHub CI (step 11). T12
  and later SSH tasks, including M2 rotation tests, wait for T10.
- SPEC.md sections 11, 12, 13, 14 and 16 item 7 are updated.
- The `ssh -i` side finding stays an open item for T12, with a failing test
  first. See M1 `plan.md`.
