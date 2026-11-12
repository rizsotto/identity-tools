//! Security tests (M1 T12): no plaintext on disk (S-4, FR-8), none in
//! stderr or error messages (S-5), and keys over 1,000,000 bytes are
//! refused (S-7).

mod common;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{TestEnv, assert_success, fixture, marker, run_with_input};

const MAX_KEY: usize = 1_000_000;

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Our binary with `TMPDIR` inside the env, so its temp files can be
/// scanned too, run under `strace`. Every file our binary or its children
/// (gpg) create is logged to a new file in `trace`.
fn ours(env: &TestEnv, trace: &Path) -> Command {
    static RUNS: AtomicUsize = AtomicUsize::new(0);
    let log = trace.join(RUNS.fetch_add(1, Ordering::Relaxed).to_string());
    let mut cmd = env.command("strace");
    cmd.args(["-f", "-qq", "-y", "-e", "trace=open,openat,openat2,creat"])
        .args(["-e", "status=successful", "-o"])
        .arg(log)
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_send-secret"))
        .env("TMPDIR", env.path("tmp"));
    cmd
}

fn key(rel: &str) -> String {
    fixture(rel).to_str().unwrap().to_owned()
}

/// Everything one session leaves behind.
struct Session {
    env: TestEnv,
    secret: String,
    /// Holds the plaintext input files, outside the env, since the user's
    /// own input is not ours to scan.
    _inputs: tempfile::TempDir,
    /// (what, stderr) of every run of our binary.
    stderrs: Vec<(String, String)>,
}

impl Session {
    fn trace_dir(&self) -> PathBuf {
        self._inputs.path().join("trace")
    }

    fn run(&mut self, what: &str, cmd: &mut Command, ok: bool) -> Output {
        let out = cmd.output().unwrap();
        self.check(what, &out, ok);
        out
    }

    fn check(&mut self, what: &str, out: &Output, ok: bool) {
        assert_eq!(out.status.success(), ok, "{what}: {}", stderr(out));
        self.stderrs.push((what.to_owned(), stderr(out)));
    }
}

/// Encrypts to every key type and decrypts again, with and without
/// armor, both self copy formats, stdin and stdout, and failing decrypts
/// (damaged messages, wrong key, junk input, junk key file). Decrypted
/// output goes to stdout or to `-o` files that the failed runs remove.
fn session() -> Session {
    let env = TestEnv::new();
    env.import_openpgp("sender.sec.asc");
    env.import_openpgp("alice.sec.asc");
    fs::create_dir(env.path("tmp")).unwrap();
    let out_dir = env.path("out");
    fs::create_dir(&out_dir).unwrap();
    let inputs = tempfile::Builder::new()
        .prefix("ss-input-")
        .tempdir()
        .unwrap();
    let trace = inputs.path().join("trace");
    fs::create_dir(&trace).unwrap();
    // Started before the traced runs, so gpg finds it and does not start
    // its own (a traced daemon would keep strace waiting).
    let out = env
        .command("gpgconf")
        .args(["--launch", "gpg-agent"])
        .output()
        .unwrap();
    assert_success(&out, "gpgconf --launch gpg-agent");
    let secret = marker();
    let msg = inputs.path().join("msg.txt");
    fs::write(&msg, format!("password: {secret}\n")).unwrap();
    // Three age chunks, the marker in each.
    let big = inputs.path().join("big.txt");
    let mut text = Vec::new();
    while text.len() < 200_000 {
        text.extend_from_slice(secret.as_bytes());
        text.extend_from_slice(&[b'x'; 1000]);
    }
    fs::write(&big, &text).unwrap();
    let erin = env.private_copy("ssh/erin_ed25519");
    let erin = erin.to_str().unwrap();

    let mut s = Session {
        env,
        secret: secret.clone(),
        _inputs: inputs,
        stderrs: Vec::new(),
    };
    let env = &s.env;
    let o = |name: &str| out_dir.join(name);

    // Encrypt: three recipients, OpenPGP self copy; armored; age self copy.
    let mut runs: Vec<(&str, Command)> = Vec::new();
    let mut cmd = ours(env, &trace);
    cmd.args(["encrypt", "--to-key", &key("openpgp/alice.asc")])
        .args(["--to-key", &key("ssh/erin_ed25519.pub")])
        .args(["--to-key", &key("age/dave.pub"), "-i"])
        .arg(&msg)
        .arg("-o")
        .arg(o("m"));
    runs.push(("encrypt three", cmd));
    let mut cmd = ours(env, &trace);
    cmd.args(["encrypt", "--armor", "--to-key", &key("openpgp/alice.asc")])
        .args(["--to-key", &key("age/dave.pub"), "-i"])
        .arg(&msg)
        .arg("-o")
        .arg(o("a"));
    runs.push(("encrypt armored", cmd));
    let mut cmd = ours(env, &trace);
    cmd.args([
        "encrypt",
        "--format",
        "age",
        "--to-key",
        &key("age/dave.pub"),
    ])
    .arg("-i")
    .arg(&big)
    .arg("-o")
    .arg(o("big.age"));
    runs.push(("encrypt age self copy", cmd));
    let mut cmd = ours(env, &trace);
    cmd.args(["encrypt", "--to-key", &key("openpgp/alice.asc"), "-i"])
        .arg(&big)
        .arg("-o")
        .arg(o("big.gpg"));
    runs.push(("encrypt big OpenPGP", cmd));
    for (what, mut cmd) in runs {
        s.run(what, &mut cmd, true);
    }
    let env = &s.env;

    // Stdin to stdout.
    let mut cmd = ours(env, &trace);
    cmd.args(["encrypt", "--to-key", &key("age/dave.pub")]);
    let out = run_with_input(&mut cmd, format!("piped {secret}").as_bytes());
    s.check("encrypt stdin", &out, true);
    let piped = out.stdout;
    let env = &s.env;
    let mut cmd = ours(env, &trace);
    cmd.args(["decrypt", "--identity", &key("age/dave.txt")]);
    let out = run_with_input(&mut cmd, &piped);
    s.check("decrypt stdin", &out, true);
    assert!(String::from_utf8_lossy(&out.stdout).contains(&secret));

    // Decrypt every output to stdout.
    let opens: [(&str, &[&str]); 9] = [
        ("m.alice.gpg", &[]),
        ("m.erin_ed25519.age", &["--identity", erin]),
        ("m.dave.age", &["--identity", &key("age/dave.txt")]),
        ("m.self.gpg", &[]),
        ("a.alice.asc", &[]),
        ("a.dave.age", &["--identity", &key("age/dave.txt")]),
        ("a.self.asc", &[]),
        ("big.self.age", &[]),
        ("big.self.gpg", &[]),
    ];
    for (file, extra) in opens {
        let env = &s.env;
        let mut cmd = ours(env, &trace);
        cmd.arg("decrypt").arg("-i").arg(o(file)).args(extra);
        let out = s.run(&format!("decrypt {file}"), &mut cmd, true);
        assert!(String::from_utf8_lossy(&out.stdout).contains(&secret));
    }

    // Damaged messages: some plaintext is written before the error.
    for (file, extra) in [
        ("big.age", &["--identity", &key("age/dave.txt")][..]),
        ("big.gpg", &[][..]),
    ] {
        let mut bytes = fs::read(o(file)).unwrap();
        let at = bytes.len() - 5;
        bytes[at] ^= 0x01;
        let damaged = o(&format!("damaged-{file}"));
        fs::write(&damaged, bytes).unwrap();
        let env = &s.env;
        let mut cmd = ours(env, &trace);
        cmd.arg("decrypt")
            .arg("-i")
            .arg(&damaged)
            .args(extra)
            .arg("-o")
            .arg(o("plain-damaged"));
        s.run(&format!("decrypt damaged {file} to file"), &mut cmd, false);
        assert!(!o("plain-damaged").exists());
        let env = &s.env;
        let mut cmd = ours(env, &trace);
        cmd.arg("decrypt").arg("-i").arg(&damaged).args(extra);
        s.run(
            &format!("decrypt damaged {file} to stdout"),
            &mut cmd,
            false,
        );
    }

    // Wrong key.
    let env = &s.env;
    let mut cmd = ours(env, &trace);
    cmd.arg("decrypt")
        .arg("-i")
        .arg(o("m.dave.age"))
        .args(["--identity", erin, "-o"])
        .arg(o("plain-wrong"));
    s.run("decrypt with the wrong key", &mut cmd, false);
    assert!(!o("plain-wrong").exists());

    // Junk that holds the marker: errors must not echo it.
    let junk_key = s._inputs.path().join("junk.pub");
    fs::write(&junk_key, format!("ssh-ed25519 {secret} comment\n")).unwrap();
    let env = &s.env;
    let mut cmd = ours(env, &trace);
    cmd.arg("encrypt")
        .arg("--to-key")
        .arg(&junk_key)
        .arg("-i")
        .arg(&msg)
        .arg("-o")
        .arg(o("junk.age"));
    s.run("encrypt to a junk key", &mut cmd, false);
    let junk_pgp = s._inputs.path().join("junk.asc");
    fs::write(
        &junk_pgp,
        format!(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{secret}\n-----END PGP PUBLIC KEY BLOCK-----\n"
        ),
    )
    .unwrap();
    let env = &s.env;
    let mut cmd = ours(env, &trace);
    cmd.arg("encrypt")
        .arg("--to-key")
        .arg(&junk_pgp)
        .arg("-i")
        .arg(&msg)
        .arg("-o")
        .arg(o("junk.gpg"));
    s.run("encrypt to a junk OpenPGP key", &mut cmd, false);
    for (name, text) in [
        (
            "junk-armor.asc",
            format!("-----BEGIN PGP MESSAGE-----\n\n{secret}\n-----END PGP MESSAGE-----\n"),
        ),
        (
            "junk-age.age",
            format!(
                "-----BEGIN AGE ENCRYPTED FILE-----\n{secret}\n-----END AGE ENCRYPTED FILE-----\n"
            ),
        ),
        ("junk.txt", format!("plain text {secret}\n")),
    ] {
        let junk = s._inputs.path().join(name);
        fs::write(&junk, text).unwrap();
        let env = &s.env;
        let mut cmd = ours(env, &trace);
        cmd.arg("decrypt").arg("-i").arg(&junk);
        s.run(&format!("decrypt {name}"), &mut cmd, false);
    }
    s
}

/// Regular files under `dir` that contain `needle`. Does not follow
/// symlinks; skips sockets and other special files.
fn files_containing(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        let path = entry.path();
        if kind.is_dir() {
            found.extend(files_containing(&path, needle));
        } else if kind.is_file() {
            let bytes = fs::read(&path).unwrap();
            if bytes.windows(needle.len()).any(|w| w == needle) {
                found.push(path);
            }
        }
    }
    found
}

#[test]
fn scan_finds_marker() {
    // The scan itself works: a planted file is found, also deep down.
    let env = TestEnv::new();
    let secret = marker();
    let deep = env.home().join("a/b");
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("f"), format!("xx{secret}yy")).unwrap();
    assert_eq!(
        files_containing(env.root(), secret.as_bytes()),
        [deep.join("f")]
    );
}

/// Files opened with `O_CREAT`, `O_TMPFILE` or `creat` in the strace logs
/// in `dir`, as the paths strace shows for the new fds (`-y`). A
/// `O_TMPFILE` file has no name, so it is reported as `O_TMPFILE <dir>`.
fn created_files(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let log = fs::read_to_string(entry.unwrap().path()).unwrap();
        // With -f, a call can be split into "<unfinished ...>" and
        // "<... openat resumed>" lines; join them by pid.
        let mut pending: HashMap<String, String> = HashMap::new();
        for line in log.lines() {
            let (pid, rest) = line.split_once(' ').unwrap_or(("", line));
            let rest = rest.trim_start();
            let call = if let Some(head) = rest.strip_suffix(" <unfinished ...>") {
                pending.insert(pid.to_owned(), head.to_owned());
                continue;
            } else if rest.starts_with("<... ") {
                let tail = rest.split_once("resumed>").map_or("", |(_, t)| t);
                pending.remove(pid).unwrap_or_default() + tail
            } else {
                rest.to_owned()
            };
            let creates = call.starts_with("creat(")
                || ["open(", "openat(", "openat2("]
                    .iter()
                    .any(|c| call.starts_with(c))
                    && (call.contains("O_CREAT") || call.contains("O_TMPFILE"));
            if !creates {
                continue;
            }
            let ret = call.rsplit_once(") = ").map_or("", |(_, r)| r);
            let path = ret
                .split_once('<')
                .and_then(|(_, p)| p.rsplit_once('>'))
                .map_or(call.as_str(), |(p, _)| p);
            if call.contains("O_TMPFILE") {
                found.push(format!("O_TMPFILE {path}"));
            } else {
                found.push(path.to_owned());
            }
        }
    }
    found
}

/// The files a session may create: outputs (incl. decrypted `-o` files
/// that failed runs remove), recipient key files in their own temp dirs,
/// the self identity, and gpg's own files in `GNUPGHOME`.
fn allowed_creation(env: &TestEnv, path: &str) -> bool {
    let path = Path::new(path);
    let tmp = env.path("tmp");
    let name = path
        .file_name()
        .map_or(String::new(), |n| n.to_string_lossy().into_owned());
    let under = |dir: &Path| path.starts_with(dir);
    let tmp_child = path
        .strip_prefix(&tmp)
        .ok()
        .and_then(|p| p.components().next())
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .unwrap_or_default();
    let gpg_file = [
        "pubring.kbx",
        "trustdb.gpg",
        "random_seed",
        ".#lk",
        "S.gpg-agent",
        "tofu.db",
    ]
    .iter()
    .any(|p| name.starts_with(p))
        || name.ends_with(".lock");
    path == Path::new("/dev/null")
        || path == Path::new("/dev/tty")
        || under(&env.path("out"))
        || under(&env.config_home().join("send-secret"))
        || (under(&tmp)
            && ["ic-recp", "ss-split"]
                .iter()
                .any(|p| tmp_child.starts_with(p)))
        || (path.parent() == Some(&env.gnupg_home()) && gpg_file)
}

/// Regular files under the shared temp dirs that contain `needle`.
/// Unreadable or vanishing entries (other tests run at the same time) are
/// skipped, and so is `skip`.
fn shared_files_containing(dirs: &[PathBuf], skip: &Path, needle: &[u8]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut todo: Vec<PathBuf> = dirs.to_vec();
    while let Some(dir) = todo.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path == skip {
                continue;
            }
            match entry.file_type() {
                Ok(t) if t.is_dir() => todo.push(path),
                Ok(t) if t.is_file() => {
                    if let Ok(bytes) = fs::read(&path)
                        && bytes.windows(needle.len()).any(|w| w == needle)
                    {
                        found.push(path);
                    }
                }
                _ => {}
            }
        }
    }
    found
}

#[test]
fn shared_scan_finds_dev_shm() {
    let secret = marker();
    let file = PathBuf::from(format!("/dev/shm/ss-scan-test-{secret}"));
    fs::write(&file, &secret).unwrap();
    let skip = tempfile::tempdir().unwrap();
    let found =
        shared_files_containing(&[PathBuf::from("/dev/shm")], skip.path(), secret.as_bytes());
    fs::remove_file(&file).unwrap();
    assert_eq!(found, [file]);
}

/// S-4 and FR-8: the session writes no plaintext to disk.
///
/// - strace logs every file our binary and its children (gpg) create;
///   any file outside `allowed_creation` fails, even if it was deleted
///   again, and so does any `O_TMPFILE` file.
/// - The env root (HOME, GNUPGHOME, XDG dirs, TMPDIR, outputs), the
///   system temp dir, `/var/tmp` and `/dev/shm` hold no marker at the end.
///
/// What it can not catch: plaintext written into an allowed file (an
/// output path, gpg's own files) other than the ones the marker scan
/// sees at the end; writes by processes not traced (the gpg-agent is
/// started before the session, so files it creates are not logged);
/// writes through fds created other ways (`memfd_create`, `io_uring`,
/// inherited fds); swap and core dumps.
#[test]
fn no_plaintext_on_disk() {
    let s = session();
    let created = created_files(&s.trace_dir());
    // The trace covered our binary: outputs and recipient key files.
    for want in ["/out/m.alice.gpg", "/out/plain-damaged", "/tmp/ic-recp"] {
        assert!(
            created.iter().any(|p| p.contains(want)),
            "{want}: {created:?}"
        );
    }
    let bad: Vec<&String> = created
        .iter()
        .filter(|p| !allowed_creation(&s.env, p))
        .collect();
    assert!(bad.is_empty(), "unexpected files created: {bad:?}");

    let found = files_containing(s.env.root(), s.secret.as_bytes());
    assert!(found.is_empty(), "plaintext found in {found:?}");
    let shared = [
        std::env::temp_dir(),
        PathBuf::from("/var/tmp"),
        PathBuf::from("/dev/shm"),
    ];
    let found = shared_files_containing(&shared, s._inputs.path(), s.secret.as_bytes());
    assert!(found.is_empty(), "plaintext found in {found:?}");
    // Nothing is left in TMPDIR (the OpenPGP key files are removed).
    let left: Vec<_> = fs::read_dir(s.env.path("tmp")).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
}

#[test]
fn trace_sees_created_files() {
    // The strace check itself works: a file created and deleted again by a
    // traced child, and one in /dev/shm, are both reported.
    let env = TestEnv::new();
    let trace = tempfile::tempdir().unwrap();
    fs::create_dir(env.path("tmp")).unwrap();
    let shm = format!("/dev/shm/ss-trace-test-{}", marker());
    let mut cmd = ours(&env, trace.path());
    let script = format!("echo x > tmp/leak; rm tmp/leak; echo x > {shm}; rm {shm}");
    cmd.args(["--version"]);
    let out = cmd.output().unwrap();
    assert_success(&out, "traced --version");
    let out = env
        .command("strace")
        .args(["-f", "-qq", "-y", "-e", "trace=open,openat,openat2,creat"])
        .args(["-e", "status=successful", "-o"])
        .arg(trace.path().join("sh"))
        .args(["--", "sh", "-c", &script])
        .output()
        .unwrap();
    assert_success(&out, "traced sh");
    let created = created_files(trace.path());
    let leak = env.path("tmp/leak");
    assert!(
        created.contains(&leak.to_string_lossy().into_owned()),
        "{created:?}"
    );
    assert!(created.contains(&shm), "{created:?}");
    assert!(!allowed_creation(&env, leak.to_str().unwrap()));
    assert!(!allowed_creation(&env, &shm));
    assert!(allowed_creation(
        &env,
        env.path("out/m.age").to_str().unwrap()
    ));
}

#[test]
fn no_plaintext_in_stderr() {
    let s = session();
    assert!(s.stderrs.len() > 20, "{}", s.stderrs.len());
    for (what, err) in &s.stderrs {
        assert!(!err.contains(&s.secret), "{what}: {err}");
    }
}

#[test]
fn no_ciphertext_in_stderr() {
    let s = session();
    // Body lines of every armored output; header lines like `Comment: x`
    // are not ciphertext.
    let mut body = Vec::new();
    for entry in fs::read_dir(s.env.path("out")).unwrap() {
        let text = String::from_utf8_lossy(&fs::read(entry.unwrap().path()).unwrap()).into_owned();
        if text.starts_with("-----BEGIN") {
            body.extend(
                text.lines()
                    .filter(|l| l.len() >= 16 && !l.starts_with("-----") && !l.contains(": "))
                    .map(str::to_owned),
            );
        }
    }
    assert!(body.len() > 10, "{}", body.len());
    for (what, err) in &s.stderrs {
        assert!(!err.contains("-----BEGIN"), "{what}: {err}");
        assert!(!err.contains("age-encryption.org"), "{what}: {err}");
        for line in &body {
            assert!(!err.contains(line.as_str()), "{what}: {err}");
        }
    }
}

/// Runs `cmd` on a new terminal, types `typed` at the first passphrase
/// prompt once echo is off, and returns (exit code, all terminal output).
fn on_tty(env: &TestEnv, typed: &str, cmd: &[&OsStr]) -> (i32, String) {
    const SCRIPT: &str = r#"
import os, pty, signal, sys, termios, time
signal.alarm(60)
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[2], sys.argv[2:])
out, sent = b"", False
while True:
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    out += data
    if not sent and b"assphrase" in out:
        for _ in range(500):
            if not termios.tcgetattr(fd)[3] & termios.ECHO:
                break
            time.sleep(0.01)
        os.write(fd, sys.argv[1].encode() + b"\n")
        sent = True
_, status = os.waitpid(pid, 0)
sys.stdout.buffer.write(out)
sys.exit(os.waitstatus_to_exitcode(status) if sent else 99)
"#;
    let out = env
        .command("python3")
        .args(["-I", "-c", SCRIPT, typed])
        .args(cmd)
        .output()
        .unwrap();
    assert!(out.stderr.is_empty(), "{}", stderr(&out));
    let code = out.status.code().unwrap();
    assert_ne!(code, 99, "no passphrase prompt");
    (code, String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn ssh_passphrase_never_echoed() {
    // The SSH key passphrase is typed on the terminal: it must not show up
    // in anything our binary writes, right or wrong.
    let env = TestEnv::new();
    let secret = marker();
    let ct = env.path("m.age");
    let out = run_with_input(
        env.ours()
            .args(["encrypt", "--no-self-copy", "--to-key"])
            .arg(fixture("ssh/grace_ed25519_pw.pub"))
            .arg("-o")
            .arg(&ct),
        secret.as_bytes(),
    );
    assert_success(&out, "encrypt");
    let identity = env.private_copy("ssh/grace_ed25519_pw");
    let decrypt = [
        OsStr::new(env!("CARGO_BIN_EXE_send-secret")),
        OsStr::new("decrypt"),
        OsStr::new("--identity"),
        identity.as_os_str(),
        OsStr::new("-i"),
        ct.as_os_str(),
    ];
    let (code, tty) = on_tty(&env, "fixture-passphrase", &decrypt);
    assert_eq!(code, 0, "{tty}");
    assert!(tty.contains(&secret), "{tty}");
    assert!(!tty.contains("fixture-passphrase"), "{tty}");

    let wrong = format!("wrong-{}", marker());
    let (code, tty) = on_tty(&env, &wrong, &decrypt);
    assert_eq!(code, 1, "{tty}");
    assert!(!tty.contains(&secret), "{tty}");
    assert!(!tty.contains(&wrong), "{tty}");
}

/// Key files of `MAX_KEY + extra` bytes, one per kind: an age line, an
/// armored OpenPGP key, binary junk.
fn sized_keys(env: &TestEnv, extra: usize) -> Vec<PathBuf> {
    let size = MAX_KEY + extra;
    let pad = |mut bytes: Vec<u8>, fill: u8| {
        assert!(bytes.len() < size);
        bytes.resize(size, fill);
        bytes
    };
    let dir = env.path(&format!("keys-{extra}"));
    fs::create_dir(&dir).unwrap();
    let files = [
        (
            "dave.pub",
            pad(fs::read(fixture("age/dave.pub")).unwrap(), b'\n'),
        ),
        (
            "alice.asc",
            pad(fs::read(fixture("openpgp/alice.asc")).unwrap(), b'\n'),
        ),
        ("junk.bin", vec![0x99; size]),
    ];
    files
        .into_iter()
        .map(|(name, bytes)| {
            let path = dir.join(name);
            fs::write(&path, bytes).unwrap();
            path
        })
        .collect()
}

#[test]
fn cli_rejects_huge_key() {
    let env = TestEnv::new();
    let msg = env.path("msg.txt");
    fs::write(&msg, "hello").unwrap();
    let out_dir = env.path("out");
    fs::create_dir(&out_dir).unwrap();
    for key in sized_keys(&env, 1) {
        let out = env
            .ours()
            .args(["encrypt", "--no-self-copy", "--no-sign", "--to-key"])
            .arg(&key)
            .arg("-i")
            .arg(&msg)
            .arg("-o")
            .arg(out_dir.join("m"))
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{key:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("larger than 1000000 bytes"),
            "{key:?}: {}",
            stderr(&out)
        );
        assert!(fs::read_dir(&out_dir).unwrap().next().is_none());
    }
    // Exactly at the limit is fine.
    let at_limit = &sized_keys(&env, 0)[..2];
    for key in at_limit {
        let out = env
            .ours()
            .args(["encrypt", "--no-self-copy", "--no-sign", "--to-key"])
            .arg(key)
            .arg("-i")
            .arg(&msg)
            .output()
            .unwrap();
        assert_success(&out, &format!("encrypt to {key:?}"));
    }
}
