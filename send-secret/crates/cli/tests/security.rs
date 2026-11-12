//! Security tests (M1 T12): no plaintext on disk (S-4, FR-8), none in
//! stderr or error messages (S-5), and keys over 1,000,000 bytes are
//! refused (S-7).

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{TestEnv, assert_success, fixture, marker, run_with_input};

const MAX_KEY: usize = 1_000_000;

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Our binary with `TMPDIR` inside the env, so its temp files can be
/// scanned too.
fn ours(env: &TestEnv) -> Command {
    let mut cmd = env.ours();
    cmd.env("TMPDIR", env.path("tmp"));
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
    let mut cmd = ours(env);
    cmd.args(["encrypt", "--to-key", &key("openpgp/alice.asc")])
        .args(["--to-key", &key("ssh/erin_ed25519.pub")])
        .args(["--to-key", &key("age/dave.pub"), "-i"])
        .arg(&msg)
        .arg("-o")
        .arg(o("m"));
    runs.push(("encrypt three", cmd));
    let mut cmd = ours(env);
    cmd.args(["encrypt", "--armor", "--to-key", &key("openpgp/alice.asc")])
        .args(["--to-key", &key("age/dave.pub"), "-i"])
        .arg(&msg)
        .arg("-o")
        .arg(o("a"));
    runs.push(("encrypt armored", cmd));
    let mut cmd = ours(env);
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
    let mut cmd = ours(env);
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
    let mut cmd = ours(env);
    cmd.args(["encrypt", "--to-key", &key("age/dave.pub")]);
    let out = run_with_input(&mut cmd, format!("piped {secret}").as_bytes());
    s.check("encrypt stdin", &out, true);
    let piped = out.stdout;
    let env = &s.env;
    let mut cmd = ours(env);
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
        let mut cmd = ours(env);
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
        let mut cmd = ours(env);
        cmd.arg("decrypt")
            .arg("-i")
            .arg(&damaged)
            .args(extra)
            .arg("-o")
            .arg(o("plain-damaged"));
        s.run(&format!("decrypt damaged {file} to file"), &mut cmd, false);
        assert!(!o("plain-damaged").exists());
        let env = &s.env;
        let mut cmd = ours(env);
        cmd.arg("decrypt").arg("-i").arg(&damaged).args(extra);
        s.run(
            &format!("decrypt damaged {file} to stdout"),
            &mut cmd,
            false,
        );
    }

    // Wrong key.
    let env = &s.env;
    let mut cmd = ours(env);
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
    let mut cmd = ours(env);
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
    let mut cmd = ours(env);
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
        let mut cmd = ours(env);
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

#[test]
fn no_plaintext_on_disk() {
    let s = session();
    // HOME, GNUPGHOME, the XDG dirs, TMPDIR and the output dir all live
    // under the env root.
    let found = files_containing(s.env.root(), s.secret.as_bytes());
    assert!(found.is_empty(), "plaintext found in {found:?}");
    // Nothing is left in TMPDIR (the OpenPGP key files are removed).
    let left: Vec<_> = fs::read_dir(s.env.path("tmp")).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
}

#[test]
fn no_plaintext_in_stderr() {
    let s = session();
    assert!(s.stderrs.len() > 20, "{}", s.stderrs.len());
    for (what, err) in &s.stderrs {
        assert!(!err.contains(&s.secret), "{what}: {err}");
    }
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
