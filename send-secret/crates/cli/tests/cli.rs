//! `send-secret encrypt` and `decrypt` (M1 T10). Every test runs in its
//! own `TestEnv`.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use assert_cmd::prelude::*;
use common::{TestEnv, fixture, marker, run_with_input};

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Writes a plaintext file with a random marker and returns its path.
fn message(env: &TestEnv) -> (PathBuf, String) {
    let text = format!("secret {}", marker());
    let path = env.path("msg.txt");
    fs::write(&path, &text).unwrap();
    (path, text)
}

/// A dir for outputs, so tests can list what was written.
fn out_dir(env: &TestEnv) -> PathBuf {
    let dir = env.path("out");
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn encrypt(env: &TestEnv, args: &[&str]) -> Command {
    let mut cmd = env.ours();
    cmd.arg("encrypt").args(args);
    cmd
}

fn key(rel: &str) -> String {
    fixture(rel).to_str().unwrap().to_owned()
}

/// Decrypts `file` with our CLI in `env` and returns the plaintext.
fn open(env: &TestEnv, file: &Path, extra: &[&str]) -> Output {
    let mut cmd = env.ours();
    cmd.arg("decrypt").arg("-i").arg(file).args(extra);
    cmd.output().unwrap()
}

fn fpr(file: &str) -> String {
    let out = Command::new("gpg")
        .args(["--batch", "--with-colons", "--show-keys"])
        .arg(fixture(&format!("openpgp/{file}")))
        .output()
        .unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .find(|l| l.starts_with("fpr"))
        .unwrap()
        .split(':')
        .nth(9)
        .unwrap()
        .to_owned()
}

#[test]
fn usage_errors_exit_2() {
    let env = TestEnv::new();
    env.ours().assert().code(2);
    env.ours().arg("encrypt").assert().code(2);
    encrypt(
        &env,
        &["--to-key", &key("age/dave.pub"), "--format", "rot13"],
    )
    .assert()
    .code(2);
    env.ours().args(["decrypt", "--bogus"]).assert().code(2);
}

#[test]
fn several_recipients_without_o_exit_2() {
    let env = TestEnv::new();
    let (msg, _) = message(&env);
    let out = encrypt(&env, &["--to-key", &key("age/dave.pub")])
        .args(["--to-key", &key("ssh/erin_ed25519.pub"), "-i"])
        .arg(&msg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("-o BASE"));
}

#[test]
fn several_recipients_with_stdin_exit_2() {
    let env = TestEnv::new();
    let dir = out_dir(&env);
    let out = run_with_input(
        encrypt(&env, &["--to-key", &key("age/dave.pub")])
            .args(["--to-key", &key("ssh/erin_ed25519.pub"), "-o"])
            .arg(dir.join("m")),
        b"hello",
    );
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(names(&dir).is_empty());
}

#[test]
fn duplicate_labels_exit_2() {
    let env = TestEnv::new();
    let (msg, _) = message(&env);
    for sub in ["a", "b"] {
        fs::create_dir_all(env.path(sub)).unwrap();
        fs::copy(fixture("age/dave.pub"), env.path(sub).join("dave.pub")).unwrap();
    }
    let dir = out_dir(&env);
    encrypt(
        &env,
        &["--to-key", "a/dave.pub", "--to-key", "b/dave.pub", "-i"],
    )
    .arg(&msg)
    .arg("-o")
    .arg(dir.join("m"))
    .assert()
    .code(2);
    assert!(names(&dir).is_empty());
}

#[test]
fn self_label_reserved_exit_2() {
    let env = TestEnv::new();
    fs::copy(fixture("age/dave.pub"), env.path("self.pub")).unwrap();
    let out = encrypt(&env, &["--to-key", "self.pub", "--no-self-copy"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("\"self\""));
}

/// Encrypts `msg` for alice (OpenPGP), erin (SSH) and dave (age) as the
/// fixture sender, into `out/m`.
fn send_three(env: &TestEnv, extra: &[&str]) -> (PathBuf, Output) {
    env.import_openpgp("sender.sec.asc");
    let (msg, _) = message(env);
    let dir = out_dir(env);
    let out = encrypt(env, &["--to-key", &key("openpgp/alice.asc")])
        .args(["--to-key", &key("ssh/erin_ed25519.pub")])
        .args(["--to-key", &key("age/dave.pub")])
        .args(extra)
        .arg("-i")
        .arg(&msg)
        .arg("-o")
        .arg(dir.join("m"))
        .output()
        .unwrap();
    (dir, out)
}

#[test]
fn several_recipients_write_base_label_files() {
    let env = TestEnv::new();
    let (dir, out) = send_three(&env, &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        names(&dir),
        [
            "m.alice.gpg",
            "m.dave.age",
            "m.erin_ed25519.age",
            "m.self.gpg"
        ]
    );
    let text = fs::read_to_string(env.path("msg.txt")).unwrap();
    let dave = open(
        &env,
        &dir.join("m.dave.age"),
        &["--identity", &key("age/dave.txt")],
    );
    assert_eq!(String::from_utf8(dave.stdout).unwrap(), text);
    let erin = env.private_copy("ssh/erin_ed25519");
    let erin = open(
        &env,
        &dir.join("m.erin_ed25519.age"),
        &["--identity", erin.to_str().unwrap()],
    );
    assert_eq!(String::from_utf8(erin.stdout).unwrap(), text);
    // Dave's key does not open Erin's message.
    let wrong = open(
        &env,
        &dir.join("m.erin_ed25519.age"),
        &["--identity", &key("age/dave.txt")],
    );
    assert_eq!(wrong.status.code(), Some(1));

    let alice = TestEnv::new();
    alice.import_openpgp("alice.sec.asc");
    let opened = open(&alice, &dir.join("m.alice.gpg"), &[]);
    assert!(opened.status.success(), "{}", stderr(&opened));
    assert_eq!(String::from_utf8(opened.stdout).unwrap(), text);
}

#[test]
fn stderr_lists_outputs() {
    let env = TestEnv::new();
    let (dir, out) = send_three(&env, &[]);
    let err = stderr(&out);
    for (label, file, format) in [
        ("alice", "m.alice.gpg", "OpenPGP, signed"),
        ("erin_ed25519", "m.erin_ed25519.age", "age"),
        ("dave", "m.dave.age", "age"),
        ("self", "m.self.gpg", "OpenPGP, signed"),
    ] {
        let line = format!("{label}: {} ({format})", dir.join(file).display());
        assert!(err.contains(&line), "missing {line:?} in {err}");
    }
}

#[test]
fn output_ext_matches_format_and_armor() {
    let env = TestEnv::new();
    let (dir, out) = send_three(&env, &["--armor"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        names(&dir),
        [
            "m.alice.asc",
            "m.dave.age",
            "m.erin_ed25519.age",
            "m.self.asc"
        ]
    );
    let head = |f: &str| fs::read_to_string(dir.join(f)).unwrap();
    assert!(head("m.alice.asc").starts_with("-----BEGIN PGP MESSAGE-----\n"));
    assert!(head("m.dave.age").starts_with("-----BEGIN AGE ENCRYPTED FILE-----\n"));
}

#[test]
fn unreachable_recipient_writes_nothing() {
    let env = TestEnv::new();
    env.import_openpgp("sender.sec.asc");
    let (msg, _) = message(&env);
    let dir = out_dir(&env);
    let out = encrypt(&env, &["--to-key", &key("openpgp/alice.asc")])
        .args(["--to-key", &key("ssh/erin_ed25519.pub")])
        .args(["--format", "openpgp", "-i"])
        .arg(&msg)
        .arg("-o")
        .arg(dir.join("m"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("erin_ed25519 has no usable OpenPGP key"));
    assert!(names(&dir).is_empty());
}

#[test]
fn self_copy_written_next_to_outputs() {
    let env = TestEnv::new();
    let (dir, out) = send_three(&env, &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let opened = open(&env, &dir.join("m.self.gpg"), &[]);
    assert!(opened.status.success(), "{}", stderr(&opened));
    let text = fs::read_to_string(env.path("msg.txt")).unwrap();
    assert!(stderr(&opened).contains(&fpr("sender.asc")));
    assert_eq!(String::from_utf8(opened.stdout).unwrap(), text);
}

#[test]
fn self_copy_base_strips_ext() {
    let env = TestEnv::new();
    env.import_openpgp("sender.sec.asc");
    let (msg, _) = message(&env);
    let dir = out_dir(&env);
    encrypt(
        &env,
        &["--to-key", &key("ssh/erin_ed25519.pub"), "-a", "-i"],
    )
    .arg(&msg)
    .arg("-o")
    .arg(dir.join("msg.age"))
    .assert()
    .success();
    assert_eq!(names(&dir), ["msg.age", "msg.self.asc"]);
}

#[test]
fn no_self_copy_flag() {
    let env = TestEnv::new();
    env.import_openpgp("sender.sec.asc");
    let (msg, _) = message(&env);
    let dir = out_dir(&env);
    let out = encrypt(&env, &["--to-key", &key("age/dave.pub"), "--no-self-copy"])
        .arg("-i")
        .arg(&msg)
        .arg("-o")
        .arg(dir.join("m.age"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(names(&dir), ["m.age"]);
    assert!(!stderr(&out).contains("self"));
    // Stdout and stdin: no note either.
    let out = run_with_input(
        &mut encrypt(&env, &["--to-key", &key("age/dave.pub"), "--no-self-copy"]),
        b"hi",
    );
    assert!(out.status.success());
    assert!(!stderr(&out).contains("note"), "{}", stderr(&out));
}

#[test]
fn self_copy_needs_files_note() {
    let env = TestEnv::new();
    let dir = out_dir(&env);
    let out = run_with_input(
        encrypt(&env, &["--to-key", &key("age/dave.pub"), "-o"]).arg(dir.join("m.age")),
        b"hello",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("needs -i FILE"), "{err}");
    assert!(err.contains("--no-self-copy"), "{err}");
    assert_eq!(names(&dir), ["m.age"]);

    let (msg, _) = message(&env);
    let out = encrypt(&env, &["--to-key", &key("age/dave.pub"), "-i"])
        .arg(&msg)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(stderr(&out).contains("needs -o"), "{}", stderr(&out));
    assert!(out.stdout.starts_with(b"age-encryption.org/v1\n"));
}

#[test]
fn self_copy_fallback_note_on_stderr() {
    let env = TestEnv::new();
    let (msg, text) = message(&env);
    let dir = out_dir(&env);
    let out = encrypt(&env, &["--to-key", &key("age/dave.pub"), "-i"])
        .arg(&msg)
        .arg("-o")
        .arg(dir.join("m.age"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("no OpenPGP secret key, so the self copy uses age"),
        "{}",
        stderr(&out)
    );
    assert_eq!(names(&dir), ["m.age", "m.self.age"]);
    let identity = env.config_home().join("send-secret/identities");
    let mode = fs::metadata(&identity).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    // The default decrypt identities include the self identity.
    let opened = open(&env, &dir.join("m.self.age"), &[]);
    assert!(opened.status.success(), "{}", stderr(&opened));
    assert_eq!(String::from_utf8(opened.stdout).unwrap(), text);
}

#[test]
fn forced_openpgp_self_copy_without_key_writes_nothing() {
    let env = TestEnv::new();
    let (msg, _) = message(&env);
    let dir = out_dir(&env);
    let out = encrypt(&env, &["--to-key", &key("openpgp/alice.asc")])
        .args(["--format", "openpgp", "-i"])
        .arg(&msg)
        .arg("-o")
        .arg(dir.join("m.gpg"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("--no-self-copy"), "{}", stderr(&out));
    assert!(names(&dir).is_empty());
    assert!(!env.config_home().join("send-secret").exists());
}

#[test]
fn ssh_rsa_outside_2048_4096_skipped_with_note() {
    let env = TestEnv::new();
    let out = run_with_input(
        &mut encrypt(&env, &["--to-key", &key("ssh/multi.keys")]),
        b"hello",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    for want in [
        "RSA 1024 is too small for age",
        "RSA 8192 is too large for age",
        "ECDSA",
        "sk-ssh-ed25519",
    ] {
        assert!(err.contains(want), "missing {want:?} in {err}");
    }
    // The good keys (erin, frank) both open it.
    let ct = env.path("multi.age");
    fs::write(&ct, &out.stdout).unwrap();
    for id in ["ssh/erin_ed25519", "ssh/frank_rsa"] {
        let id = env.private_copy(id);
        let opened = open(&env, &ct, &["--identity", id.to_str().unwrap()]);
        assert_eq!(opened.stdout, b"hello");
    }
}

#[test]
fn signer_on_stderr() {
    let env = TestEnv::new();
    env.import_openpgp("sender.sec.asc");
    let out = run_with_input(
        &mut encrypt(&env, &["--to-key", &key("openpgp/alice.asc"), "-a"]),
        b"hello alice",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let alice = TestEnv::new();
    alice.import_openpgp("alice.sec.asc");
    alice.import_openpgp("sender.asc");
    let opened = run_with_input(alice.ours().arg("decrypt"), &out.stdout);
    assert!(opened.status.success(), "{}", stderr(&opened));
    assert_eq!(opened.stdout, b"hello alice");
    let err = stderr(&opened);
    assert!(
        err.contains(&format!("signed by {} (good signature", fpr("sender.asc"))),
        "{err}"
    );
    // --no-sign: decrypt says it is not signed.
    let out = run_with_input(
        &mut encrypt(&env, &["--to-key", &key("openpgp/alice.asc"), "--no-sign"]),
        b"hi",
    );
    let opened = run_with_input(alice.ours().arg("decrypt"), &out.stdout);
    assert!(
        stderr(&opened).contains("not signed"),
        "{}",
        stderr(&opened)
    );
}

#[test]
fn openpgp_without_secret_key_needs_no_sign() {
    let env = TestEnv::new();
    let out = run_with_input(
        &mut encrypt(&env, &["--to-key", &key("openpgp/alice.asc")]),
        b"hi",
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("--no-sign"), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
}

/// A binary age message for dave, three chunks long, with its last
/// chunk damaged: the first chunks decrypt before the error.
fn damaged_age_message(env: &TestEnv) -> PathBuf {
    let big = env.path("big.txt");
    fs::write(&big, vec![b'x'; 200_000]).unwrap();
    let ct = env.path("big.age");
    encrypt(
        env,
        &["--to-key", &key("age/dave.pub"), "--no-self-copy", "-i"],
    )
    .arg(&big)
    .arg("-o")
    .arg(&ct)
    .assert()
    .success();
    let mut bytes = fs::read(&ct).unwrap();
    let at = bytes.len() - 5;
    bytes[at] ^= 0x01;
    fs::write(&ct, bytes).unwrap();
    ct
}

#[test]
fn decrypt_error_removes_output_file() {
    let env = TestEnv::new();
    let ct = damaged_age_message(&env);
    let dir = out_dir(&env);
    let out = open(
        &env,
        &ct,
        &[
            "--identity",
            &key("age/dave.txt"),
            "-o",
            dir.join("plain").to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(names(&dir).is_empty(), "{:?}", names(&dir));
}

#[test]
fn decrypt_output_file_created_0600_no_temp() {
    let env = TestEnv::new();
    let (msg, text) = message(&env);
    let ct = env.path("m.age");
    encrypt(
        &env,
        &["--to-key", &key("age/dave.pub"), "--no-self-copy", "-i"],
    )
    .arg(&msg)
    .arg("-o")
    .arg(&ct)
    .assert()
    .success();
    let dir = out_dir(&env);
    let plain = dir.join("plain.txt");
    let args = [
        "--identity",
        &key("age/dave.txt"),
        "-o",
        plain.to_str().unwrap(),
    ];
    let out = open(&env, &ct, &args);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(names(&dir), ["plain.txt"]);
    assert_eq!(fs::read_to_string(&plain).unwrap(), text);
    let mode = fs::metadata(&plain).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    // An existing file is never overwritten.
    fs::write(&plain, "keep").unwrap();
    let out = open(&env, &ct, &args);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(fs::read_to_string(&plain).unwrap(), "keep");
}

#[test]
fn decrypt_error_on_stdout_says_discard() {
    let env = TestEnv::new();
    let ct = damaged_age_message(&env);
    let out = open(&env, &ct, &["--identity", &key("age/dave.txt")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("output incomplete, discard it"),
        "{}",
        stderr(&out)
    );
    // Some plaintext came out before the damage was found; the same
    // happens with -o, where the file is removed.
    assert!(out.stdout.len() >= 64 * 1024, "{}", out.stdout.len());
}

#[test]
fn decrypt_second_message_note() {
    let env = TestEnv::new();
    let mut two = fs::read(fixture("ciphertext/age-armored.age")).unwrap();
    two.extend(fs::read(fixture("ciphertext/age-armored.age")).unwrap());
    let out = run_with_input(
        env.ours()
            .args(["decrypt", "--identity", &key("age/dave.txt")]),
        &two,
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"Send Secret fixture message");
    assert!(
        stderr(&out).contains("only the first was decrypted"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn relative_xdg_config_home_ignored() {
    let env = TestEnv::new();
    let (msg, _) = message(&env);
    let dir = out_dir(&env);
    let out = encrypt(&env, &["--to-key", &key("age/dave.pub"), "-i"])
        .arg(&msg)
        .arg("-o")
        .arg(dir.join("m.age"))
        .env("XDG_CONFIG_HOME", "rel-config")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(env.config_home().join("send-secret/identities").is_file());
    assert!(!env.path("rel-config").exists());
}
