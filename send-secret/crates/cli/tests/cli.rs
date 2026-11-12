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
    let out = TestEnv::new()
        .gpg()
        .args(["--with-colons", "--show-keys"])
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
fn self_label_is_not_reserved() {
    let env = TestEnv::new();
    fs::copy(fixture("age/dave.pub"), env.path("self.pub")).unwrap();
    let out = run_with_input(&mut encrypt(&env, &["--to-key", "self.pub"]), b"hi");
    assert!(out.status.success(), "{}", stderr(&out));
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
        ["m.alice.gpg", "m.dave.age", "m.erin_ed25519.age"]
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
        ["m.alice.asc", "m.dave.age", "m.erin_ed25519.age"]
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
fn sender_reads_back_every_message() {
    // Each recipient's message also opens with the sender's own keys: the
    // OpenPGP one with the default secret key, the age ones with the
    // sender's X25519 identity (found by decrypt without --identity).
    let env = TestEnv::new();
    let (dir, out) = send_three(&env, &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!stderr(&out).contains("note"), "{}", stderr(&out));
    let text = fs::read_to_string(env.path("msg.txt")).unwrap();
    for file in ["m.alice.gpg", "m.dave.age", "m.erin_ed25519.age"] {
        let opened = open(&env, &dir.join(file), &[]);
        assert!(opened.status.success(), "{file}: {}", stderr(&opened));
        assert_eq!(String::from_utf8(opened.stdout).unwrap(), text, "{file}");
    }
    let opened = open(&env, &dir.join("m.alice.gpg"), &[]);
    assert!(stderr(&opened).contains(&fpr("sender.asc")));
    let identity = env.config_home().join("send-secret/identities");
    let mode = fs::metadata(&identity).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn no_self_flag() {
    let env = TestEnv::new();
    env.import_openpgp("sender.sec.asc");
    let (msg, _) = message(&env);
    let dir = out_dir(&env);
    let out = encrypt(&env, &["--to-key", &key("age/dave.pub"), "--no-self"])
        .args(["--to-key", &key("openpgp/alice.asc"), "-i"])
        .arg(&msg)
        .arg("-o")
        .arg(dir.join("m"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!stderr(&out).contains("note"), "{}", stderr(&out));
    assert_eq!(names(&dir), ["m.alice.gpg", "m.dave.age"]);
    // No age identity was made, and the sender opens neither message.
    assert!(!env.config_home().join("send-secret").exists());
    for file in ["m.alice.gpg", "m.dave.age"] {
        let opened = open(&env, &dir.join(file), &[]);
        assert_eq!(opened.status.code(), Some(1), "{file}");
    }
}

#[test]
fn one_recipient_stdin_to_stdout() {
    let env = TestEnv::new();
    let out = run_with_input(
        &mut encrypt(&env, &["--to-key", &key("age/dave.pub")]),
        b"hello",
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!stderr(&out).contains("note"), "{}", stderr(&out));
    assert!(out.stdout.starts_with(b"age-encryption.org/v1\n"));
    let ct = env.path("m.age");
    fs::write(&ct, &out.stdout).unwrap();
    let mine = open(&env, &ct, &[]);
    assert_eq!(mine.stdout, b"hello", "{}", stderr(&mine));
    let dave = open(&env, &ct, &["--identity", &key("age/dave.txt")]);
    assert_eq!(dave.stdout, b"hello", "{}", stderr(&dave));
}

#[test]
fn no_openpgp_key_note_names_recipient() {
    // No OpenPGP secret key: alice's message is made without the sender's
    // key and stderr says so; dave's age message still has it. Exit 0.
    let env = TestEnv::new();
    let (msg, text) = message(&env);
    let dir = out_dir(&env);
    let out = encrypt(&env, &["--to-key", &key("openpgp/alice.asc")])
        .args(["--to-key", &key("age/dave.pub"), "--no-sign", "-i"])
        .arg(&msg)
        .arg("-o")
        .arg(dir.join("m"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains(
            "note: alice: your own key is not in this message, so you can not read it back \
             (you have no OpenPGP secret key)"
        ),
        "{err}"
    );
    assert!(!err.contains("note: dave"), "{err}");
    assert_eq!(names(&dir), ["m.alice.gpg", "m.dave.age"]);
    assert_eq!(
        open(&env, &dir.join("m.alice.gpg"), &[]).status.code(),
        Some(1)
    );
    let opened = open(&env, &dir.join("m.dave.age"), &[]);
    assert_eq!(String::from_utf8(opened.stdout).unwrap(), text);
    let alice = TestEnv::new();
    alice.import_openpgp("alice.sec.asc");
    let opened = open(&alice, &dir.join("m.alice.gpg"), &[]);
    assert_eq!(String::from_utf8(opened.stdout).unwrap(), text);
}

#[test]
fn forced_openpgp_with_sign_only_key_notes_and_sends() {
    // The default key can sign but not encrypt; --format openpgp follows
    // the same rule: the message is made, signed, without the sender.
    let env = TestEnv::new();
    let out = env
        .gpg()
        .args(["--passphrase", "", "--quick-gen-key"])
        .args(["Sign Only (test fixture) <signonly@example.org>", "ed25519"])
        .args(["sign", "1y"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let (msg, _) = message(&env);
    let dir = out_dir(&env);
    let out = encrypt(&env, &["--to-key", &key("openpgp/alice.asc")])
        .args(["--format", "openpgp", "-i"])
        .arg(&msg)
        .arg("-o")
        .arg(dir.join("m.gpg"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains("alice: your own key is not in this message"),
        "{err}"
    );
    assert!(err.contains("default OpenPGP key cannot encrypt"), "{err}");
    assert!(err.contains("(OpenPGP, signed)"), "{err}");
    assert_eq!(names(&dir), ["m.gpg"]);
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
    encrypt(env, &["--to-key", &key("age/dave.pub"), "--no-self", "-i"])
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
    encrypt(&env, &["--to-key", &key("age/dave.pub"), "--no-self", "-i"])
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

#[test]
fn encrypt_refuses_existing_output() {
    let env = TestEnv::new();
    let (msg, _) = message(&env);
    let dir = out_dir(&env);
    // One output path exists: nothing is written, not even the other.
    fs::write(dir.join("m.erin_ed25519.age"), "keep").unwrap();
    let out = encrypt(&env, &["--to-key", &key("age/dave.pub")])
        .args(["--to-key", &key("ssh/erin_ed25519.pub"), "-i"])
        .arg(&msg)
        .arg("-o")
        .arg(dir.join("m"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("file exists"), "{}", stderr(&out));
    assert_eq!(names(&dir), ["m.erin_ed25519.age"]);
    assert_eq!(
        fs::read_to_string(dir.join("m.erin_ed25519.age")).unwrap(),
        "keep"
    );
}

#[test]
fn read_back_note_not_printed_when_run_fails() {
    // No secret key: alice's message would get the note, but signing it
    // fails first, so no note about reading it back.
    let env = TestEnv::new();
    let (msg, _) = message(&env);
    let dir = out_dir(&env);
    let out = encrypt(&env, &["--to-key", &key("openpgp/alice.asc"), "-i"])
        .arg(&msg)
        .arg("-o")
        .arg(dir.join("m.gpg"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("--no-sign"), "{err}");
    assert!(!err.contains("read it back"), "{err}");
    assert!(names(&dir).is_empty());
}
