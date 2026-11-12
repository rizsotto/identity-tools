//! Interop (M1 T11): our CLI against plain `gpg` and Go `age`, both ways.
//!
//! The sender and every recipient have their own `TestEnv`, so a message
//! only opens where that person's secret key is. Recipients use only plain
//! `gpg` and `age` commands (decision 0003). If `gpg` or `age` is missing,
//! the tests fail; they never skip.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{TestEnv, assert_success, fixture, marker};

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn path_str(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Writes a plaintext file with a random marker into `env`.
fn message(env: &TestEnv, name: &str) -> (PathBuf, Vec<u8>) {
    let text = format!("secret {}\nsecond line\n", marker()).into_bytes();
    let path = env.path(name);
    fs::write(&path, &text).unwrap();
    (path, text)
}

/// The sending user: the fixture sender's OpenPGP secret key.
fn sender() -> TestEnv {
    let env = TestEnv::new();
    env.import_openpgp("sender.sec.asc");
    env
}

/// An OpenPGP recipient: their secret key, and the sender's public key so
/// `gpg` can check the signature.
fn openpgp_recipient(name: &str) -> TestEnv {
    let env = TestEnv::new();
    env.import_openpgp(&format!("{name}.sec.asc"));
    env.import_openpgp("sender.asc");
    env
}

/// Runs `send-secret encrypt` in `env` and checks it worked.
fn ours_encrypt(env: &TestEnv, keys: &[&Path], input: &Path, output: &Path, extra: &[&str]) {
    let mut cmd = env.ours();
    cmd.arg("encrypt");
    for key in keys {
        cmd.arg("--to-key").arg(key);
    }
    let out = cmd
        .args(extra)
        .arg("-i")
        .arg(input)
        .arg("-o")
        .arg(output)
        .output()
        .unwrap();
    assert_success(&out, "send-secret encrypt");
}

fn ours_decrypt(env: &TestEnv, input: &Path, extra: &[&str]) -> Output {
    env.ours()
        .arg("decrypt")
        .arg("-i")
        .arg(input)
        .args(extra)
        .output()
        .unwrap()
}

fn gpg_decrypt(env: &TestEnv, input: &Path) -> Output {
    env.gpg()
        .args(["--status-fd", "2", "--decrypt"])
        .arg(input)
        .output()
        .unwrap()
}

fn age_decrypt(env: &TestEnv, identity: &Path, input: &Path) -> Output {
    env.age()
        .args(["--decrypt", "-i"])
        .arg(identity)
        .arg(input)
        .output()
        .unwrap()
}

/// Fields of `gpg --with-colons --show-keys` for a fixture key.
fn colons(file: &str) -> Vec<Vec<String>> {
    let env = TestEnv::new();
    let out = env
        .gpg()
        .args(["--with-colons", "--show-keys"])
        .arg(fixture(&format!("openpgp/{file}")))
        .output()
        .unwrap();
    assert_success(&out, "gpg --show-keys");
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| l.split(':').map(str::to_owned).collect())
        .collect()
}

fn primary_fpr(file: &str) -> String {
    colons(file)
        .into_iter()
        .find(|f| f[0] == "fpr")
        .map(|f| f[9].clone())
        .unwrap()
}

/// Key IDs of the primary key and every subkey.
fn all_key_ids(file: &str) -> Vec<String> {
    colons(file)
        .into_iter()
        .filter(|f| f[0] == "pub" || f[0] == "sub")
        .map(|f| f[4].clone())
        .collect()
}

/// Key IDs of the subkeys that can encrypt.
fn encryption_key_ids(file: &str) -> Vec<String> {
    colons(file)
        .into_iter()
        .filter(|f| f[0] == "sub" && f[11].contains('e'))
        .map(|f| f[4].clone())
        .collect()
}

/// The key IDs a message is encrypted to, from `gpg --list-packets` in an
/// env with no keys (gpg fails to decrypt but lists the packets).
fn message_key_ids(file: &Path) -> Vec<String> {
    let env = TestEnv::new();
    let out = env.gpg().arg("--list-packets").arg(file).output().unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter(|l| l.starts_with(":pubkey enc packet:"))
        .map(|l| l.rsplit("keyid ").next().unwrap().trim().to_owned())
        .collect()
}

/// Checks that `gpg --decrypt` gave `plain` and a good signature by the
/// fixture sender.
fn assert_gpg_opened_signed(out: &Output, plain: &[u8]) {
    assert_success(out, "gpg --decrypt");
    assert_eq!(out.stdout, plain);
    let err = stderr(out);
    assert!(err.contains("[GNUPG:] GOODSIG "), "{err}");
    let validsig = format!("[GNUPG:] VALIDSIG {}", primary_fpr("sender.asc"));
    assert!(err.contains(&validsig), "{err}");
    assert!(!err.contains("[GNUPG:] BADSIG"), "{err}");
}

/// Our decrypt gave `plain` and reported a good signature by the sender.
fn assert_ours_opened_signed(out: &Output, plain: &[u8]) {
    assert_success(out, "send-secret decrypt");
    assert_eq!(out.stdout, plain);
    let want = format!("signed by {} (good signature", primary_fpr("sender.asc"));
    assert!(stderr(out).contains(&want), "{}", stderr(out));
}

/// The stanza types in a binary age header, for example `X25519`.
fn age_stanzas(file: &Path) -> Vec<String> {
    let bytes = fs::read(file).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    let header = text.split("\n---").next().unwrap();
    assert!(
        header.starts_with("age-encryption.org/v1\n"),
        "not binary age"
    );
    header
        .lines()
        .filter_map(|l| l.strip_prefix("-> "))
        .map(|l| l.split(' ').next().unwrap().to_owned())
        .filter(|t| !t.ends_with("-grease"))
        .collect()
}

/// A fresh SSH RSA key pair of `bits` in `env`, made with `ssh-keygen`.
fn ssh_rsa_key(env: &TestEnv, bits: u32) -> (PathBuf, PathBuf) {
    let key = env.path(&format!("rsa{bits}"));
    let out = env
        .command("ssh-keygen")
        .args(["-q", "-t", "rsa", "-b", &bits.to_string(), "-N", ""])
        .args(["-C", "test-fixture@example.org", "-f"])
        .arg(&key)
        .output()
        .unwrap();
    assert_success(&out, "ssh-keygen");
    let public = key.with_extension("pub");
    (key, public)
}

/// The age key types, each as (name, recipient file, identity file) in
/// `env`. SSH RSA covers both ends of the `age` crate range.
fn age_keys(env: &TestEnv) -> Vec<(String, PathBuf, PathBuf)> {
    let mut keys = vec![
        (
            "x25519".to_owned(),
            fixture("age/dave.pub"),
            fixture("age/dave.txt"),
        ),
        (
            "ssh-ed25519".to_owned(),
            fixture("ssh/erin_ed25519.pub"),
            env.private_copy("ssh/erin_ed25519"),
        ),
        (
            "ssh-rsa-3072".to_owned(),
            fixture("ssh/frank_rsa.pub"),
            env.private_copy("ssh/frank_rsa"),
        ),
    ];
    for bits in [2048, 4096] {
        let (key, public) = ssh_rsa_key(env, bits);
        keys.push((format!("ssh-rsa-{bits}"), public, key));
    }
    keys
}

#[test]
fn interop_tools_present() {
    // Fails, never skips, when a tool is missing (M1 T13).
    let env = TestEnv::new();
    let gpg = env.command("gpg").arg("--version").output().unwrap();
    assert_success(&gpg, "gpg --version");
    assert!(String::from_utf8_lossy(&gpg.stdout).starts_with("gpg (GnuPG) 2."));
    let age = env.age().arg("--version").output().unwrap();
    assert_success(&age, "age --version");
    let version = String::from_utf8_lossy(&age.stdout);
    assert!(
        version.trim_start_matches('v').starts_with("1."),
        "{version}"
    );
}

#[test]
fn interop_openpgp_ours_to_gpg() {
    let from = sender();
    for name in ["alice", "bob-rsa"] {
        let to = openpgp_recipient(name);
        for armor in [true, false] {
            let (msg, plain) = message(&from, &format!("{name}-{armor}.txt"));
            let ct = from.path(&format!("{name}-{armor}.msg"));
            let key = fixture(&format!("openpgp/{name}.asc"));
            let flags: &[&str] = if armor {
                &["--armor", "--no-self"]
            } else {
                &["--no-self"]
            };
            ours_encrypt(&from, &[&key], &msg, &ct, flags);
            let bytes = fs::read(&ct).unwrap();
            assert_eq!(bytes.starts_with(b"-----BEGIN PGP MESSAGE-----"), armor);

            assert_gpg_opened_signed(&gpg_decrypt(&to, &ct), &plain);

            // `gpg --verify` checks the signature too, on the signed
            // message inside the encryption.
            let inner = to.path(&format!("inner-{armor}.gpg"));
            let out = to
                .gpg()
                .args(["--unwrap", "--decrypt", "-o"])
                .arg(&inner)
                .arg(&ct)
                .output()
                .unwrap();
            assert_success(&out, "gpg --unwrap --decrypt");
            let out = to
                .gpg()
                .args(["--status-fd", "2", "--verify"])
                .arg(&inner)
                .output()
                .unwrap();
            assert_success(&out, "gpg --verify");
            let validsig = format!("[GNUPG:] VALIDSIG {}", primary_fpr("sender.asc"));
            assert!(stderr(&out).contains(&validsig), "{}", stderr(&out));
        }
    }
}

#[test]
fn interop_openpgp_unsigned_ours_to_gpg() {
    let from = TestEnv::new();
    let to = openpgp_recipient("alice");
    let (msg, plain) = message(&from, "m.txt");
    let ct = from.path("m.gpg");
    let key = fixture("openpgp/alice.asc");
    ours_encrypt(&from, &[&key], &msg, &ct, &["--no-sign", "--no-self"]);
    let out = gpg_decrypt(&to, &ct);
    assert_success(&out, "gpg --decrypt");
    assert_eq!(out.stdout, plain);
    assert!(!stderr(&out).contains("SIG "), "{}", stderr(&out));
}

#[test]
fn interop_openpgp_gpg_to_ours() {
    // Plain gpg as the sender: sign with the sender key, encrypt to the
    // recipient's key file.
    let from = sender();
    for name in ["alice", "bob-rsa"] {
        let to = openpgp_recipient(name);
        for armor in [true, false] {
            let (msg, plain) = message(&from, &format!("{name}-{armor}.txt"));
            let ct = from.path(&format!("{name}-{armor}.msg"));
            let mut cmd = from.gpg();
            if armor {
                cmd.arg("--armor");
            }
            let out = cmd
                .args(["--local-user", "sender@example.org", "--recipient-file"])
                .arg(fixture(&format!("openpgp/{name}.asc")))
                .args(["--sign", "--encrypt", "-o"])
                .arg(&ct)
                .arg(&msg)
                .output()
                .unwrap();
            assert_success(&out, "gpg --sign --encrypt");
            assert_ours_opened_signed(&ours_decrypt(&to, &ct, &[]), &plain);
        }
    }

    // Unsigned.
    let to = openpgp_recipient("alice");
    let (msg, plain) = message(&from, "unsigned.txt");
    let ct = from.path("unsigned.asc");
    let out = from
        .gpg()
        .args(["--armor", "--recipient-file"])
        .arg(fixture("openpgp/alice.asc"))
        .args(["--encrypt", "-o"])
        .arg(&ct)
        .arg(&msg)
        .output()
        .unwrap();
    assert_success(&out, "gpg --encrypt");
    let out = ours_decrypt(&to, &ct, &[]);
    assert_success(&out, "send-secret decrypt");
    assert_eq!(out.stdout, plain);
    assert!(stderr(&out).contains("not signed"), "{}", stderr(&out));
}

#[test]
fn interop_age_ours_to_age() {
    let env = TestEnv::new();
    for (name, recipient, identity) in age_keys(&env) {
        for armor in [true, false] {
            let (msg, plain) = message(&env, &format!("{name}-{armor}.txt"));
            let ct = env.path(&format!("{name}-{armor}.age"));
            let flags: &[&str] = if armor {
                &["--armor", "--no-self"]
            } else {
                &["--no-self"]
            };
            ours_encrypt(&env, &[&recipient], &msg, &ct, flags);
            let bytes = fs::read(&ct).unwrap();
            assert_eq!(
                bytes.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"),
                armor,
                "{name}"
            );
            let out = age_decrypt(&env, &identity, &ct);
            assert_success(&out, &format!("age --decrypt ({name}, armor {armor})"));
            assert_eq!(out.stdout, plain, "{name}");
        }
    }
}

#[test]
fn interop_age_age_to_ours() {
    let env = TestEnv::new();
    for (name, recipient, identity) in age_keys(&env) {
        for armor in [true, false] {
            let (msg, plain) = message(&env, &format!("{name}-{armor}.txt"));
            let ct = env.path(&format!("{name}-{armor}.age"));
            let mut cmd = env.age();
            if armor {
                cmd.arg("--armor");
            }
            let out = cmd
                .arg("-R")
                .arg(&recipient)
                .arg("-o")
                .arg(&ct)
                .arg(&msg)
                .output()
                .unwrap();
            assert_success(&out, "age --encrypt");
            let out = ours_decrypt(&env, &ct, &["--identity", path_str(&identity)]);
            assert_success(
                &out,
                &format!("send-secret decrypt ({name}, armor {armor})"),
            );
            assert_eq!(out.stdout, plain, "{name}");
        }
    }
}

#[test]
fn interop_age_to_ours_default_ssh_identities() {
    // FR-7: no --identity, the keys in ~/.ssh are used.
    let env = TestEnv::new();
    let ssh = env.home().join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    for (key, name) in [
        ("ssh/erin_ed25519", "id_ed25519"),
        ("ssh/frank_rsa", "id_rsa"),
    ] {
        fs::rename(env.private_copy(key), ssh.join(name)).unwrap();
    }
    for public in ["ssh/erin_ed25519.pub", "ssh/frank_rsa.pub"] {
        let (msg, plain) = message(&env, "m.txt");
        let ct = env.path("m.age");
        let out = env
            .age()
            .arg("-R")
            .arg(fixture(public))
            .arg("-o")
            .arg(&ct)
            .arg(&msg)
            .output()
            .unwrap();
        assert_success(&out, "age --encrypt");
        let out = ours_decrypt(&env, &ct, &[]);
        assert_success(&out, &format!("send-secret decrypt ({public})"));
        assert_eq!(out.stdout, plain);
        fs::remove_file(&ct).unwrap();
    }
}

#[test]
fn interop_per_recipient_outputs() {
    // One OpenPGP and one age recipient in one run. Each output opens with
    // plain gpg or age by its own recipient and by the sender, nobody else.
    let from = sender();
    let alice = openpgp_recipient("alice");
    let dave = fixture("age/dave.txt");
    for armor in [true, false] {
        let (msg, plain) = message(&from, &format!("m-{armor}.txt"));
        let base = from.path(&format!("m-{armor}"));
        let flags: &[&str] = if armor { &["--armor"] } else { &[] };
        ours_encrypt(
            &from,
            &[&fixture("openpgp/alice.asc"), &fixture("age/dave.pub")],
            &msg,
            &base,
            flags,
        );
        let ext = if armor { "asc" } else { "gpg" };
        let to_alice = PathBuf::from(format!("{}.alice.{ext}", base.display()));
        let to_dave = PathBuf::from(format!("{}.dave.age", base.display()));
        let mine = from.config_home().join("send-secret/identities");

        assert_gpg_opened_signed(&gpg_decrypt(&alice, &to_alice), &plain);
        let out = age_decrypt(&alice, &dave, &to_dave);
        assert_success(&out, "age --decrypt");
        assert_eq!(out.stdout, plain);
        assert_gpg_opened_signed(&gpg_decrypt(&from, &to_alice), &plain);
        let out = age_decrypt(&from, &mine, &to_dave);
        assert_success(&out, "age --decrypt with the sender's identity");
        assert_eq!(out.stdout, plain);

        // Nobody else opens them.
        let out = gpg_decrypt(&alice, &to_dave);
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        let other = alice.private_copy("ssh/erin_ed25519");
        let out = age_decrypt(&alice, &other, &to_dave);
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        let bob = openpgp_recipient("bob-rsa");
        let out = gpg_decrypt(&bob, &to_alice);
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn interop_age_sender_identity_opens_with_age() {
    // No OpenPGP secret key needed: an age message gets one X25519 stanza
    // for the sender's own identity, which plain `age -d -i` reads. Never
    // an SSH key of the sender.
    let from = TestEnv::new();
    let ssh = from.home().join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    fs::rename(from.private_copy("ssh/frank_rsa"), ssh.join("id_rsa")).unwrap();
    fs::copy(fixture("ssh/frank_rsa.pub"), ssh.join("id_rsa.pub")).unwrap();
    let (msg, plain) = message(&from, "m.txt");
    let ct = from.path("m.age");
    ours_encrypt(&from, &[&fixture("ssh/erin_ed25519.pub")], &msg, &ct, &[]);
    assert_eq!(age_stanzas(&ct), ["ssh-ed25519", "X25519"]);
    let identity = from.config_home().join("send-secret/identities");
    let out = age_decrypt(&from, &identity, &ct);
    assert_success(&out, "age --decrypt with the sender's identity");
    assert_eq!(out.stdout, plain);
    let erin = from.private_copy("ssh/erin_ed25519");
    let out = age_decrypt(&from, &erin, &ct);
    assert_success(&out, "age --decrypt with erin's key");
    assert_eq!(out.stdout, plain);
    let out = age_decrypt(&from, &ssh.join("id_rsa"), &ct);
    assert!(!out.status.success(), "the sender's SSH key opens it");
}

#[test]
fn interop_sender_key_in_each_recipient_output() {
    let from = sender();
    from.import_openpgp("carol-pw.asc");
    // gpg.conf asks for another key (carol) and the sender's key in every
    // message; gpg.conf adds neither. We add the sender's key ourselves.
    fs::write(
        from.gnupg_home().join("gpg.conf"),
        format!(
            "encrypt-to {}\nencrypt-to {}\n",
            primary_fpr("carol-pw.asc"),
            primary_fpr("sender.asc")
        ),
    )
    .unwrap();
    let carol_ids = all_key_ids("carol-pw.asc");

    let (msg, plain) = message(&from, "m.txt");
    let base = from.path("m");
    ours_encrypt(
        &from,
        &[
            &fixture("openpgp/alice.asc"),
            &fixture("openpgp/bob-rsa.asc"),
        ],
        &msg,
        &base,
        &[],
    );
    for (name, other) in [("alice", "bob-rsa"), ("bob-rsa", "alice")] {
        let file = from.path(&format!("m.{name}.gpg"));
        let mut ids = message_key_ids(&file);
        ids.sort();
        let mut want = encryption_key_ids(&format!("{name}.asc"));
        want.extend(encryption_key_ids("sender.asc"));
        want.sort();
        assert_eq!(ids, want, "{name}");
        assert!(ids.iter().all(|id| !carol_ids.contains(id)), "{name}");
        assert!(
            ids.iter()
                .all(|id| !all_key_ids(&format!("{other}.asc")).contains(id)),
            "{name}"
        );
        assert_gpg_opened_signed(&gpg_decrypt(&openpgp_recipient(name), &file), &plain);
        assert_gpg_opened_signed(&gpg_decrypt(&from, &file), &plain);
        let out = gpg_decrypt(&openpgp_recipient(other), &file);
        assert!(!out.status.success(), "{name}");
        assert!(out.stdout.is_empty(), "{name}");
    }

    // age: each message holds its recipient's stanza plus one X25519
    // stanza for the sender's identity, and nothing of the other.
    let base = from.path("a");
    ours_encrypt(
        &from,
        &[&fixture("age/dave.pub"), &fixture("ssh/erin_ed25519.pub")],
        &msg,
        &base,
        &["--format", "age"],
    );
    let identity = from.config_home().join("send-secret/identities");
    let dave = fixture("age/dave.txt");
    let erin = from.private_copy("ssh/erin_ed25519");
    for (name, stanzas, own, other) in [
        ("dave", ["X25519", "X25519"], &dave, &erin),
        ("erin_ed25519", ["ssh-ed25519", "X25519"], &erin, &dave),
    ] {
        let file = from.path(&format!("a.{name}.age"));
        assert_eq!(age_stanzas(&file), stanzas, "{name}");
        for key in [own, &identity] {
            let out = age_decrypt(&from, key, &file);
            assert_success(&out, &format!("age --decrypt {name}"));
            assert_eq!(out.stdout, plain, "{name}");
        }
        let out = age_decrypt(&from, other, &file);
        assert!(!out.status.success(), "{name}");
        assert!(out.stdout.is_empty(), "{name}");
    }
}

#[test]
fn interop_no_self_holds_only_recipient_keys() {
    let from = sender();
    let (msg, _) = message(&from, "m.txt");
    let base = from.path("m");
    ours_encrypt(
        &from,
        &[&fixture("openpgp/alice.asc"), &fixture("age/dave.pub")],
        &msg,
        &base,
        &["--no-self"],
    );
    let to_alice = from.path("m.alice.gpg");
    assert_eq!(message_key_ids(&to_alice), encryption_key_ids("alice.asc"));
    let out = gpg_decrypt(&from, &to_alice);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert_eq!(age_stanzas(&from.path("m.dave.age")), ["X25519"]);
    assert!(!from.config_home().join("send-secret").exists());
}

#[test]
fn interop_armor_is_gpgs_own() {
    // Decision 0003: armor header lines from the user's gpg.conf stay as
    // gpg writes them, and plain gpg opens the message.
    let from = sender();
    fs::write(
        from.gnupg_home().join("gpg.conf"),
        "comment Test comment\nemit-version\n",
    )
    .unwrap();
    let to = openpgp_recipient("alice");
    let (msg, plain) = message(&from, "m.txt");
    let ct = from.path("m.asc");
    ours_encrypt(
        &from,
        &[&fixture("openpgp/alice.asc")],
        &msg,
        &ct,
        &["--armor", "--no-self"],
    );
    let text = fs::read_to_string(&ct).unwrap();
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("-----BEGIN PGP MESSAGE-----"));
    let header: Vec<&str> = lines.take_while(|l| !l.is_empty()).collect();
    assert!(header.contains(&"Comment: Test comment"), "{header:?}");
    assert!(
        header.iter().any(|l| l.starts_with("Version: ")),
        "{header:?}"
    );
    assert_gpg_opened_signed(&gpg_decrypt(&to, &ct), &plain);
    let out = to.gpg().arg("--dearmor").arg(&ct).output().unwrap();
    assert_success(&out, "gpg --dearmor");
}
