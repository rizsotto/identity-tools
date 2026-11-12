mod common;

use common::{TestEnv, assert_success, fixture, marker, run_with_input};
use std::collections::BTreeSet;

fn fingerprints(colons: &str, record: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut want_fpr = false;
    for line in colons.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields[0] == record {
            want_fpr = true;
        } else if fields[0] == "fpr" && want_fpr {
            found.insert(fields[9].to_string());
            want_fpr = false;
        } else if fields[0] != "fpr" {
            want_fpr = false;
        }
    }
    found
}

fn fixture_fingerprint(env: &TestEnv, file: &str) -> String {
    let out = env
        .gpg()
        .args(["--with-colons", "--show-keys"])
        .arg(fixture(&format!("openpgp/{file}")))
        .output()
        .unwrap();
    assert_success(&out, "gpg --show-keys");
    let fprs = fingerprints(&String::from_utf8(out.stdout).unwrap(), "pub");
    assert_eq!(fprs.len(), 1);
    fprs.into_iter().next().unwrap()
}

#[test]
fn harness_isolates_home() {
    let env = TestEnv::new();

    let out = env
        .gpg()
        .args(["--with-colons", "--list-keys"])
        .output()
        .unwrap();
    assert_success(&out, "gpg --list-keys");
    assert!(fingerprints(&String::from_utf8(out.stdout).unwrap(), "pub").is_empty());

    env.import_openpgp("alice.asc");
    env.import_openpgp("sender.sec.asc");

    let out = env
        .gpg()
        .args(["--with-colons", "--list-keys"])
        .output()
        .unwrap();
    assert_success(&out, "gpg --list-keys");
    let public = fingerprints(&String::from_utf8(out.stdout).unwrap(), "pub");
    let expected: BTreeSet<String> = [
        fixture_fingerprint(&env, "alice.asc"),
        fixture_fingerprint(&env, "sender.asc"),
    ]
    .into();
    assert_eq!(public, expected);

    let out = env
        .gpg()
        .args(["--with-colons", "--list-secret-keys"])
        .output()
        .unwrap();
    assert_success(&out, "gpg --list-secret-keys");
    let secret = fingerprints(&String::from_utf8(out.stdout).unwrap(), "sec");
    assert_eq!(secret, [fixture_fingerprint(&env, "sender.asc")].into());

    assert!(env.gnupg_home().join("pubring.kbx").is_file());
    assert!(env.gnupg_home().starts_with(env.root()));
}

#[test]
fn harness_passes_only_its_own_env() {
    let env = TestEnv::new();
    let out = env.command("env").output().unwrap();
    assert_success(&out, "env");
    let text = String::from_utf8(out.stdout).unwrap();
    let names: BTreeSet<&str> = text.lines().filter_map(|l| l.split('=').next()).collect();
    let allowed: BTreeSet<&str> = [
        "HOME",
        "GNUPGHOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "PATH",
        "LC_ALL",
    ]
    .into();
    assert_eq!(names, allowed);
    let root = env.root().to_str().unwrap();
    for line in text
        .lines()
        .filter(|l| !l.starts_with("PATH=") && !l.starts_with("LC_ALL="))
    {
        assert!(line.contains(root), "{line} is outside the temp dir");
    }
}

#[test]
fn harness_runs_age_round_trip() {
    let env = TestEnv::new();
    let secret = marker();
    let mut enc = env.age();
    enc.args(["-a", "-R"]).arg(fixture("age/dave.pub"));
    let out = run_with_input(&mut enc, secret.as_bytes());
    assert_success(&out, "age -e");
    let mut dec = env.age();
    dec.args(["-d", "-i"]).arg(fixture("age/dave.txt"));
    let out = run_with_input(&mut dec, &out.stdout);
    assert_success(&out, "age -d");
    assert_eq!(out.stdout, secret.as_bytes());
}

#[test]
fn harness_runs_our_binary() {
    let env = TestEnv::new();
    let out = env.ours().output().unwrap();
    assert!(out.status.code().is_some());
}

#[test]
fn private_copy_is_0600() {
    use std::os::unix::fs::PermissionsExt;
    let env = TestEnv::new();
    let key = env.private_copy("ssh/erin_ed25519");
    assert!(key.starts_with(env.root()));
    let mode = std::fs::metadata(&key).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn markers_differ() {
    assert_ne!(marker(), marker());
}

#[test]
fn temp_dir_is_removed_on_drop() {
    let env = TestEnv::new();
    env.import_openpgp("sender.sec.asc");
    let root = env.root().to_path_buf();
    drop(env);
    assert!(!root.exists());
}
