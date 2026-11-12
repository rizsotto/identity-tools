//! GnuPG backend (Send Secret T06, Key Steward T05). Every test uses its own
//! temp GnuPG home.

mod common;

use std::time::{Duration, SystemTime};

use common::GpgHome;
use identity_core::{Fingerprint, Gpg, GpgError, KeyAlgo, MAX_KEY_INPUT, OpenPgpBackend};

fn fprs(keys: &[identity_core::OpenPgpKey]) -> Vec<String> {
    keys.iter().map(|k| k.fingerprint.to_string()).collect()
}

#[test]
fn gpg_wrapper_uses_given_home() {
    let a = GpgHome::new();
    let b = GpgHome::new();
    let a_fpr = a.gen_key("A Example (test fixture) <a@example.org>");
    let b_fpr = b.gen_key("B Example (test fixture) <b@example.org>");

    let mut gpg = Gpg::with_home(a.path()).unwrap();
    assert_eq!(gpg.home(), Some(a.path()));
    assert_eq!(gpg.effective_home().as_deref(), Some(a.path()));
    assert_eq!(fprs(&gpg.public_keys().unwrap()), [a_fpr]);

    let mut gpg = Gpg::with_home(b.path()).unwrap();
    assert_eq!(fprs(&gpg.public_keys().unwrap()), [b_fpr]);

    let empty = GpgHome::new();
    let mut gpg = Gpg::with_home(empty.path()).unwrap();
    assert!(gpg.public_keys().unwrap().is_empty());
    assert!(gpg.secret_keys().unwrap().is_empty());
}

#[test]
fn lists_keys_and_subkeys_in_temp_gnupghome() {
    let home = GpgHome::new();
    let uid = "Alice Example (test fixture) <alice@example.org>";
    let fpr = home.gen_key(uid);
    home.gpg(&[
        "--quick-gen-key",
        "Rsa Example <rsa@example.org>",
        "rsa3072",
        "sign",
        "never",
    ]);

    let mut gpg = Gpg::with_home(home.path()).unwrap();
    let keys = gpg.public_keys().unwrap();
    assert_eq!(keys.len(), 2);
    let key = keys.iter().find(|k| k.fingerprint.as_str() == fpr).unwrap();
    let colons = home.colons(&["--list-keys", &fpr]);

    assert_eq!(key.algo, KeyAlgo::Ed25519);
    assert_eq!(key.user_ids.len(), 1);
    assert_eq!(key.user_ids[0].uid, uid);
    assert_eq!(key.user_ids[0].email.as_deref(), Some("alice@example.org"));
    assert!(key.can_encrypt && key.can_sign);
    assert!(!key.revoked && !key.expired && !key.disabled && !key.invalid);

    // Primary and subkey match `gpg --with-colons`: fingerprint, created,
    // expiry (fields 6 and 7, seconds since the epoch).
    let pub_rows: Vec<_> = colons
        .iter()
        .filter(|f| f[0] == "pub" || f[0] == "sub")
        .collect();
    let fpr_rows: Vec<_> = colons.iter().filter(|f| f[0] == "fpr").collect();
    assert_eq!(key.subkeys.len(), 2);
    for (i, sub) in key.subkeys.iter().enumerate() {
        let secs = |s: &str| SystemTime::UNIX_EPOCH + Duration::from_secs(s.parse().unwrap());
        assert_eq!(sub.fingerprint.as_str(), fpr_rows[i][9]);
        assert_eq!(sub.created, Some(secs(&pub_rows[i][5])));
        assert_eq!(sub.expiry, Some(secs(&pub_rows[i][6])));
    }
    assert_eq!(key.created, key.subkeys[0].created);
    assert_eq!(key.expiry, key.subkeys[0].expiry);
    let (primary, enc) = (&key.subkeys[0], &key.subkeys[1]);
    assert!(primary.can_sign && primary.can_certify && !primary.can_encrypt);
    assert_eq!(enc.algo, KeyAlgo::Cv25519);
    assert!(enc.can_encrypt && !enc.can_sign);

    let rsa = keys.iter().find(|k| k.fingerprint.as_str() != fpr).unwrap();
    assert_eq!(rsa.algo, KeyAlgo::Rsa(3072));
    assert_eq!(rsa.expiry, None);
    assert_eq!(rsa.subkeys.len(), 1);
    assert!(!rsa.can_encrypt && rsa.can_sign);
}

#[test]
fn openpgp_fingerprint_matches_gpg() {
    let source = GpgHome::new();
    let a = source.gen_key("A Example (test fixture) <a@example.org>");
    let b = source.gen_key("B Example (test fixture) <b@example.org>");
    let armored = source.export(&[&a, &b]);
    let binary = source.gpg(&["--export", &a, &b]);

    let colons = source.colons(&["--list-keys"]);
    let gpg_primary: Vec<String> = colons
        .windows(2)
        .filter(|w| w[0][0] == "pub" && w[1][0] == "fpr")
        .map(|w| w[1][9].clone())
        .collect();
    assert_eq!(gpg_primary.len(), 2);

    // Parse without import, in an empty home.
    let empty = GpgHome::new();
    let mut gpg = Gpg::with_home(empty.path()).unwrap();
    for bytes in [&armored, &binary] {
        let keys = gpg.read_keys(bytes).unwrap();
        let mut got = fprs(&keys);
        let mut want = gpg_primary.clone();
        got.sort();
        want.sort();
        assert_eq!(got, want);
        assert!(
            keys.iter()
                .all(|k| matches!(k.fingerprint, Fingerprint::OpenPgp(_)))
        );
    }
    assert!(gpg.public_keys().unwrap().is_empty(), "nothing imported");
}

#[test]
fn read_keys_refuses_oversized_input() {
    let empty = GpgHome::new();
    let mut gpg = Gpg::with_home(empty.path()).unwrap();
    let big = vec![b'a'; MAX_KEY_INPUT + 1];
    assert!(matches!(
        gpg.read_keys(&big),
        Err(GpgError::TooLarge { .. })
    ));
}

fn default_fpr(home: &GpgHome) -> Option<String> {
    Gpg::with_home(home.path())
        .unwrap()
        .default_secret_key()
        .unwrap()
        .map(|k| k.fingerprint.to_string())
}

fn write_conf(home: &GpgHome, name: &str, text: &str) {
    std::fs::write(home.path().join(name), text).unwrap();
}

#[test]
fn default_secret_key_is_first_secret_key_without_conf() {
    let home = GpgHome::new();
    let first = home.gen_key("First Example (test fixture) <first@example.org>");
    home.gen_key("Second Example (test fixture) <second@example.org>");
    let key = Gpg::with_home(home.path())
        .unwrap()
        .default_secret_key()
        .unwrap()
        .unwrap();
    assert_eq!(key.fingerprint.as_str(), first);
    assert!(key.can_encrypt);

    let empty = GpgHome::new();
    assert_eq!(default_fpr(&empty), None);
}

#[test]
fn default_secret_key_without_conf_skips_unusable_keys() {
    let home = GpgHome::new();
    home.gen_expired("Expired Example (test fixture) <expired@example.org>");
    let revoked = home.gen_key("Revoked Example (test fixture) <revoked@example.org>");
    home.revoke(&revoked);
    home.gpg(&[
        "--quick-gen-key",
        "Certify Only <certify@example.org>",
        "ed25519",
        "cert",
        "1y",
    ]);
    let good = home.gen_key("Good Example (test fixture) <good@example.org>");
    assert_eq!(default_fpr(&home).as_deref(), Some(good.as_str()));
}

#[test]
fn default_key_last_value_wins() {
    let home = GpgHome::new();
    let first = home.gen_key("First Example (test fixture) <first@example.org>");
    let second = home.gen_sign_only("Second Example (test fixture) <second@example.org>");
    write_conf(
        &home,
        "gpg.conf",
        &format!("default-key {second}\ndefault-key {first}\n"),
    );
    assert_eq!(default_fpr(&home).as_deref(), Some(first.as_str()));
    write_conf(
        &home,
        "gpg.conf",
        &format!("default-key {first}\ndefault-key {second}\n"),
    );
    let key = Gpg::with_home(home.path())
        .unwrap()
        .default_secret_key()
        .unwrap()
        .unwrap();
    assert_eq!(key.fingerprint.as_str(), second);
    assert!(!key.can_encrypt, "sign-only key cannot encrypt");
}

#[test]
fn default_key_value_forms() {
    let home = GpgHome::new();
    home.gen_key("First Example (test fixture) <first@example.org>");
    let second = home.gen_key("Second Example (test fixture) <second@example.org>");
    let long_id = &second[second.len() - 16..];
    for value in [
        format!("{second}!"),
        long_id.to_string(),
        format!("0x{long_id}"),
        "second@example.org".to_string(),
        "<second@example.org>".to_string(),
        "\"second@example.org\"".to_string(),
    ] {
        write_conf(&home, "gpg.conf", &format!("  default-key\t{value}  \n"));
        assert_eq!(
            default_fpr(&home).as_deref(),
            Some(second.as_str()),
            "{value}"
        );
    }
}

#[test]
fn default_key_skips_expired_and_revoked_values() {
    let home = GpgHome::new();
    let first = home.gen_key("First Example (test fixture) <first@example.org>");
    let expired = home.gen_expired("Expired Example (test fixture) <expired@example.org>");
    let revoked = home.gen_key("Revoked Example (test fixture) <revoked@example.org>");
    home.revoke(&revoked);
    let second = home.gen_key("Second Example (test fixture) <second@example.org>");
    write_conf(
        &home,
        "gpg.conf",
        &format!("default-key {second}\ndefault-key {expired}\ndefault-key {revoked}\n"),
    );
    assert_eq!(default_fpr(&home).as_deref(), Some(second.as_str()));
    assert_ne!(first, second);
}

#[test]
fn default_key_without_usable_value_falls_back_to_first_usable_key() {
    let home = GpgHome::new();
    home.gen_expired("Expired Example (test fixture) <expired@example.org>");
    let first = home.gen_key("First Example (test fixture) <first@example.org>");
    let other = GpgHome::new();
    let public_only = other.gen_key("Public Example (test fixture) <public@example.org>");
    let export = home.path().join("public.asc");
    std::fs::write(&export, other.export(&[&public_only])).unwrap();
    home.gpg(&["--import", export.to_str().unwrap()]);
    for conf in [
        format!("default-key {public_only}\n"),
        "default-key 0000000000000000000000000000000000000000\n".to_string(),
        format!("default-key {first} # comment\n"),
        "default-key no-such-user@example.org\n".to_string(),
    ] {
        write_conf(&home, "gpg.conf", &conf);
        assert_eq!(
            default_fpr(&home).as_deref(),
            Some(first.as_str()),
            "{conf}"
        );
    }
}

#[test]
fn default_key_reads_versioned_conf_first() {
    let home = GpgHome::new();
    let first = home.gen_key("First Example (test fixture) <first@example.org>");
    let second = home.gen_key("Second Example (test fixture) <second@example.org>");
    write_conf(&home, "gpg.conf", &format!("default-key {first}\n"));
    write_conf(&home, "gpg.conf-2", &format!("default-key {second}\n"));
    assert_eq!(default_fpr(&home).as_deref(), Some(second.as_str()));
}

#[test]
fn default_key_conf_may_be_non_utf8() {
    let home = GpgHome::new();
    home.gen_key("First Example (test fixture) <first@example.org>");
    let second = home.gen_key("Second Example (test fixture) <second@example.org>");
    let mut conf = b"# caf\xe9\n".to_vec();
    conf.extend_from_slice(format!("default-key {second}\n").as_bytes());
    std::fs::write(home.path().join("gpg.conf"), conf).unwrap();
    assert_eq!(default_fpr(&home).as_deref(), Some(second.as_str()));
}
