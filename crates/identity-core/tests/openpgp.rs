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

#[test]
fn default_secret_key_follows_gpg_conf() {
    let home = GpgHome::new();
    let first = home.gen_key("First Example (test fixture) <first@example.org>");
    let second = home.gen_sign_only("Second Example (test fixture) <second@example.org>");

    let mut gpg = Gpg::with_home(home.path()).unwrap();
    let key = gpg.default_secret_key().unwrap().unwrap();
    assert_eq!(key.fingerprint.as_str(), first);
    assert!(key.can_encrypt);

    std::fs::write(
        home.path().join("gpg.conf"),
        format!("default-key {first}\ndefault-key {second}\n"),
    )
    .unwrap();
    let key = gpg.default_secret_key().unwrap().unwrap();
    assert_eq!(key.fingerprint.as_str(), second);
    assert!(!key.can_encrypt, "sign-only key cannot encrypt");

    std::fs::write(
        home.path().join("gpg.conf"),
        "default-key 0000000000000000000000000000000000000000\n",
    )
    .unwrap();
    assert!(gpg.default_secret_key().unwrap().is_none());

    let empty = GpgHome::new();
    let mut gpg = Gpg::with_home(empty.path()).unwrap();
    assert!(gpg.default_secret_key().unwrap().is_none());
}
