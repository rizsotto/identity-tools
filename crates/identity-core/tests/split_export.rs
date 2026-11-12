//! `UserId::has_email`, `Gpg::export_key` and `Gpg::split_keys` (Send
//! Secret M2 T03). Every test uses its own temp GnuPG home.

mod common;

use common::GpgHome;
use identity_core::{
    Gpg, GpgError, MAX_KEY_INPUT, MAX_SPLIT_SUBKEYS, MAX_SPLIT_USER_IDS, OpenPgpBackend, UserId,
};

fn uid(uid: &str, email: Option<&str>) -> UserId {
    UserId {
        uid: uid.to_string(),
        name: None,
        email: email.map(str::to_string),
        revoked: false,
        invalid: false,
    }
}

#[test]
fn has_email_cases() {
    let u = uid("Alice <alice@example.org>", Some("alice@example.org"));
    assert!(u.has_email("alice@example.org"));
    assert!(u.has_email("Alice@Example.ORG"));
    assert!(u.has_email("<alice@example.org>"));
    assert!(!u.has_email("alice@example.net"));
    assert!(!u.has_email("lice@example.org"));
    assert!(!u.has_email("alice@example.org.evil"));
    assert!(!u.has_email(""));

    // Only ASCII is folded: non-ASCII must match exactly.
    let u = uid("Ü <Ünï@example.org>", Some("Ünï@example.org"));
    assert!(u.has_email("Ünï@EXAMPLE.org"));
    assert!(!u.has_email("ünï@example.org"));

    let revoked = UserId {
        revoked: true,
        ..uid("A <alice@example.org>", Some("alice@example.org"))
    };
    assert!(!revoked.has_email("alice@example.org"));
    let invalid = UserId {
        invalid: true,
        ..uid("A <alice@example.org>", Some("alice@example.org"))
    };
    assert!(!invalid.has_email("alice@example.org"));

    // No email field: a user ID that is only an address, bare or in <>.
    assert!(uid("alice@example.org", None).has_email("alice@example.org"));
    assert!(uid("<alice@example.org>", Some("")).has_email("ALICE@example.org"));
    assert!(!uid("Alice Example", None).has_email("alice@example.org"));
    assert!(!uid("", None).has_email(""));
}

#[test]
fn has_email_on_keys_from_gpg() {
    let home = GpgHome::new();
    let fpr = home.gen_key("Bob Example (test fixture) <bob@example.org>");
    home.gpg(&["--quick-add-uid", &fpr, "<only@example.org>"]);
    home.gpg(&["--quick-add-uid", &fpr, "bare@example.org"]);
    home.gpg(&["--quick-add-uid", &fpr, "Gone <gone@example.org>"]);
    home.gpg(&["--quick-revoke-uid", &fpr, "Gone <gone@example.org>"]);
    let mut gpg = Gpg::with_home(home.path()).unwrap();
    let key = gpg.public_keys().unwrap().remove(0);
    let has = |e: &str| key.user_ids.iter().any(|u| u.has_email(e));
    assert!(has("BOB@example.org"));
    assert!(has("only@example.org"));
    assert!(has("bare@example.org"));
    assert!(!has("gone@example.org"), "revoked user ID");
}

#[test]
fn export_key_gives_one_key() {
    let home = GpgHome::new();
    let a = home.gen_key("A Example (test fixture) <a@example.org>");
    let b = home.gen_key("B Example (test fixture) <b@example.org>");
    let mut gpg = Gpg::with_home(home.path()).unwrap();
    for fpr in [&a, &b] {
        let bytes = gpg.export_key(&fpr.to_lowercase()).unwrap();
        assert_ne!(bytes[0] & 0x80, 0, "binary");
        let keys = gpg.read_keys(&bytes).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].fingerprint.as_str(), fpr);
    }
    assert!(matches!(
        gpg.export_key(&"0".repeat(40)),
        Err(GpgError::KeyNotFound)
    ));
    for bad in [
        "",
        "a@example.org",
        &a[..16],
        &format!("{a}0"),
        &format!("{}Z", &a[1..]),
    ] {
        assert!(
            matches!(gpg.export_key(bad), Err(GpgError::BadFingerprint)),
            "{bad}"
        );
    }
}

#[test]
fn export_key_never_exports_secret_parts() {
    let home = GpgHome::new();
    let a = home.gen_key("A Example (test fixture) <a@example.org>");
    let mut gpg = Gpg::with_home(home.path()).unwrap();
    let bytes = gpg.export_key(&a).unwrap();
    let other = GpgHome::new();
    std::fs::write(other.path().join("k.gpg"), &bytes).unwrap();
    other.gpg(&["--import", other.path().join("k.gpg").to_str().unwrap()]);
    let mut gpg = Gpg::with_home(other.path()).unwrap();
    assert!(gpg.secret_keys().unwrap().is_empty());
}

#[test]
fn split_keys_concatenated_two_keys() {
    let home = GpgHome::new();
    let a = home.gen_key("A Example (test fixture) <a@example.org>");
    let b = home.gen_key("B Example (test fixture) <b@example.org>");
    let armored = home.export(&[&a, &b]);
    let mut binary = home.gpg(&["--export", &a]);
    binary.extend(home.gpg(&["--export", &b]));
    let mut reader = Gpg::with_home(home.path()).unwrap();
    for blob in [armored, binary] {
        let parts = Gpg::split_keys(&blob).unwrap();
        let fprs: Vec<&str> = parts.iter().map(|(k, _)| k.fingerprint.as_str()).collect();
        assert_eq!(fprs.len(), 2);
        assert!(fprs.contains(&a.as_str()) && fprs.contains(&b.as_str()));
        for (key, bytes) in &parts {
            let read = reader.read_keys(bytes).unwrap();
            assert_eq!(read.len(), 1, "one key per blob");
            assert_eq!(read[0].fingerprint, key.fingerprint);
        }
    }
}

#[test]
fn split_keys_one_key_and_no_key() {
    let home = GpgHome::new();
    let a = home.gen_key("A Example (test fixture) <a@example.org>");
    let parts = Gpg::split_keys(&home.export(&[&a])).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].0.fingerprint.as_str(), a);
    assert!(parts[0].0.can_encrypt);

    // GitHub's `.gpg` answer for a user with no key (Send Secret SPEC 15).
    let empty = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
                  Note: This user hasn't uploaded any GPG keys.\n\n\n=twTO\n\
                  -----END PGP PUBLIC KEY BLOCK-----";
    assert!(Gpg::split_keys(empty).unwrap().is_empty());
}

#[test]
fn split_keys_refuses_too_large_and_too_many() {
    assert!(matches!(
        Gpg::split_keys(&vec![b'a'; MAX_KEY_INPUT + 1]),
        Err(GpgError::TooLarge { .. })
    ));

    let home = GpgHome::new();
    let fprs: Vec<String> = (0..33)
        .map(|i| home.gen_sign_only(&format!("K{i} Example (test fixture) <k{i}@example.org>")))
        .collect();
    let refs: Vec<&str> = fprs.iter().map(String::as_str).collect();
    assert!(matches!(
        Gpg::split_keys(&home.export(&refs)),
        Err(GpgError::TooManyKeys { limit: 32 })
    ));
    assert_eq!(
        Gpg::split_keys(&home.export(&refs[..32])).unwrap().len(),
        32
    );
}

#[test]
fn split_keys_junk_gives_no_key() {
    for junk in [
        &b"not a key"[..],
        b"<!DOCTYPE html><html></html>",
        &[0u8; 64],
    ] {
        match Gpg::split_keys(junk) {
            Ok(keys) => assert!(keys.is_empty()),
            Err(e) => assert!(matches!(e, GpgError::Gpgme(_))),
        }
    }
}

#[test]
fn export_key_is_binary_even_with_armor_in_gpg_conf() {
    let home = GpgHome::new();
    let a = home.gen_key("A Example (test fixture) <a@example.org>");
    std::fs::write(home.path().join("gpg.conf"), "armor\n").unwrap();
    let mut gpg = Gpg::with_home(home.path()).unwrap();
    let bytes = gpg.export_key(&a).unwrap();
    assert_ne!(bytes[0] & 0x80, 0, "binary, not armor");
    let keys = gpg.read_keys(&bytes).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].fingerprint.as_str(), a);
}

#[test]
fn split_keys_refuses_too_many_user_ids() {
    let home = GpgHome::new();
    let fpr = home.gen_sign_only("U0 Example (test fixture) <u0@example.org>");
    for i in 1..MAX_SPLIT_USER_IDS {
        home.gpg(&["--quick-add-uid", &fpr, &format!("U{i} <u{i}@example.org>")]);
    }
    assert_eq!(Gpg::split_keys(&home.export(&[&fpr])).unwrap().len(), 1);
    let n = MAX_SPLIT_USER_IDS;
    home.gpg(&["--quick-add-uid", &fpr, &format!("U{n} <u{n}@example.org>")]);
    assert!(matches!(
        Gpg::split_keys(&home.export(&[&fpr])),
        Err(GpgError::TooComplex { .. })
    ));
}

#[test]
fn split_keys_refuses_too_many_subkeys() {
    let home = GpgHome::new();
    let fpr = home.gen_sign_only("S Example (test fixture) <s@example.org>");
    for _ in 0..MAX_SPLIT_SUBKEYS {
        home.gpg(&["--quick-add-key", &fpr, "cv25519", "encr", "1y"]);
    }
    assert_eq!(Gpg::split_keys(&home.export(&[&fpr])).unwrap().len(), 1);
    home.gpg(&["--quick-add-key", &fpr, "cv25519", "encr", "1y"]);
    assert!(matches!(
        Gpg::split_keys(&home.export(&[&fpr])),
        Err(GpgError::TooComplex { .. })
    ));
}
