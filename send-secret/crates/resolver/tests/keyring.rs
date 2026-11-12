//! GnuPG keyring source against a temp GNUPGHOME with fixture keys.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use identity_core::{Fingerprint, Gpg, OpenPgpBackend};
use resolver::{
    KeyBytes, KeySource, KeyringSource, Query, SourceError, SourceKind, Unusable, parse_query,
};
use tempfile::TempDir;
use tokio::time::Instant;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/openpgp")
        .join(name)
}

fn fpr_of(name: &str) -> Fingerprint {
    let keys = Gpg::split_keys(&std::fs::read(fixture(name)).unwrap()).unwrap();
    keys[0].0.fingerprint.clone()
}

/// A temp GNUPGHOME (0700) with the given fixture keys imported.
fn home_with(names: &[&str], conf: &str) -> TempDir {
    let dir = tempfile::Builder::new().prefix("kr").tempdir().unwrap();
    std::fs::write(dir.path().join("gpg.conf"), format!("no-autostart\n{conf}")).unwrap();
    for name in names {
        let out = Command::new("gpg")
            .arg("--homedir")
            .arg(dir.path())
            .args(["--batch", "--quiet", "--import"])
            .arg(fixture(name))
            .output()
            .unwrap();
        assert!(out.status.success(), "import {name}: {out:?}");
    }
    dir
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

async fn lookup(home: &Path, q: &str) -> Result<resolver::Found, SourceError> {
    KeyringSource::with_home(home)
        .lookup(&parse_query(q).unwrap(), None, soon())
        .await
}

const ALL: &[&str] = &[
    "alice.asc",
    "mallory-other.asc",
    "olivia-two-uids.asc",
    "rita-revoked-uid.asc",
    "eve-expired.asc",
];

#[test]
fn accepts_email_and_fingerprint() {
    let s = KeyringSource::with_home("/nonexistent");
    assert_eq!(s.kind(), SourceKind::Keyring);
    assert!(s.accepts(&parse_query("alice@example.org").unwrap()));
    assert!(s.accepts(&parse_query(fpr_of("alice.asc").as_str()).unwrap()));
    assert!(!s.accepts(&parse_query("github:alice").unwrap()));
    assert!(!s.accepts(&parse_query("Alice").unwrap()));
    assert!(!s.accepts(&Query::pasted(b"x".to_vec()).unwrap()));
}

#[tokio::test]
async fn email_match_gives_one_key_with_bytes() {
    let home = home_with(ALL, "");
    let found = lookup(home.path(), "Alice@Example.org").await.unwrap();
    assert_eq!(found.keys.len(), 1);
    let k = &found.keys[0];
    assert_eq!(k.fingerprint(), fpr_of("alice.asc"));
    assert_eq!(k.usable, Ok(()));
    assert_eq!(k.source.kind, SourceKind::Keyring);
    assert_eq!(k.source.location, home.path().display().to_string());
    assert!(!k.shown_user_ids.is_empty());
    let KeyBytes::OpenPgp(bytes) = &k.bytes else {
        panic!("not OpenPGP");
    };
    let one = Gpg::split_keys(bytes).unwrap();
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].0.fingerprint, k.fingerprint());
}

#[tokio::test]
async fn bytes_are_binary_even_with_armor_in_gpg_conf() {
    let home = home_with(&["alice.asc"], "armor\n");
    let found = lookup(home.path(), "alice@example.org").await.unwrap();
    let KeyBytes::OpenPgp(bytes) = &found.keys[0].bytes else {
        panic!("not OpenPGP");
    };
    assert!(bytes[0] & 0x80 != 0, "not binary");
}

#[tokio::test]
async fn fingerprint_match() {
    let home = home_with(ALL, "");
    let fpr = fpr_of("olivia-two-uids.asc");
    let lower = fpr.as_str().to_ascii_lowercase();
    let found = lookup(home.path(), &lower).await.unwrap();
    assert_eq!(found.keys.len(), 1);
    assert_eq!(found.keys[0].fingerprint(), fpr);
    assert_eq!(found.keys[0].shown_user_ids.len(), 2);
}

#[tokio::test]
async fn revoked_user_id_is_not_matched() {
    let home = home_with(ALL, "");
    assert_eq!(
        lookup(home.path(), "rita@example.org").await.unwrap_err(),
        SourceError::NotFound
    );
    let found = lookup(home.path(), "rita@example.net").await.unwrap();
    assert_eq!(found.keys[0].fingerprint(), fpr_of("rita-revoked-uid.asc"));
    let shown = &found.keys[0].shown_user_ids;
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].email.as_deref(), Some("rita@example.net"));
}

#[tokio::test]
async fn second_user_id_matches() {
    let home = home_with(ALL, "");
    let found = lookup(home.path(), "olivia@example.net").await.unwrap();
    assert_eq!(found.keys[0].fingerprint(), fpr_of("olivia-two-uids.asc"));
}

#[tokio::test]
async fn expired_key_is_kept_with_note() {
    let home = home_with(ALL, "");
    let found = lookup(home.path(), "eve@example.org").await.unwrap();
    assert_eq!(found.keys.len(), 1);
    assert_eq!(found.keys[0].usable, Err(Unusable::Expired));
}

#[tokio::test]
async fn two_keys_for_one_email() {
    let home = home_with(&["alice.asc", "alice-new.asc"], "");
    let found = lookup(home.path(), "alice@example.org").await.unwrap();
    let mut got: Vec<_> = found.keys.iter().map(|k| k.fingerprint()).collect();
    let mut want = vec![fpr_of("alice.asc"), fpr_of("alice-new.asc")];
    got.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    want.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    assert_eq!(got, want);
}

#[tokio::test]
async fn no_match_is_not_found() {
    let home = home_with(ALL, "");
    assert_eq!(
        lookup(home.path(), "nobody@example.org").await.unwrap_err(),
        SourceError::NotFound
    );
    let empty = home_with(&[], "");
    assert_eq!(
        lookup(empty.path(), "alice@example.org").await.unwrap_err(),
        SourceError::NotFound
    );
}

#[tokio::test]
async fn keyring_is_not_changed() {
    let home = home_with(&["alice.asc"], "");
    let before = Gpg::with_home(home.path()).unwrap().public_keys().unwrap();
    lookup(home.path(), "alice@example.org").await.unwrap();
    let after = Gpg::with_home(home.path()).unwrap().public_keys().unwrap();
    assert_eq!(before, after);
    assert_eq!(before.len(), 1);
}

#[tokio::test]
async fn past_deadline_is_timeout() {
    let home = home_with(&["alice.asc"], "");
    let err = KeyringSource::with_home(home.path())
        .lookup(
            &parse_query("alice@example.org").unwrap(),
            None,
            Instant::now(),
        )
        .await
        .unwrap_err();
    assert_eq!(err, SourceError::Timeout);
}
