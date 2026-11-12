//! Pasted key source: OpenPGP armored and binary, SSH lines, age lines,
//! junk and oversized input. No network, no keyring.

use std::path::PathBuf;
use std::time::Duration;

use identity_core::{Fingerprint, Gpg, KeyKind};
use resolver::{
    KeyBytes, KeySource, PastedSource, Query, RejectReason, SourceError, SourceKind, Unusable,
    parse_query,
};
use tokio::time::Instant;

fn fixture(rel: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests")
        .join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn fpr_of(rel: &str) -> Fingerprint {
    Gpg::split_keys(&fixture(rel)).unwrap()[0]
        .0
        .fingerprint
        .clone()
}

async fn paste(bytes: Vec<u8>) -> Result<resolver::Found, SourceError> {
    PastedSource::new()
        .lookup(
            &Query::Pasted(bytes),
            None,
            Instant::now() + Duration::from_secs(10),
        )
        .await
}

#[test]
fn accepts_only_pasted() {
    let s = PastedSource::new();
    assert_eq!(s.kind(), SourceKind::Pasted);
    assert!(s.accepts(&Query::pasted(b"x".to_vec()).unwrap()));
    assert!(!s.accepts(&parse_query("alice@example.org").unwrap()));
}

#[tokio::test]
async fn armored_openpgp() {
    let found = paste(fixture("fixtures/openpgp/alice.asc")).await.unwrap();
    assert_eq!(found.keys.len(), 1);
    let k = &found.keys[0];
    assert_eq!(k.fingerprint(), fpr_of("fixtures/openpgp/alice.asc"));
    assert_eq!(k.usable, Ok(()));
    assert_eq!(k.source.kind, SourceKind::Pasted);
    assert_eq!(k.source.location, "pasted");
    assert!(!k.shown_user_ids.is_empty());
    let KeyBytes::OpenPgp(bytes) = &k.bytes else {
        panic!("not OpenPGP");
    };
    assert!(bytes[0] & 0x80 != 0);
}

#[tokio::test]
async fn binary_openpgp_with_two_keys() {
    let found = paste(fixture("fixtures/openpgp/alice-mallory.gpg"))
        .await
        .unwrap();
    assert_eq!(found.keys.len(), 2);
    assert!(found.rejected.is_empty());
    for k in &found.keys {
        let KeyBytes::OpenPgp(bytes) = &k.bytes else {
            panic!("not OpenPGP");
        };
        let one = Gpg::split_keys(bytes).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].0.fingerprint, k.fingerprint());
    }
}

#[tokio::test]
async fn revoked_user_id_not_shown() {
    let found = paste(fixture("fixtures/openpgp/rita-revoked-uid.asc"))
        .await
        .unwrap();
    let shown = &found.keys[0].shown_user_ids;
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].email.as_deref(), Some("rita@example.net"));
}

#[tokio::test]
async fn expired_openpgp_key_has_note() {
    let found = paste(fixture("fixtures/openpgp/eve-expired.asc"))
        .await
        .unwrap();
    assert_eq!(found.keys[0].usable, Err(Unusable::Expired));
}

#[tokio::test]
async fn ssh_lines_with_skip_notes() {
    let found = paste(fixture("fixtures/ssh/multi.keys")).await.unwrap();
    assert_eq!(found.keys.len(), 6);
    let notes: Vec<_> = found.keys.iter().map(|k| k.usable.clone()).collect();
    assert_eq!(
        notes,
        [
            Ok(()),
            Ok(()),
            Err(Unusable::EcdsaNotAge),
            Err(Unusable::SkKey),
            Err(Unusable::RsaSize(8192)),
            Err(Unusable::RsaSize(1024)),
        ]
    );
    for k in &found.keys {
        assert_eq!(k.key.kind(), KeyKind::Ssh);
        let KeyBytes::Ssh(line) = &k.bytes else {
            panic!("not SSH");
        };
        assert_eq!(line.split(' ').count(), 2, "comment kept");
        assert!(!line.contains("example.org"));
    }
}

#[tokio::test]
async fn age_line() {
    let line = fixture("fixtures/age/dave.pub");
    let found = paste(line.clone()).await.unwrap();
    assert_eq!(found.keys.len(), 1);
    let k = &found.keys[0];
    assert_eq!(k.key.kind(), KeyKind::Age);
    assert_eq!(k.usable, Ok(()));
    let text = String::from_utf8(line).unwrap();
    let want = text.lines().find(|l| l.starts_with("age1")).unwrap().trim();
    assert_eq!(k.bytes, KeyBytes::Age(want.to_string()));
}

#[tokio::test]
async fn junk_is_malformed() {
    for body in [
        fixture("mock-sources/junk.bin"),
        fixture("mock-sources/not-found.html"),
        fixture("mock-sources/broken-armor.asc"),
        fixture("mock-sources/github-empty.gpg"),
        b"# only a comment\n\n".to_vec(),
        b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINotAKey\n".to_vec(),
    ] {
        let err = paste(body).await.unwrap_err();
        assert!(matches!(err, SourceError::Malformed(_)), "{err:?}");
    }
}

#[tokio::test]
async fn bad_line_names_its_number_not_its_text() {
    let mut body = fixture("fixtures/age/dave.pub");
    body.extend_from_slice(b"\nnot-a-key SECRETLOOKINGTEXT\n");
    let err = paste(body).await.unwrap_err();
    let SourceError::Malformed(msg) = &err else {
        panic!("{err:?}");
    };
    assert!(msg.starts_with("line "), "{msg}");
    assert!(!msg.contains("SECRETLOOKINGTEXT"));
}

#[tokio::test]
async fn private_key_is_refused() {
    let err = paste(fixture("fixtures/ssh/erin_ed25519"))
        .await
        .unwrap_err();
    assert!(matches!(err, SourceError::Malformed(_)), "{err:?}");
    let err = paste(fixture("fixtures/age/dave.txt")).await.unwrap_err();
    assert!(matches!(err, SourceError::Malformed(_)), "{err:?}");
}

#[tokio::test]
async fn over_1_mb_is_refused() {
    let mut big = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n".to_vec();
    big.resize(1_000_001, b'A');
    assert_eq!(paste(big).await.unwrap_err(), SourceError::TooLarge);
    let ssh = vec![b'a'; 1_000_001];
    assert_eq!(paste(ssh).await.unwrap_err(), SourceError::TooLarge);
}

#[tokio::test]
async fn too_many_keys_are_rejected() {
    let alice = fixture("fixtures/openpgp/alice.gpg");
    let blob: Vec<u8> = (0..=identity_core::MAX_SPLIT_KEYS)
        .flat_map(|_| alice.clone())
        .collect();
    let found = paste(blob).await.unwrap();
    assert!(found.keys.is_empty());
    assert_eq!(found.rejected[0].reason, RejectReason::TooManyKeys);
}
