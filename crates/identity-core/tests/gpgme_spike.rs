//! Spike (Key Steward M1 T01a, Send Secret M1 T02): does the `gpgme` crate
//! work against the system gpgme 2.0.x, and can it encrypt to a key file
//! without importing it? Results are in both SPECs, section 15. The
//! encrypt-to-key-file tests moved with `RecipientFile` to Send Secret's
//! `crypto` crate (`tests/recipient_file.rs`).

mod common;

use common::GpgHome;
use gpgme::{Context, EncryptFlags, Protocol};

fn ctx(home: &GpgHome) -> Context {
    let mut ctx = Context::from_protocol(Protocol::OpenPgp).unwrap();
    ctx.set_engine_home_dir(home.path().to_str().unwrap())
        .unwrap();
    ctx.set_pinentry_mode(gpgme::PinentryMode::Loopback)
        .unwrap();
    ctx
}

fn public_fprs(home: &GpgHome) -> Vec<String> {
    ctx(home)
        .keys()
        .unwrap()
        .map(|k| k.unwrap().fingerprint().unwrap().to_string())
        .collect()
}

#[test]
fn gpgme_lists_key_in_temp_home() {
    let home = GpgHome::new();
    let fpr = home.gen_key("Test User <test@example.org>");

    let mut ctx = ctx(&home);
    let keys: Vec<_> = ctx.keys().unwrap().map(Result::unwrap).collect();
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    assert_eq!(key.fingerprint().unwrap(), fpr);
    assert_eq!(
        key.user_ids().next().unwrap().email().unwrap(),
        "test@example.org"
    );
    assert_eq!(key.subkeys().count(), 2);
}

/// A key read with `read_keys` (keylist from data) is not usable as a
/// recipient in another home: gpgme passes it to gpg by fingerprint, and gpg
/// looks it up in the keyring.
#[test]
fn gpgme_read_keys_key_is_not_a_recipient_without_import() {
    let recipient = GpgHome::new();
    let recipient_fpr = recipient.gen_key("Recipient <recipient@example.org>");
    let armored = recipient.export(&[&recipient_fpr]);

    let sender = GpgHome::new();
    let mut ctx = ctx(&sender);
    let keys: Vec<_> = ctx
        .read_keys(&armored)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].fingerprint().unwrap(), recipient_fpr);

    let mut cipher = Vec::new();
    let res = ctx.encrypt_with_flags(&keys, &b"x"[..], &mut cipher, EncryptFlags::ALWAYS_TRUST);
    assert!(res.is_err());
    assert!(public_fprs(&sender).is_empty());
}
