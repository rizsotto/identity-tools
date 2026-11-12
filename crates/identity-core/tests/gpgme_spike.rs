//! Spike (Key Steward M1 T01a, Send Secret M1 T02): does the `gpgme` crate
//! work against the system gpgme 2.0.x, and can it encrypt to a key file
//! without importing it? Results are in both SPECs, section 15. The key
//! file part now uses [`RecipientFile`]; `encrypt_sign_to` shows the one
//! `unsafe` call Send Secret's `crypto` crate makes.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::GpgHome;
use gpgme::{Context, Data, EncryptFlags, Protocol};
use identity_core::{Gpg, GpgError, MAX_KEY_INPUT, RecipientFile};

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

fn encrypt_sign_to(ctx: &mut Context, recp: &RecipientFile, plain: &[u8]) -> Vec<u8> {
    let plain = Data::from_bytes(plain).unwrap();
    let cipher = Data::new().unwrap();
    // SAFETY: `ctx`, `plain` and `cipher` are live gpgme objects owned by
    // safe wrappers. A null key array is allowed with a recipient string.
    // The string is a NUL-terminated C string that lives as long as `recp`.
    let err = unsafe {
        gpgme_sys::gpgme_op_encrypt_sign_ext(
            ctx.as_raw(),
            std::ptr::null_mut(),
            recp.gpgme_recipients().as_ptr(),
            EncryptFlags::empty().bits(),
            plain.as_raw(),
            cipher.as_raw(),
        )
    };
    assert_eq!(err, 0, "{}", gpgme::Error::new(err));
    cipher.try_into_bytes().unwrap()
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

#[test]
fn gpgme_encrypts_to_key_file_without_import() {
    let recipient = GpgHome::new();
    let recipient_fpr = recipient.gen_key("Recipient <recipient@example.org>");
    let key = recipient.export(&[&recipient_fpr]);

    let sender = GpgHome::new();
    let sender_fpr = sender.gen_key("Sender <sender@example.org>");

    let recp = RecipientFile::new(&mut Gpg::with_home(sender.path()).unwrap(), &key).unwrap();
    assert_eq!(recp.key().fingerprint.as_str(), recipient_fpr);
    let path = recp.path().to_path_buf();
    assert!(path.is_absolute());
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);

    let cipher = encrypt_sign_to(&mut ctx(&sender), &recp, b"spike plaintext");
    assert!(!cipher.is_empty());
    drop(recp);
    assert!(!path.parent().unwrap().exists(), "temp dir deleted on drop");

    // The recipient key never entered the sender's keyring.
    assert_eq!(public_fprs(&sender), vec![sender_fpr]);

    // The recipient can decrypt it.
    let mut plain = Vec::new();
    ctx(&recipient).decrypt(&cipher, &mut plain).unwrap();
    assert_eq!(plain, b"spike plaintext");
}

#[test]
fn key_bytes_must_hold_exactly_one_key() {
    let a = GpgHome::new();
    let a_fpr = a.gen_key("A <a@example.org>");
    let b_fpr = a.gen_key("B <b@example.org>");
    let two = a.export(&[&a_fpr, &b_fpr]);
    let sender = GpgHome::new();
    let mut gpg = Gpg::with_home(sender.path()).unwrap();
    for key in [&two[..], b"not a key", b""] {
        assert!(matches!(
            RecipientFile::new(&mut gpg, key),
            Err(GpgError::NotOneKey | GpgError::Gpgme(_))
        ));
    }
    let big = vec![b'a'; MAX_KEY_INPUT + 1];
    assert!(matches!(
        RecipientFile::new(&mut gpg, &big),
        Err(GpgError::TooLarge { .. })
    ));
    assert!(public_fprs(&sender).is_empty());
}

#[test]
fn key_without_encryption_subkey_is_refused() {
    let a = GpgHome::new();
    let fpr = a.gen_sign_only("Sign Only <sign@example.org>");
    let key = a.export(&[&fpr]);
    let sender = GpgHome::new();
    let mut gpg = Gpg::with_home(sender.path()).unwrap();
    assert!(matches!(
        RecipientFile::new(&mut gpg, &key),
        Err(GpgError::CannotEncrypt)
    ));
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
