//! Spike (Key Steward M1 T01a, Send Secret M1 T02): does the `gpgme` crate
//! work against the system gpgme 2.0.x, and can it encrypt to a key file
//! without importing it? Results are in both SPECs, section 15.

use std::ffi::CString;
use std::path::Path;
use std::process::Command;

use gpgme::{Context, Data, EncryptFlags, Protocol};
use tempfile::TempDir;

/// A throwaway GnuPG home. Kills its agent on drop.
struct GpgHome {
    dir: TempDir,
}

impl GpgHome {
    fn new() -> Self {
        // Short path under /tmp: the agent socket path has a length limit.
        let dir = tempfile::Builder::new()
            .prefix("ic-gpg")
            .tempdir_in("/tmp")
            .unwrap();
        GpgHome { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn gpg(&self, args: &[&str]) -> Vec<u8> {
        let out = Command::new("gpg")
            .arg("--homedir")
            .arg(self.path())
            .args(["--batch", "--quiet", "--pinentry-mode", "loopback"])
            .args(["--passphrase", ""])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "gpg {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    fn gen_key(&self, uid: &str) -> String {
        self.gpg(&["--quick-gen-key", uid, "ed25519", "sign", "1y"]);
        let colons = String::from_utf8(self.gpg(&["--with-colons", "--list-keys", uid])).unwrap();
        let fpr = colons
            .lines()
            .find(|l| l.starts_with("fpr:"))
            .and_then(|l| l.split(':').nth(9))
            .unwrap()
            .to_string();
        self.gpg(&["--quick-add-key", &fpr, "cv25519", "encr", "1y"]);
        fpr
    }

    fn ctx(&self) -> Context {
        let mut ctx = Context::from_protocol(Protocol::OpenPgp).unwrap();
        ctx.set_engine_home_dir(self.path().to_str().unwrap())
            .unwrap();
        ctx.set_pinentry_mode(gpgme::PinentryMode::Loopback)
            .unwrap();
        ctx
    }

    fn public_fprs(&self) -> Vec<String> {
        let mut ctx = self.ctx();
        ctx.keys()
            .unwrap()
            .map(|k| k.unwrap().fingerprint().unwrap().to_string())
            .collect()
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(self.path())
            .args(["--kill", "all"])
            .status();
    }
}

#[test]
fn gpgme_lists_key_in_temp_home() {
    let home = GpgHome::new();
    let fpr = home.gen_key("Test User <test@example.org>");

    let mut ctx = home.ctx();
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

/// Encrypt (and sign) in `sender`'s home to the key in `key_file`, through
/// `gpgme_op_encrypt_sign_ext` with the `--file` recipient prefix. The safe
/// `gpgme` crate has no wrapper for the `_ext` calls, so this uses
/// `gpgme-sys` directly.
fn encrypt_sign_to_file(sender: &GpgHome, key_file: &Path, plain: &[u8]) -> Vec<u8> {
    let ctx = sender.ctx();
    let plain = Data::from_bytes(plain).unwrap();
    let cipher = Data::new().unwrap();
    let recp = CString::new(format!("--file\n{}", key_file.display())).unwrap();
    let err = unsafe {
        gpgme_sys::gpgme_op_encrypt_sign_ext(
            ctx.as_raw(),
            std::ptr::null_mut(),
            recp.as_ptr(),
            EncryptFlags::empty().bits(),
            plain.as_raw(),
            cipher.as_raw(),
        )
    };
    assert_eq!(err, 0, "encrypt_sign_ext: {}", gpgme::Error::new(err));
    cipher.try_into_bytes().unwrap()
}

#[test]
fn gpgme_encrypts_to_key_file_without_import() {
    let recipient = GpgHome::new();
    let recipient_fpr = recipient.gen_key("Recipient <recipient@example.org>");
    let key_dir = TempDir::new().unwrap();
    let key_file = key_dir.path().join("recipient.asc");
    std::fs::write(
        &key_file,
        recipient.gpg(&["--armor", "--export", &recipient_fpr]),
    )
    .unwrap();

    let sender = GpgHome::new();
    let sender_fpr = sender.gen_key("Sender <sender@example.org>");

    let cipher = encrypt_sign_to_file(&sender, &key_file, b"spike plaintext");
    assert!(!cipher.is_empty());

    // The recipient key never entered the sender's keyring.
    assert_eq!(sender.public_fprs(), vec![sender_fpr]);

    // The recipient can decrypt it.
    let mut ctx = recipient.ctx();
    let mut plain = Vec::new();
    ctx.decrypt(&cipher, &mut plain).unwrap();
    assert_eq!(plain, b"spike plaintext");
}

/// A key read with `read_keys` (keylist from data) is not usable as a
/// recipient in another home: gpgme passes it to gpg by fingerprint, and gpg
/// looks it up in the keyring.
#[test]
fn gpgme_read_keys_key_is_not_a_recipient_without_import() {
    let recipient = GpgHome::new();
    let recipient_fpr = recipient.gen_key("Recipient <recipient@example.org>");
    let armored = recipient.gpg(&["--armor", "--export", &recipient_fpr]);

    let sender = GpgHome::new();
    let mut ctx = sender.ctx();
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
    assert!(sender.public_fprs().is_empty());
}
