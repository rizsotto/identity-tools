//! Encrypt to a key file without importing it (SPEC 15, F3). Every test
//! uses its own temp GnuPG homes. `encrypt_sign_to` is the model for the
//! one `unsafe` call the OpenPGP backend (T08b) makes.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use crypto::{RecipientFile, RecipientFileError};
use gpgme::{Context, Data, EncryptFlags, Protocol};
use identity_core::{Gpg, GpgError, MAX_KEY_INPUT};
use tempfile::TempDir;

/// A throwaway GnuPG home. Kills its agent on drop.
struct GpgHome {
    dir: TempDir,
}

impl GpgHome {
    fn new() -> Self {
        // Short path under /tmp: the agent socket path has a length limit.
        let dir = tempfile::Builder::new()
            .prefix("ss-gpg")
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

    fn fpr(&self, uid: &str) -> String {
        String::from_utf8(self.gpg(&["--with-colons", "--list-keys", uid]))
            .unwrap()
            .lines()
            .find(|l| l.starts_with("fpr:"))
            .and_then(|l| l.split(':').nth(9))
            .unwrap()
            .to_string()
    }

    /// Ed25519 primary key plus a Cv25519 encryption subkey that expires
    /// after `enc_expiry` (a gpg expiry string).
    fn gen_key_with(&self, uid: &str, enc_expiry: &str) -> String {
        self.gpg(&["--quick-gen-key", uid, "ed25519", "sign", "1y"]);
        let fpr = self.fpr(uid);
        self.gpg(&["--quick-add-key", &fpr, "cv25519", "encr", enc_expiry]);
        fpr
    }

    fn gen_key(&self, uid: &str) -> String {
        self.gen_key_with(uid, "1y")
    }

    fn export(&self, fprs: &[&str]) -> Vec<u8> {
        let mut args = vec!["--armor", "--export"];
        args.extend_from_slice(fprs);
        self.gpg(&args)
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
        self.ctx()
            .keys()
            .unwrap()
            .map(|k| k.unwrap().fingerprint().unwrap().to_string())
            .collect()
    }

    fn gpgme(&self) -> Gpg {
        Gpg::with_home(self.path()).unwrap()
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
fn gpgme_encrypts_to_key_file_without_import() {
    let recipient = GpgHome::new();
    let recipient_fpr = recipient.gen_key("Recipient <recipient@example.org>");
    let key = recipient.export(&[&recipient_fpr]);

    let sender = GpgHome::new();
    let sender_fpr = sender.gen_key("Sender <sender@example.org>");

    let recp = RecipientFile::new(&mut sender.gpgme(), &key).unwrap();
    assert_eq!(recp.key().fingerprint.as_str(), recipient_fpr);
    let path = recp.path().to_path_buf();
    assert!(path.is_absolute());
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);

    let cipher = encrypt_sign_to(&mut sender.ctx(), &recp, b"spike plaintext");
    assert!(!cipher.is_empty());
    drop(recp);
    assert!(!path.parent().unwrap().exists(), "temp dir deleted on drop");

    // The recipient key never entered the sender's keyring.
    assert_eq!(sender.public_fprs(), vec![sender_fpr]);

    // The recipient can decrypt it.
    let mut plain = Vec::new();
    recipient.ctx().decrypt(&cipher, &mut plain).unwrap();
    assert_eq!(plain, b"spike plaintext");
}

#[test]
fn key_bytes_must_hold_exactly_one_key() {
    let a = GpgHome::new();
    let a_fpr = a.gen_key("A <a@example.org>");
    let b_fpr = a.gen_key("B <b@example.org>");
    let two = a.export(&[&a_fpr, &b_fpr]);
    let sender = GpgHome::new();
    let mut gpg = sender.gpgme();
    for key in [&two[..], b"not a key", b""] {
        assert!(matches!(
            RecipientFile::new(&mut gpg, key),
            Err(RecipientFileError::NotOneKey | RecipientFileError::Gpg(GpgError::Gpgme(_)))
        ));
    }
    let big = vec![b'a'; MAX_KEY_INPUT + 1];
    assert!(matches!(
        RecipientFile::new(&mut gpg, &big),
        Err(RecipientFileError::Gpg(GpgError::TooLarge { .. }))
    ));
    assert!(sender.public_fprs().is_empty());
}

#[test]
fn one_key_plus_junk_block_is_refused() {
    let a = GpgHome::new();
    let fpr = a.gen_key("A <a@example.org>");
    let mut key = a.export(&[&fpr]);
    key.extend_from_slice(
        b"\n-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nbm90IGEga2V5\n=AAAA\n\
          -----END PGP PUBLIC KEY BLOCK-----\n",
    );
    let sender = GpgHome::new();
    let res = RecipientFile::new(&mut sender.gpgme(), &key);
    assert!(
        matches!(
            res,
            Err(RecipientFileError::NotOneKey | RecipientFileError::Gpg(GpgError::Gpgme(_)))
        ),
        "{res:?}"
    );
}

#[test]
fn key_without_encryption_subkey_is_refused() {
    let a = GpgHome::new();
    a.gpg(&[
        "--quick-gen-key",
        "Sign Only <sign@example.org>",
        "ed25519",
        "sign",
        "1y",
    ]);
    let key = a.export(&[&a.fpr("sign@example.org")]);
    let res = RecipientFile::new(&mut GpgHome::new().gpgme(), &key);
    assert!(
        matches!(res, Err(RecipientFileError::CannotEncrypt)),
        "{res:?}"
    );
}

#[test]
fn expired_encryption_subkey_is_refused() {
    let a = GpgHome::new();
    let fpr = a.gen_key_with("Expired Enc <expired@example.org>", "seconds=1");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let key = a.export(&[&fpr]);
    let res = RecipientFile::new(&mut GpgHome::new().gpgme(), &key);
    assert!(
        matches!(res, Err(RecipientFileError::CannotEncrypt)),
        "{res:?}"
    );
}

#[test]
fn revoked_key_is_refused() {
    let a = GpgHome::new();
    let fpr = a.gen_key("Revoked <revoked@example.org>");
    // gpg writes a revocation certificate at key generation; the leading
    // ':' guards it against an accidental import.
    let rev = std::fs::read_to_string(a.path().join("openpgp-revocs.d").join(format!("{fpr}.rev")))
        .unwrap()
        .replace(":-----BEGIN", "-----BEGIN");
    let rev_path = a.path().join("revoke.asc");
    std::fs::write(&rev_path, rev).unwrap();
    a.gpg(&["--import", rev_path.to_str().unwrap()]);
    let key = a.export(&[&fpr]);
    let res = RecipientFile::new(&mut GpgHome::new().gpgme(), &key);
    assert!(
        matches!(res, Err(RecipientFileError::CannotEncrypt)),
        "{res:?}"
    );
}
