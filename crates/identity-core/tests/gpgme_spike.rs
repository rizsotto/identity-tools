//! Spike (Key Steward M1 T01a, Send Secret M1 T02): does the `gpgme` crate
//! work against the system gpgme 2.0.x, and can it encrypt to a key file
//! without importing it? Results are in both SPECs, section 15.

use std::ffi::CString;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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

#[derive(Debug)]
enum RecipientFileError {
    TooLarge,
    NotOneKey,
    UnsafePath,
    Io,
    Gpgme(#[allow(dead_code)] gpgme::Error),
}

/// The F3 design: the caller hands over key bytes, never a path. We check
/// the size and that it is exactly one key, write it into a fresh 0700 dir
/// under a name we pick, and pass that absolute path with `--file`.
fn encrypt_sign_to_key_bytes(
    ctx: &mut Context,
    key: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>, RecipientFileError> {
    if key.len() > identity_core::MAX_KEY_INPUT {
        return Err(RecipientFileError::TooLarge);
    }
    let count = ctx
        .read_keys(key)
        .map_err(RecipientFileError::Gpgme)?
        .filter(Result::is_ok)
        .count();
    if count != 1 {
        return Err(RecipientFileError::NotOneKey);
    }

    let dir = tempfile::Builder::new()
        .prefix("ic-recp")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .map_err(|_| RecipientFileError::Io)?;
    let path = dir.path().join("recipient.pgp");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| f.write_all(key))
        .map_err(|_| RecipientFileError::Io)?;

    let recp = CString::new(format!("--file\n{}", checked_recipient_path(&path)?))
        .map_err(|_| RecipientFileError::UnsafePath)?;
    let plain = Data::from_bytes(plain).map_err(RecipientFileError::Gpgme)?;
    let cipher = Data::new().map_err(RecipientFileError::Gpgme)?;
    // The safe `gpgme` crate has no wrapper for the `_ext` calls.
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
    if err != 0 {
        return Err(RecipientFileError::Gpgme(gpgme::Error::new(err)));
    }
    cipher.try_into_bytes().ok_or(RecipientFileError::Io)
}

/// A path is safe in a gpgme recipient string only if it is absolute (so not
/// a gpg special file name like `-&3`), UTF-8, has no control characters (a
/// newline starts a new recipient or keyword line) and no leading or
/// trailing spaces (gpgme trims them).
fn checked_recipient_path(path: &Path) -> Result<&str, RecipientFileError> {
    let s = path.to_str().ok_or(RecipientFileError::UnsafePath)?;
    let ok = path.is_absolute()
        && s.starts_with('/')
        && !s.chars().any(char::is_control)
        && s.trim() == s;
    ok.then_some(s).ok_or(RecipientFileError::UnsafePath)
}

#[test]
fn gpgme_encrypts_to_key_file_without_import() {
    let recipient = GpgHome::new();
    let recipient_fpr = recipient.gen_key("Recipient <recipient@example.org>");
    let key = recipient.gpg(&["--armor", "--export", &recipient_fpr]);

    let sender = GpgHome::new();
    let sender_fpr = sender.gen_key("Sender <sender@example.org>");

    let cipher = encrypt_sign_to_key_bytes(&mut sender.ctx(), &key, b"spike plaintext").unwrap();
    assert!(!cipher.is_empty());

    // The recipient key never entered the sender's keyring.
    assert_eq!(sender.public_fprs(), vec![sender_fpr]);

    // The recipient can decrypt it.
    let mut ctx = recipient.ctx();
    let mut plain = Vec::new();
    ctx.decrypt(&cipher, &mut plain).unwrap();
    assert_eq!(plain, b"spike plaintext");
}

#[test]
fn key_bytes_must_hold_exactly_one_key() {
    let a = GpgHome::new();
    let a_fpr = a.gen_key("A <a@example.org>");
    let b_fpr = a.gen_key("B <b@example.org>");
    let two = a.gpg(&["--armor", "--export", &a_fpr, &b_fpr]);
    let sender = GpgHome::new();
    let mut ctx = sender.ctx();
    for key in [&two[..], b"not a key", b""] {
        assert!(matches!(
            encrypt_sign_to_key_bytes(&mut ctx, key, b"x"),
            Err(RecipientFileError::NotOneKey | RecipientFileError::Gpgme(_))
        ));
    }
    let big = vec![b'a'; identity_core::MAX_KEY_INPUT + 1];
    assert!(matches!(
        encrypt_sign_to_key_bytes(&mut ctx, &big, b"x"),
        Err(RecipientFileError::TooLarge)
    ));
    assert!(sender.public_fprs().is_empty());
}

#[test]
fn recipient_path_check_refuses_unsafe_paths() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    assert!(checked_recipient_path(Path::new("/tmp/ic-recp/recipient.pgp")).is_ok());
    for bad in [
        "/tmp/a\n--hidden\n/tmp/b",
        "/tmp/a\x1b[2J",
        "/tmp/a ",
        " /tmp/a",
        "-&3",
        "relative/key.asc",
    ] {
        assert!(checked_recipient_path(Path::new(bad)).is_err(), "{bad:?}");
    }
    let non_utf8 = Path::new(OsStr::from_bytes(b"/tmp/\xff"));
    assert!(checked_recipient_path(non_utf8).is_err());
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
