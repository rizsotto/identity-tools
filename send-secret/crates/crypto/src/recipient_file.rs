//! Encrypt to an OpenPGP key without importing it (Send Secret SPEC 15, F3).
//!
//! gpgme can encrypt to a key in a file with the recipient string
//! `--file\n<path>` (`gpgme_op_encrypt_ext` / `gpgme_op_encrypt_sign_ext`).
//! That string is an injection point: each line is a key spec or a keyword,
//! so a newline in the path adds recipients or `--hidden`. [`RecipientFile`]
//! takes key bytes, never a path, and builds the string itself.
//!
//! The OpenPGP backend (`openpgp_backend.rs`) makes the one `unsafe` call
//! into `gpgme-sys` with [`RecipientFile::gpgme_recipients`], because the
//! safe `gpgme` crate does not wrap the `_ext` functions.

use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use gpgme::{Context, ExportMode, Protocol};
use identity_core::{Gpg, GpgError, OpenPgpBackend, OpenPgpKey};
use tempfile::TempDir;

/// Why a key can not be used as a recipient file. Fixed text, never the
/// key input.
#[derive(Debug, thiserror::Error)]
pub enum RecipientFileError {
    #[error(transparent)]
    Gpg(#[from] GpgError),
    #[error("key input must hold exactly one OpenPGP key")]
    NotOneKey,
    #[error("key input holds more than {MAX_KEYS} OpenPGP keys")]
    TooManyKeys,
    #[error("the OpenPGP key has no usable encryption subkey")]
    CannotEncrypt,
    #[error("unsafe path for a GnuPG recipient file")]
    UnsafePath,
    #[error("cannot write the recipient key file: {0}")]
    Io(#[from] std::io::Error),
}

const FILE_NAME: &str = "recipient.pgp";

/// Most keys one key file may hold.
pub const MAX_KEYS: usize = 32;

/// One OpenPGP public key in a private temp file, ready to pass to gpgme.
///
/// - The bytes must be at most [`identity_core::MAX_KEY_INPUT`] long and hold
///   exactly one key that can encrypt.
/// - The file is `recipient.pgp`, mode 0600, in a fresh dir with mode 0700
///   under `$XDG_RUNTIME_DIR` (if set and absolute), else the system temp
///   dir.
/// - The dir and file are deleted on drop. Keep the value alive until the
///   gpgme operation has finished.
pub struct RecipientFile {
    _dir: TempDir,
    path: PathBuf,
    recipients: CString,
    key: OpenPgpKey,
}

impl std::fmt::Debug for RecipientFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecipientFile")
            .field("path", &self.path)
            .field("fingerprint", &self.key.fingerprint)
            .finish()
    }
}

impl RecipientFile {
    /// Check `key` with `gpg` (nothing is imported) and write it out.
    pub fn new(gpg: &mut Gpg, key: &[u8]) -> Result<Self, RecipientFileError> {
        Self::new_in(gpg, key, &runtime_dir())
    }

    /// One recipient file per key in `keys` (an OpenPGP key file may hold
    /// several, FR-4). Each key is checked like [`RecipientFile::new`]; one
    /// unusable key fails the whole file.
    ///
    /// gpg wants one key per `--file`, and we do not parse OpenPGP packets
    /// ourselves. So a file with several keys is imported into a throwaway
    /// home (mode 0700, gpg.conf `no-autostart` so no agent starts, deleted
    /// after) and each key is exported from there. The user's keyring is
    /// never touched.
    pub fn all(gpg: &mut Gpg, keys: &[u8]) -> Result<Vec<Self>, RecipientFileError> {
        let count = gpg.read_keys(keys)?.len();
        if count <= 1 {
            return Ok(vec![Self::new(gpg, keys)?]);
        }
        if count > MAX_KEYS {
            return Err(RecipientFileError::TooManyKeys);
        }
        split_keys(keys)?
            .iter()
            .map(|key| Self::new(gpg, key))
            .collect()
    }

    fn new_in(gpg: &mut Gpg, key: &[u8], parent: &Path) -> Result<Self, RecipientFileError> {
        let mut keys = gpg.read_keys(key)?;
        if keys.len() != 1 {
            return Err(RecipientFileError::NotOneKey);
        }
        let parsed = keys.remove(0);
        if !parsed.can_encrypt {
            return Err(RecipientFileError::CannotEncrypt);
        }

        let dir = tempfile::Builder::new()
            .prefix("ic-recp")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)?;
        let path = dir.path().join(FILE_NAME);
        let recipients = recipient_string(&path)?;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?
            .write_all(key)?;
        Ok(RecipientFile {
            _dir: dir,
            path,
            recipients,
            key: parsed,
        })
    }

    /// The key in the file.
    pub fn key(&self) -> &OpenPgpKey {
        &self.key
    }

    /// The absolute path of the key file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The `recp` argument for `gpgme_op_encrypt_ext` and
    /// `gpgme_op_encrypt_sign_ext`: `--file\n<path>`, path checked by
    /// [`checked_recipient_path`]. Pass it unchanged, or join several with
    /// [`RecipientFile::joined`]. Never add other lines.
    pub fn gpgme_recipients(&self) -> &CStr {
        &self.recipients
    }

    /// The `recp` argument for several files: their `--file\n<path>` lines
    /// joined with newlines. Each path is already checked, so no line can
    /// add a key or keyword of its own.
    pub fn joined(files: &[RecipientFile]) -> CString {
        let lines: Vec<&[u8]> = files.iter().map(|f| f.recipients.to_bytes()).collect();
        // No NUL bytes: each part came from a CString.
        CString::new(lines.join(&b"\n"[..])).unwrap_or_default()
    }
}

/// Exports each key of `keys` on its own, through a throwaway home.
fn split_keys(keys: &[u8]) -> Result<Vec<Vec<u8>>, RecipientFileError> {
    let gpgme = |e: gpgme::Error| RecipientFileError::Gpg(e.into());
    let dir = tempfile::Builder::new()
        .prefix("ss-split")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(runtime_dir())?;
    std::fs::write(dir.path().join("gpg.conf"), "no-autostart\n")?;
    let home = dir.path().to_str().ok_or(RecipientFileError::UnsafePath)?;
    let mut ctx = Context::from_protocol(Protocol::OpenPgp).map_err(gpgme)?;
    ctx.set_engine_home_dir(home).map_err(gpgme)?;
    ctx.import(keys).map_err(gpgme)?;
    let fprs: Vec<String> = ctx
        .keys()
        .map_err(gpgme)?
        .filter_map(Result::ok)
        .filter_map(|k| k.fingerprint().ok().map(str::to_owned))
        .collect();
    fprs.iter()
        .map(|fpr| {
            let mut out = Vec::new();
            ctx.export([fpr.as_str()], ExportMode::empty(), &mut out)
                .map_err(gpgme)?;
            Ok(out)
        })
        .collect()
}

/// `$XDG_RUNTIME_DIR` if set and absolute, else the system temp dir.
fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_dir())
        .unwrap_or_else(std::env::temp_dir)
}

fn recipient_string(path: &Path) -> Result<CString, RecipientFileError> {
    CString::new(format!("--file\n{}", checked_recipient_path(path)?))
        .map_err(|_| RecipientFileError::UnsafePath)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn recipient_path_check_refuses_unsafe_paths() {
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

    #[test]
    fn recipient_string_is_one_file_line() {
        let s = recipient_string(Path::new("/run/user/1000/ic-recp1/recipient.pgp")).unwrap();
        assert_eq!(
            s.to_bytes(),
            b"--file\n/run/user/1000/ic-recp1/recipient.pgp"
        );
    }
}
