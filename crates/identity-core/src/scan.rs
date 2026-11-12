//! SSH dir scan (Key Steward T04). The dir is always a parameter; this
//! module never looks up the home dir.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::error::{KeyError, LineError};
use crate::key::{PublicKey, SshPublicKey};
use crate::parse::{parse_public_keys, read_key_file};
use crate::private_header::{PrivateKeyProtection, private_key_protection};

/// One `.pub` file found by [`scan_ssh_dir`].
#[derive(Debug)]
pub struct SshKeyFile {
    pub public_path: PathBuf,
    /// The key, or why the file could not be used. A `.pub` file must hold
    /// exactly one SSH public key.
    pub key: Result<SshPublicKey, KeyError>,
    /// The file with the same name without `.pub`, if it is a regular file.
    pub private_path: Option<PathBuf>,
    /// Header check of the private file (S-1). A file we can not read is
    /// [`PrivateKeyProtection::Unknown`].
    pub protection: Option<PrivateKeyProtection>,
    /// SSH keys have no creation time. This is the modification time of the
    /// private file, else of the `.pub` file. Show it as the file date.
    pub file_date: Option<SystemTime>,
}

/// The result of [`scan_ssh_dir`].
#[derive(Debug, Default)]
pub struct SshScan {
    /// One entry per `.pub` file, sorted by path.
    pub keys: Vec<SshKeyFile>,
    /// OpenSSH certificates (`*-cert.pub`). They are not keys, so they are
    /// not in `keys`; the caller can note them.
    pub certificates: Vec<PathBuf>,
    /// Dir entries that could not be read. The scan goes on after them.
    pub entry_errors: Vec<KeyError>,
}

/// List the SSH keys in `dir` (not its subdirs): every regular `*.pub`
/// file, paired with its private file. Private files without a `.pub` are
/// not listed, since the public key would have to come from the private
/// file. File names need not be UTF-8. Only a dir that can not be opened
/// is an error.
pub fn scan_ssh_dir(dir: &Path) -> Result<SshScan, KeyError> {
    let mut scan = SshScan::default();
    for entry in std::fs::read_dir(dir)? {
        let public_path = match entry {
            Ok(e) => e.path(),
            Err(e) => {
                scan.entry_errors.push(e.into());
                continue;
            }
        };
        let Some(name) = public_path.file_name().map(OsStrExt::as_bytes) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(b".pub").filter(|s| !s.is_empty()) else {
            continue;
        };
        if stem.ends_with(b"-cert") {
            scan.certificates.push(public_path);
            continue;
        }
        let private = dir.join(OsStr::from_bytes(stem));
        let meta = match std::fs::metadata(&public_path) {
            Ok(m) if m.is_file() => m,
            Ok(_) => continue,
            Err(e) => {
                scan.keys.push(SshKeyFile {
                    public_path,
                    key: Err(e.into()),
                    private_path: None,
                    protection: None,
                    file_date: None,
                });
                continue;
            }
        };
        let private_meta = std::fs::metadata(&private).ok().filter(|m| m.is_file());
        let protection = private_meta
            .as_ref()
            .map(|_| private_key_protection(&private).unwrap_or(PrivateKeyProtection::Unknown));
        let file_date = private_meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .or_else(|| meta.modified().ok());
        scan.keys.push(SshKeyFile {
            key: read_ssh_pub(&public_path),
            private_path: private_meta.map(|_| private),
            protection,
            file_date,
            public_path,
        });
    }
    scan.keys.sort_by(|a, b| a.public_path.cmp(&b.public_path));
    scan.certificates.sort();
    Ok(scan)
}

fn read_ssh_pub(path: &Path) -> Result<SshPublicKey, KeyError> {
    let mut lines = parse_public_keys(&read_key_file(path)?)?;
    if lines.len() != 1 {
        return Err(KeyError::NotOneKey);
    }
    match lines.remove(0).key? {
        PublicKey::Ssh(k) => Ok(k),
        _ => Err(LineError::UnknownType.into()),
    }
}
