//! SSH dir scan (Key Steward T04). The dir is always a parameter; this
//! module never looks up the home dir.

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

/// List the SSH keys in `dir` (not its subdirs): every regular `*.pub`
/// file, paired with its private file. Private files without a `.pub` are
/// not listed, since the public key would have to come from the private
/// file. Sorted by path.
pub fn scan_ssh_dir(dir: &Path) -> Result<Vec<SshKeyFile>, KeyError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let public_path = entry?.path();
        let Some(stem) = public_path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".pub"))
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let Ok(meta) = std::fs::metadata(&public_path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let private = dir.join(stem);
        let private_meta = std::fs::metadata(&private).ok().filter(|m| m.is_file());
        let protection = private_meta
            .as_ref()
            .map(|_| private_key_protection(&private).unwrap_or(PrivateKeyProtection::Unknown));
        let file_date = private_meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .or_else(|| meta.modified().ok());
        out.push(SshKeyFile {
            key: read_ssh_pub(&public_path),
            private_path: private_meta.map(|_| private),
            protection,
            file_date,
            public_path,
        });
    }
    out.sort_by(|a, b| a.public_path.cmp(&b.public_path));
    Ok(out)
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
