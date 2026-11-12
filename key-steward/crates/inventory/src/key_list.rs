//! The key list (FR-1): local keys with their location counts and weak key
//! warnings. Keys are read from their source each time (S-8); only the
//! location counts come from the store. No network (NFR-4).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use identity_core::{
    Fingerprint, KeyAlgo, KeyKind, KeyWarning, OpenPgpBackend, OpenPgpKey, OpenPgpSubkey,
    PublicKey, SshScan, scan_ssh_dir, weak_key_warnings,
};

use crate::store::{Store, StoreError};

/// When a key was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Created {
    /// The creation time stored in the key (OpenPGP).
    Key(SystemTime),
    /// SSH keys have no creation time. This is the file date (FR-1): the
    /// modification time of the private file, else of the `.pub` file.
    FileDate(SystemTime),
}

/// Where a key was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    Ssh {
        public_path: PathBuf,
        private_path: Option<PathBuf>,
    },
    /// The GnuPG keyring.
    OpenPgp,
}

/// One row of the key list, with all FR-1 fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRow {
    pub kind: KeyKind,
    /// SSH: the comment, else the file name. OpenPGP: the first valid user
    /// ID, else the first one. Control and bidi characters are removed.
    pub name: String,
    /// Type with bits or curve.
    pub algo: KeyAlgo,
    pub fingerprint: Fingerprint,
    pub created: Option<Created>,
    /// Expiry of the key (OpenPGP primary key). SSH keys do not expire.
    pub expiry: Option<SystemTime>,
    /// OpenPGP subkeys without the primary key, each with its own expiry.
    /// Empty for SSH keys.
    pub subkeys: Vec<OpenPgpSubkey>,
    /// Number of stored locations that hold this key.
    pub location_count: usize,
    /// Weak key warnings (SPEC 9.4).
    pub warnings: Vec<KeyWarning>,
    pub source: KeySource,
}

/// A key that could not be listed, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyProblem {
    /// A file path, or `GnuPG`.
    pub source: String,
    /// Fixed text from the parser or backend, never key bytes.
    pub reason: String,
}

/// The FR-1 key list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyList {
    /// SSH keys first (sorted by file path), then OpenPGP keys in keyring
    /// order.
    pub rows: Vec<KeyRow>,
    pub problems: Vec<KeyProblem>,
}

impl KeyList {
    /// Reads the SSH keys in `ssh_dir` and the OpenPGP keys that have a
    /// secret key in `gpg` (the user's own keys), then joins them with
    /// `store`. A missing SSH dir gives no SSH keys. SSH or GnuPG errors go
    /// into [`KeyList::problems`], so one broken source does not hide the
    /// other. Only store errors fail.
    pub fn load(
        ssh_dir: &Path,
        gpg: &mut dyn OpenPgpBackend,
        store: &Store,
    ) -> Result<KeyList, StoreError> {
        let mut problems = Vec::new();
        let scan = match scan_ssh_dir(ssh_dir) {
            Ok(s) => s,
            Err(identity_core::KeyError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                SshScan::default()
            }
            Err(e) => {
                problems.push(KeyProblem {
                    source: ssh_dir.display().to_string(),
                    reason: e.to_string(),
                });
                SshScan::default()
            }
        };
        let openpgp = gpg.secret_keys().unwrap_or_else(|e| {
            problems.push(KeyProblem {
                source: "GnuPG".into(),
                reason: e.to_string(),
            });
            Vec::new()
        });
        let mut list = KeyList::build(&scan, &openpgp, store)?;
        problems.append(&mut list.problems);
        list.problems = problems;
        Ok(list)
    }

    /// Joins already read keys with the location counts in `store`.
    pub fn build(
        ssh: &SshScan,
        openpgp: &[OpenPgpKey],
        store: &Store,
    ) -> Result<KeyList, StoreError> {
        let mut counts: HashMap<Fingerprint, usize> = HashMap::new();
        for loc in store.list()? {
            *counts.entry(loc.key).or_default() += 1;
        }
        let count = |f: &Fingerprint| counts.get(f).copied().unwrap_or(0);

        let mut list = KeyList::default();
        for file in &ssh.keys {
            let key = match &file.key {
                Ok(k) => k,
                Err(e) => {
                    list.problems.push(KeyProblem {
                        source: file.public_path.display().to_string(),
                        reason: e.to_string(),
                    });
                    continue;
                }
            };
            let name = key
                .comment_display()
                .filter(|c| !c.is_empty())
                .unwrap_or_else(|| {
                    file.public_path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                });
            list.rows.push(KeyRow {
                kind: KeyKind::Ssh,
                name,
                algo: key.algo.clone(),
                fingerprint: key.fingerprint.clone(),
                created: file.file_date.map(Created::FileDate),
                expiry: None,
                subkeys: Vec::new(),
                location_count: count(&key.fingerprint),
                warnings: weak_key_warnings(&PublicKey::Ssh(key.clone()), file.protection),
                source: KeySource::Ssh {
                    public_path: file.public_path.clone(),
                    private_path: file.private_path.clone(),
                },
            });
        }
        for path in &ssh.certificates {
            list.problems.push(KeyProblem {
                source: path.display().to_string(),
                reason: "SSH certificates are not listed".into(),
            });
        }
        for e in &ssh.entry_errors {
            list.problems.push(KeyProblem {
                source: "SSH dir".into(),
                reason: e.to_string(),
            });
        }

        for key in openpgp {
            let uid = key
                .user_ids
                .iter()
                .find(|u| !u.revoked && !u.invalid)
                .or(key.user_ids.first());
            list.rows.push(KeyRow {
                kind: KeyKind::OpenPgp,
                name: uid.map(|u| u.display()).unwrap_or_default(),
                algo: key.algo.clone(),
                fingerprint: key.fingerprint.clone(),
                created: key.created.map(Created::Key),
                expiry: key.expiry,
                subkeys: key
                    .subkeys
                    .iter()
                    .filter(|s| s.fingerprint != key.fingerprint)
                    .cloned()
                    .collect(),
                location_count: count(&key.fingerprint),
                warnings: weak_key_warnings(&PublicKey::OpenPgp(key.clone()), None),
                source: KeySource::OpenPgp,
            });
        }
        Ok(list)
    }
}
