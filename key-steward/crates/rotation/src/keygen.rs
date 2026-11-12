//! New key generation with `ssh-keygen` (plan.md, "Key generation").
//!
//! `ssh-keygen` writes the pair into a fresh temp dir next to `new_path`.
//! Then the files are hard linked to their final names (fails if a name
//! exists) and the temp names are dropped. Nothing is overwritten or
//! deleted (S-2), and the private key file is never opened (S-1): only
//! `<new_path>.pub` is read.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use identity_core::{Fingerprint, PublicKey, parse_public_keys, read_key_file};

use crate::files::{Moved, file_name, move_group, pub_path, retired_dir, same_file};

/// Prefix of the temp dirs `generate` makes next to `new_path`.
pub const GEN_DIR_PREFIX: &str = ".keysteward-gen-";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ed25519,
    Ecdsa,
    /// Always 4096 bits.
    Rsa,
}

impl KeyType {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyType::Ed25519 => "ed25519",
            KeyType::Ecdsa => "ecdsa",
            KeyType::Rsa => "rsa",
        }
    }

    fn args(self) -> &'static [&'static str] {
        match self {
            KeyType::Ed25519 => &["-t", "ed25519"],
            KeyType::Ecdsa => &["-t", "ecdsa"],
            KeyType::Rsa => &["-t", "rsa", "-b", "4096"],
        }
    }
}

/// How the new key gets its passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Passphrase {
    /// `ssh-keygen` inherits the terminal and asks itself. The passphrase
    /// never passes through Key Steward.
    Terminal,
    /// No passphrase (`-N ''`). The dry-run warns about it (SPEC 9.4).
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeygenRequest {
    /// Where retired and leftover files go (`<ssh_dir>/retired/`).
    pub ssh_dir: PathBuf,
    /// The new private key path. `<new_path>.pub` is the public key.
    pub new_path: PathBuf,
    pub key_type: KeyType,
    pub comment: Option<String>,
    pub passphrase: Passphrase,
    /// The `ssh-keygen` program.
    pub program: PathBuf,
}

impl KeygenRequest {
    /// Ed25519, passphrase asked on the terminal, `ssh-keygen` from `PATH`.
    pub fn new(ssh_dir: impl Into<PathBuf>, new_path: impl Into<PathBuf>) -> Self {
        KeygenRequest {
            ssh_dir: ssh_dir.into(),
            new_path: new_path.into(),
            key_type: KeyType::Ed25519,
            comment: None,
            passphrase: Passphrase::Terminal,
            program: PathBuf::from("ssh-keygen"),
        }
    }

    fn dir(&self) -> &Path {
        match self.new_path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        }
    }

    fn pub_path(&self) -> PathBuf {
        pub_path(&self.new_path)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    #[error("{0} already exists; it is never overwritten")]
    Exists(PathBuf),
    /// After a crash, `<new_path>.pub` is not the file `ssh-keygen` made
    /// with the private key: it came from somewhere else.
    #[error(
        "{0} is not the public key made with the new private key; it was put there from \
         outside. Check both files by hand"
    )]
    PublicKeyMismatch(PathBuf),
    #[error("ssh-keygen failed ({status}): {stderr}")]
    Keygen { status: String, stderr: String },
    #[error("{path}: {reason}")]
    Io { path: PathBuf, reason: String },
    #[error("{path} does not hold one SSH public key: {reason}")]
    BadPublicKey { path: PathBuf, reason: String },
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> KeygenError + '_ {
    move |e| KeygenError::Io {
        path: path.to_path_buf(),
        reason: e.to_string(),
    }
}

/// The new key pair, read from the `.pub` file only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generated {
    pub private_path: PathBuf,
    pub public_path: PathBuf,
    pub fingerprint: Fingerprint,
    pub public_key: PublicKey,
}

/// What [`recover`] found after a `generate` start with no end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovered {
    /// Both files are in place: the step is done.
    Done(Box<Generated>),
    /// Half-made files were moved to `retired/`; run `generate` again.
    RunAgain { moved: Vec<Moved> },
}

/// Makes a new key pair at `new_path`. Fails with [`KeygenError::Exists`]
/// if `new_path` or `<new_path>.pub` exists, before and after
/// `ssh-keygen` runs.
pub fn generate(req: &KeygenRequest) -> Result<Generated, KeygenError> {
    let pub_path = req.pub_path();
    for p in [&req.new_path, &pub_path] {
        if fs::symlink_metadata(p).is_ok() {
            return Err(KeygenError::Exists(p.clone()));
        }
    }
    let tmp = make_gen_dir(req.dir())?;
    let tmp_id = tmp.join("id");
    let tmp_pub = tmp.join("id.pub");

    let mut cmd = Command::new(&req.program);
    cmd.arg("-q").args(req.key_type.args());
    if let Some(c) = &req.comment {
        cmd.arg("-C").arg(c);
    }
    cmd.arg("-f").arg(&tmp_id);
    let result = match req.passphrase {
        Passphrase::Empty => cmd
            .args(["-N", ""])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .output()
            .map(|o| {
                (
                    o.status,
                    String::from_utf8_lossy(&o.stderr).trim().to_string(),
                )
            }),
        Passphrase::Terminal => cmd.status().map(|s| (s, String::new())),
    };
    let (status, stderr) = result.map_err(io_err(&req.program))?;
    if !status.success() {
        let _ = clean_leftovers(req, &[]);
        return Err(KeygenError::Keygen {
            status: status.to_string(),
            stderr,
        });
    }

    link_new(&tmp_id, &req.new_path)?;
    link_new(&tmp_pub, &pub_path)?;
    // Both final names exist now, so dropping the temp names removes no data.
    for p in [&tmp_id, &tmp_pub] {
        fs::remove_file(p).map_err(io_err(p))?;
    }
    fs::remove_dir(&tmp).map_err(io_err(&tmp))?;
    read_public(&req.new_path, &pub_path)
}

/// Settles a `generate` step that started and has no end entry (crash).
/// Both final files there: done. Otherwise the half-made files and any
/// temp leftovers go to `<ssh_dir>/retired/`, never deleted.
pub fn recover(req: &KeygenRequest) -> Result<Recovered, KeygenError> {
    let pub_path = req.pub_path();
    let finals: Vec<fs::Metadata> = [&req.new_path, &pub_path]
        .into_iter()
        .filter_map(|p| fs::symlink_metadata(p).ok())
        .collect();
    if finals.len() == 2 {
        check_pair(req, &finals[0], &finals[1])?;
        clean_leftovers(req, &finals)?;
        return read_public(&req.new_path, &pub_path).map(|g| Recovered::Done(Box::new(g)));
    }
    let mut moved = Vec::new();
    if !finals.is_empty() {
        let retired = retired_dir(&req.ssh_dir).map_err(io_err(&req.ssh_dir))?;
        let base = file_name(&req.new_path).map_err(io_err(&req.new_path))?;
        let items = [(req.new_path.clone(), ""), (pub_path.clone(), ".pub")];
        moved = move_group(&retired, &items, &base).map_err(io_err(&req.new_path))?;
    }
    moved.extend(clean_leftovers(req, &finals)?);
    Ok(Recovered::RunAgain { moved })
}

/// A temp dir whose `id` is our new private key must hold the matching
/// `id.pub`, and that must be the same file as `<new_path>.pub`.
fn check_pair(
    req: &KeygenRequest,
    private: &fs::Metadata,
    public: &fs::Metadata,
) -> Result<(), KeygenError> {
    let dir = req.dir();
    for entry in fs::read_dir(dir).map_err(io_err(dir))? {
        let gen_dir = entry.map_err(io_err(dir))?.path();
        let is_gen = gen_dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(GEN_DIR_PREFIX));
        if !is_gen {
            continue;
        }
        let ours = fs::symlink_metadata(gen_dir.join("id")).is_ok_and(|m| same_file(&m, private));
        if !ours {
            continue;
        }
        let pub_ok =
            fs::symlink_metadata(gen_dir.join("id.pub")).is_ok_and(|m| same_file(&m, public));
        if !pub_ok {
            return Err(KeygenError::PublicKeyMismatch(req.pub_path()));
        }
    }
    Ok(())
}

fn make_gen_dir(dir: &Path) -> Result<PathBuf, KeygenError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut last = None;
    for i in 0..16u32 {
        let p = dir.join(format!(
            "{GEN_DIR_PREFIX}{}-{nanos}-{i}",
            std::process::id()
        ));
        match fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(io_err(&p)(e)),
        }
    }
    Err(io_err(dir)(
        last.unwrap_or_else(|| io::Error::other("no free name")),
    ))
}

fn link_new(from: &Path, to: &Path) -> Result<(), KeygenError> {
    fs::hard_link(from, to).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => KeygenError::Exists(to.to_path_buf()),
        _ => io_err(to)(e),
    })
}

/// Temp dirs of earlier runs next to `new_path`: a name that is the same
/// file as one in `keep` is only a second name and is dropped; every other
/// file is moved to `retired/`. Then the empty dir is removed.
fn clean_leftovers(req: &KeygenRequest, keep: &[fs::Metadata]) -> Result<Vec<Moved>, KeygenError> {
    let dir = req.dir();
    let mut moved = Vec::new();
    for entry in fs::read_dir(dir).map_err(io_err(dir))? {
        let entry = entry.map_err(io_err(dir))?;
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|n| n.starts_with(GEN_DIR_PREFIX)) else {
            continue;
        };
        let gen_dir = entry.path();
        if !fs::symlink_metadata(&gen_dir).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        for f in fs::read_dir(&gen_dir).map_err(io_err(&gen_dir))? {
            let f = f.map_err(io_err(&gen_dir))?.path();
            let meta = fs::symlink_metadata(&f).map_err(io_err(&f))?;
            if keep.iter().any(|k| same_file(k, &meta)) {
                fs::remove_file(&f).map_err(io_err(&f))?;
                continue;
            }
            let retired = retired_dir(&req.ssh_dir).map_err(io_err(&req.ssh_dir))?;
            let fname: OsString = f.file_name().unwrap_or_default().to_owned();
            let base = format!(
                "{}-{}",
                name.trim_start_matches('.'),
                fname.to_string_lossy()
            );
            moved.extend(move_group(&retired, &[(f.clone(), "")], &base).map_err(io_err(&f))?);
        }
        fs::remove_dir(&gen_dir).map_err(io_err(&gen_dir))?;
    }
    Ok(moved)
}

fn read_public(private_path: &Path, pub_path: &Path) -> Result<Generated, KeygenError> {
    let bad = |reason: String| KeygenError::BadPublicKey {
        path: pub_path.to_path_buf(),
        reason,
    };
    let bytes = read_key_file(pub_path).map_err(|e| bad(e.to_string()))?;
    let mut lines = parse_public_keys(&bytes).map_err(|e| bad(e.to_string()))?;
    if lines.len() != 1 {
        return Err(bad(format!("{} key lines", lines.len())));
    }
    let key = lines.remove(0).key.map_err(|e| bad(e.to_string()))?;
    if !matches!(key, PublicKey::Ssh(_)) {
        return Err(bad("not an SSH key".into()));
    }
    Ok(Generated {
        private_path: private_path.to_path_buf(),
        public_path: pub_path.to_path_buf(),
        fingerprint: key.fingerprint(),
        public_key: key,
    })
}
