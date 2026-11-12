//! One process drives rotations at a time (plan.md, "Locking"): an
//! advisory `flock` on `rotation.lock` next to the database file. The kernel drops the
//! lock when the process dies, so a crash never leaves a stale lock.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("another Key Steward process is running a rotation ({0} is locked)")]
    Busy(PathBuf),
    #[error("cannot lock {path}: {reason}")]
    Io { path: PathBuf, reason: String },
}

/// Held for the whole run. Dropping it releases the lock.
#[derive(Debug)]
pub struct RotationLock {
    _file: File,
}

/// The lock file of the database at `db`: `rotation.lock` in its dir.
pub fn lock_path(db: &Path) -> PathBuf {
    db.with_file_name("rotation.lock")
}

impl RotationLock {
    /// Takes the lock for the database at `db`, or fails at once with
    /// [`LockError::Busy`].
    pub fn for_database(db: &Path) -> Result<RotationLock, LockError> {
        Self::acquire(&lock_path(db))
    }

    fn acquire(path: &Path) -> Result<RotationLock, LockError> {
        let io_err = |e: io::Error| LockError::Io {
            path: path.to_path_buf(),
            reason: e.to_string(),
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(io_err)?;
        // SAFETY: flock only reads the fd, which `file` keeps open.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let e = io::Error::last_os_error();
            return Err(match e.raw_os_error() {
                Some(libc::EWOULDBLOCK) => LockError::Busy(path.to_path_buf()),
                _ => io_err(e),
            });
        }
        Ok(RotationLock { _file: file })
    }
}

impl Drop for RotationLock {
    fn drop(&mut self) {
        // SAFETY: the fd is still open; closing it would also release.
        unsafe { libc::flock(self._file.as_raw_fd(), libc::LOCK_UN) };
    }
}
