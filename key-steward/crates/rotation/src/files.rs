//! Local file moves that never overwrite and never delete (S-2).
//!
//! A move is a hard link to the new name (fails if the name exists), then
//! the old name is unlinked. The file's data is never removed: it always
//! has at least one name. A crash between the two calls leaves both names
//! on the same file; running the move again sees that and only drops the
//! old name. No file is opened.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Name of the archive dir inside the ssh dir (SPEC 6 step 5).
pub const RETIRED_DIR: &str = "retired";

/// Most `-N` suffixes tried before giving up on a free name.
const MAX_SUFFIX: u32 = 1000;

/// One file move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    pub from: PathBuf,
    pub to: PathBuf,
}

/// Moves the old key files `old_path` and `old_path.pub` to
/// `<ssh_dir>/retired/` (dir 0700). Never overwrites: on a clash both get
/// the same `-1`, `-2`, ... suffix. Files that are already gone are
/// skipped, so running it again after a crash finishes the job. Returns
/// the moves made.
///
/// The caller asks the user first (plan.md, "Retire").
pub fn retire(ssh_dir: &Path, old_path: &Path) -> io::Result<Vec<Moved>> {
    let base = file_name(old_path)?;
    let items = [(old_path.to_path_buf(), ""), (pub_path(old_path), ".pub")];
    move_group(&retired_dir(ssh_dir)?, &items, &base)
}

/// `<path>.pub`.
pub(crate) fn pub_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".pub");
    PathBuf::from(s)
}

pub(crate) fn file_name(path: &Path) -> io::Result<String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} has no usable file name", path.display()),
            )
        })
}

/// `<ssh_dir>/retired`, made 0700 if missing. An existing one must be a
/// real dir (not a symlink) and is set to 0700.
pub(crate) fn retired_dir(ssh_dir: &Path) -> io::Result<PathBuf> {
    let dir = ssh_dir.join(RETIRED_DIR);
    match fs::symlink_metadata(&dir) {
        Ok(m) if m.is_dir() => {
            if m.mode() & 0o777 != 0o700 {
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a dir", dir.display()),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o700).create(&dir)?;
        }
        Err(e) => return Err(e),
    }
    Ok(dir)
}

/// Moves each `(source, tail)` to `<dir>/<base><suffix><tail>`, with one
/// suffix (`""`, `-1`, `-2`, ...) for the whole group so names stay paired.
/// A target that already is the same file as its source counts as free.
pub(crate) fn move_group(
    dir: &Path,
    items: &[(PathBuf, &str)],
    base: &str,
) -> io::Result<Vec<Moved>> {
    let present: Vec<(&Path, &str, fs::Metadata)> = items
        .iter()
        .filter_map(|(p, tail)| {
            fs::symlink_metadata(p)
                .ok()
                .map(|m| (p.as_path(), *tail, m))
        })
        .collect();
    if present.is_empty() {
        return Ok(Vec::new());
    }
    for n in 0..MAX_SUFFIX {
        let suffix = if n == 0 {
            String::new()
        } else {
            format!("-{n}")
        };
        let target = |tail: &str| dir.join(format!("{base}{suffix}{tail}"));
        let free = present
            .iter()
            .all(|(_, tail, src)| match fs::symlink_metadata(target(tail)) {
                Ok(t) => same_file(src, &t),
                Err(e) => e.kind() == io::ErrorKind::NotFound,
            });
        if !free {
            continue;
        }
        let mut moved = Vec::new();
        for (src, tail, meta) in &present {
            let to = target(tail);
            match fs::symlink_metadata(&to) {
                Ok(t) if same_file(meta, &t) => {}
                _ => fs::hard_link(src, &to).map_err(|e| link_error(e, src, dir))?,
            }
            fs::remove_file(src)?;
            moved.push(Moved {
                from: src.to_path_buf(),
                to,
            });
        }
        return Ok(moved);
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("no free name for {base} in {}", dir.display()),
    ))
}

/// A clear message for a link across filesystems (EXDEV).
fn link_error(e: io::Error, src: &Path, dir: &Path) -> io::Error {
    if e.raw_os_error() == Some(libc::EXDEV) {
        io::Error::new(
            e.kind(),
            format!(
                "{} and {} are on different filesystems, so it cannot be moved \
                 without a copy; move it by hand",
                src.display(),
                dir.display()
            ),
        )
    } else {
        e
    }
}

pub(crate) fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_filesystem_link_has_clear_message() {
        let e = link_error(
            io::Error::from_raw_os_error(libc::EXDEV),
            Path::new("/a/id"),
            Path::new("/b/retired"),
        );
        let msg = e.to_string();
        assert!(msg.contains("different filesystems"), "{msg}");
        assert!(msg.contains("/a/id") && msg.contains("/b/retired"), "{msg}");
        let other = link_error(
            io::Error::from_raw_os_error(libc::EACCES),
            Path::new("/a"),
            Path::new("/b"),
        );
        assert_eq!(other.raw_os_error(), Some(libc::EACCES));
    }
}
