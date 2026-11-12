use std::ffi::CStr;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The user who runs the tests, from the passwd entry of the effective uid.
#[derive(Debug, Clone)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    /// The passwd home. OpenSSH uses this, not `$HOME`.
    pub home: PathBuf,
}

pub fn current_user() -> User {
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers point to live, correctly sized buffers.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        panic!("test-support: no passwd entry for uid {uid} (getpwuid_r returned {rc})");
    }
    // SAFETY: on success pw_name and pw_dir are NUL terminated strings in buf.
    let (name, home) = unsafe {
        (
            CStr::from_ptr(pwd.pw_name).to_string_lossy().into_owned(),
            CStr::from_ptr(pwd.pw_dir).to_string_lossy().into_owned(),
        )
    };
    User {
        uid,
        gid: pwd.pw_gid,
        name,
        home: PathBuf::from(home),
    }
}

/// Panics if the tests run as root. A root sshd wants the privsep user and
/// would log in as root.
pub fn refuse_root() {
    let user = current_user();
    if user.uid == 0 {
        panic!(
            "test-support: refusing to run as root (uid 0, user {}). \
             Run the tests as a normal user, for example `dev` in the devcontainer.",
            user.name
        );
    }
}

fn normalize(path: &Path) -> PathBuf {
    if let Ok(p) = path.canonicalize() {
        return p;
    }
    // Canonicalize the longest existing ancestor, then add the rest back.
    let mut rest = Vec::new();
    let mut cur = path;
    while let Some(parent) = cur.parent() {
        if let Some(name) = cur.file_name() {
            rest.push(name.to_owned());
        }
        if let Ok(base) = parent.canonicalize() {
            let mut out = base;
            for name in rest.iter().rev() {
                out.push(name);
            }
            return out;
        }
        cur = parent;
    }
    path.to_path_buf()
}

/// Errors if `path` is the real home dir, or inside the real `~/.ssh` or
/// `~/.gnupg`. The real home is the passwd home, and `$HOME` if it differs.
pub fn check_not_real_home(path: &Path) -> Result<(), String> {
    let mut homes = vec![current_user().home];
    if let Some(env_home) = std::env::var_os("HOME") {
        homes.push(PathBuf::from(env_home));
    }
    let target = normalize(path);
    for home in homes {
        let home = normalize(&home);
        if target == home {
            return Err(format!(
                "test-support: {} is the real home dir; tests must use a temp dir",
                path.display()
            ));
        }
        for sub in [".ssh", ".gnupg"] {
            if target.starts_with(home.join(sub)) {
                return Err(format!(
                    "test-support: {} is inside the real {}; tests must use a temp dir",
                    path.display(),
                    home.join(sub).display()
                ));
            }
        }
    }
    Ok(())
}

/// Checks `dir` and every parent up to `/`: each must be owned by root or
/// `uid` and must not be group or world writable. sshd `StrictModes yes`
/// walks the same chain for an `AuthorizedKeysFile` outside the real home.
pub fn check_dir_chain(dir: &Path, uid: u32) -> Result<(), String> {
    let dir = dir
        .canonicalize()
        .map_err(|e| format!("test-support: cannot resolve {}: {e}", dir.display()))?;
    for d in dir.ancestors() {
        let meta = fs::metadata(d)
            .map_err(|e| format!("test-support: cannot stat {}: {e}", d.display()))?;
        let mode = meta.mode() & 0o7777;
        let owner_ok = meta.uid() == 0 || meta.uid() == uid;
        if !owner_ok || mode & 0o022 != 0 {
            return Err(format!(
                "test-support: {} is owned by uid {} gid {} with mode {:o}. \
                 sshd StrictModes needs every parent dir of the test dir to be owned \
                 by root or uid {uid} and not group or world writable. \
                 Fix that dir (for example `chmod go-w`) or use another base dir.",
                d.display(),
                meta.uid(),
                meta.gid(),
                mode
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_rejects_real_home() {
        let home = current_user().home;
        assert!(check_not_real_home(&home).is_err());
        assert!(check_not_real_home(&home.join(".ssh")).is_err());
        assert!(check_not_real_home(&home.join(".ssh/id_ed25519")).is_err());
        assert!(check_not_real_home(&home.join(".gnupg")).is_err());
        let tmp = tempfile::tempdir().unwrap();
        assert!(check_not_real_home(tmp.path()).is_ok());
        assert!(check_not_real_home(&tmp.path().join(".ssh")).is_ok());
    }

    #[test]
    fn current_user_is_not_root() {
        refuse_root();
        let user = current_user();
        assert!(!user.name.is_empty());
        assert!(user.home.is_absolute());
    }
}
