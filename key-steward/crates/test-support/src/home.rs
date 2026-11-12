use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use tempfile::TempDir;

use crate::guard::check_not_real_home;

/// A temp `HOME` dir (mode 0700). Removed on drop.
pub struct TempHome {
    dir: TempDir,
}

impl TempHome {
    /// Makes the dir under `base`. Tests pass `env!("CARGO_TARGET_TMPDIR")`.
    pub fn new(base: impl AsRef<Path>) -> Self {
        let base = base.as_ref();
        fs::create_dir_all(base)
            .unwrap_or_else(|e| panic!("test-support: cannot create {}: {e}", base.display()));
        let dir = tempfile::Builder::new()
            .prefix("home-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(base)
            .unwrap_or_else(|e| panic!("test-support: temp HOME in {}: {e}", base.display()));
        check_not_real_home(dir.path()).unwrap_or_else(|e| panic!("{e}"));
        Self { dir }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// `<home>/.ssh`, created with mode 0700 if missing.
    pub fn ssh_dir(&self) -> PathBuf {
        let ssh = self.path().join(".ssh");
        if !ssh.exists() {
            fs::create_dir(&ssh).unwrap();
            fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
        }
        ssh
    }

    /// Sets `HOME` to this dir and removes `SSH_AUTH_SOCK` for a child.
    pub fn apply<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env("HOME", self.path()).env_remove("SSH_AUTH_SOCK")
    }
}

/// A temp `GNUPGHOME` (mode 0700). It lives under the system temp dir, not
/// under `CARGO_TARGET_TMPDIR`, to keep the gpg-agent socket path short.
/// On drop it stops the agent for this home, then removes the dir.
pub struct TempGnupgHome {
    dir: TempDir,
}

impl TempGnupgHome {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("gpg-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap_or_else(|e| panic!("test-support: temp GNUPGHOME: {e}"));
        check_not_real_home(dir.path()).unwrap_or_else(|e| panic!("{e}"));
        Self { dir }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Sets `GNUPGHOME` to this dir for a child.
    pub fn apply<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env("GNUPGHOME", self.path())
    }
}

impl Drop for TempGnupgHome {
    fn drop(&mut self) {
        // gpgconf may not be installed; then no agent was started either.
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(self.path())
            .args(["--kill", "all"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn temp_home_is_private_and_not_real() {
        let base = tempfile::tempdir().unwrap();
        let home = TempHome::new(base.path());
        assert!(home.path().starts_with(base.path()));
        assert_eq!(fs::metadata(home.path()).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(home.ssh_dir()).unwrap().mode() & 0o777, 0o700);
        let mut cmd = Command::new("true");
        home.apply(&mut cmd);
        let envs: Vec<_> = cmd.get_envs().collect();
        assert!(envs.contains(&(std::ffi::OsStr::new("HOME"), Some(home.path().as_os_str()))));
        assert!(envs.contains(&(std::ffi::OsStr::new("SSH_AUTH_SOCK"), None)));
    }

    #[test]
    fn temp_gnupghome_is_private_and_short() {
        let g = TempGnupgHome::new();
        assert_eq!(fs::metadata(g.path()).unwrap().mode() & 0o777, 0o700);
        // Room for "/S.gpg-agent.browser" within the 108 byte socket limit.
        assert!(g.path().as_os_str().len() < 80, "{}", g.path().display());
        let p = g.path().to_path_buf();
        drop(g);
        assert!(!p.exists());
    }
}
