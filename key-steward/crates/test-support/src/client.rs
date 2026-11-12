use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

use crate::guard::check_not_real_home;
use crate::sshd::Sshd;

/// One client `ssh_config` and one `known_hosts` for several test servers,
/// so a test sees them like a user with several hosts. Each server is a
/// `Host` block under its own alias (see [`Sshd::start_named`]). Removed
/// on drop.
pub struct ClientConfig {
    dir: TempDir,
}

impl ClientConfig {
    /// Writes the files in a temp dir next to the first server's dir.
    /// Panics if `servers` is empty or two servers share an alias.
    pub fn new(servers: &[&Sshd]) -> Self {
        let first = servers
            .first()
            .expect("test-support: ClientConfig needs a server");
        for (i, a) in servers.iter().enumerate() {
            if servers[..i].iter().any(|b| b.alias() == a.alias()) {
                panic!("test-support: two servers use the alias {}", a.alias());
            }
        }
        let base = first.dir().parent().expect("server dir has a parent");
        let dir = tempfile::Builder::new()
            .prefix("client-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(base)
            .unwrap_or_else(|e| panic!("test-support: temp dir in {}: {e}", base.display()));
        let cfg = ClientConfig { dir };
        fs::create_dir(cfg.home()).unwrap();
        fs::set_permissions(cfg.home(), fs::Permissions::from_mode(0o700)).unwrap();
        check_not_real_home(&cfg.home()).unwrap_or_else(|e| panic!("{e}"));

        let kh = cfg.known_hosts();
        let hosts: String = servers.iter().map(|s| s.known_hosts_line()).collect();
        let blocks: Vec<String> = servers.iter().map(|s| s.host_block(&kh)).collect();
        fs::write(&kh, hosts).unwrap();
        fs::write(cfg.ssh_config(), blocks.join("\n")).unwrap();
        cfg
    }

    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    pub fn ssh_config(&self) -> PathBuf {
        self.dir().join("ssh_config")
    }

    pub fn known_hosts(&self) -> PathBuf {
        self.dir().join("known_hosts")
    }

    /// Temp `HOME` for client processes.
    pub fn home(&self) -> PathBuf {
        self.dir().join("home")
    }

    /// `ssh -F <ssh_config>` with the temp `HOME`, no `SSH_AUTH_SOCK` and
    /// stdin from /dev/null. Add `-i <key>`, the alias and the command.
    pub fn ssh(&self) -> Command {
        let mut cmd = Command::new("ssh");
        cmd.arg("-F")
            .arg(self.ssh_config())
            .env("HOME", self.home())
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null());
        cmd
    }

    /// Runs `ssh -F <cfg> -i <key> <alias> <remote>`.
    pub fn run(&self, key: &Path, alias: &str, remote: &str) -> Output {
        self.ssh()
            .arg("-i")
            .arg(key)
            .arg(alias)
            .arg(remote)
            .output()
            .unwrap_or_else(|e| panic!("test-support: cannot run ssh: {e}"))
    }
}
