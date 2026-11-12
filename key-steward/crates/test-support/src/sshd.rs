use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

use crate::guard::{User, check_dir_chain, check_not_real_home, current_user, refuse_root};

const SSHD: &str = "/usr/sbin/sshd";
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const ATTEMPTS: u32 = 5;

/// The `Host` alias in the client `ssh_config`.
pub const ALIAS: &str = "testsshd";

/// A real OpenSSH sshd run as the current user on `127.0.0.1` and a free
/// port, with its own temp dir. Stopped on drop.
///
/// Every `ssh` run against it must get `-F <ssh_config>` and a temp `HOME`
/// (see [`Sshd::ssh`]), because OpenSSH finds `~` from passwd, not `$HOME`.
pub struct Sshd {
    dir: TempDir,
    port: u16,
    child: Option<Child>,
    user: User,
    reported: bool,
    extra_config: String,
}

enum StartError {
    AddrInUse,
    Other(String),
}

impl Sshd {
    /// Starts a new server in a temp dir under `base_dir`. Tests pass
    /// `env!("CARGO_TARGET_TMPDIR")`. Panics with diagnostics on failure.
    pub fn start(base_dir: impl AsRef<Path>) -> Self {
        Self::start_with(base_dir, "")
    }

    /// Like [`Sshd::start`], with extra lines at the start of `sshd_config`
    /// (for example `Banner` or `TrustedUserCAKeys`). sshd keeps the first
    /// value of an option, so these win over the defaults. Paths in them
    /// may use `@DIR@` for the server's temp dir and `@PORT@` for its port.
    pub fn start_with(base_dir: impl AsRef<Path>, extra_config: &str) -> Self {
        refuse_root();
        let base = base_dir.as_ref();
        fs::create_dir_all(base)
            .unwrap_or_else(|e| panic!("test-support: cannot create {}: {e}", base.display()));
        let user = current_user();
        if let Err(e) = check_dir_chain(base, user.uid) {
            panic!("{e}\n{}", env_summary(&user));
        }
        if !Path::new(SSHD).exists() {
            panic!(
                "test-support: {SSHD} not found. Install openssh-server (it is in \
                 .devcontainer/Containerfile).\n{}",
                env_summary(&user)
            );
        }
        let dir = tempfile::Builder::new()
            .prefix("sshd-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(base)
            .unwrap_or_else(|e| panic!("test-support: temp dir in {}: {e}", base.display()));
        let mut sshd = Sshd {
            dir,
            port: 0,
            child: None,
            user,
            reported: false,
            extra_config: extra_config.to_string(),
        };
        sshd.setup_files();

        let mut last = String::new();
        for _ in 0..ATTEMPTS {
            let port = free_port();
            match sshd.spawn(port) {
                Ok(()) => {
                    sshd.write_client_files();
                    return sshd;
                }
                Err(StartError::AddrInUse) => last = format!("port {port} in use"),
                Err(StartError::Other(e)) => sshd.fail(&e),
            }
        }
        sshd.fail(&format!("no free port after {ATTEMPTS} tries ({last})"))
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn alias(&self) -> &str {
        ALIAS
    }

    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// Client config with the `Host` alias [`ALIAS`]. Has no `IdentityFile`:
    /// pass the key you mean with `-i`.
    pub fn ssh_config(&self) -> PathBuf {
        self.dir().join("ssh_config")
    }

    pub fn known_hosts(&self) -> PathBuf {
        self.dir().join("known_hosts")
    }

    /// Temp `HOME` for client processes.
    pub fn client_home(&self) -> PathBuf {
        self.dir().join("clienthome")
    }

    /// `$HOME` of sessions on this server (`SetEnv HOME`).
    pub fn server_home(&self) -> PathBuf {
        self.dir().join("srvhome")
    }

    /// The file sshd reads. Equal to `$HOME/.ssh/authorized_keys` of a session.
    pub fn authorized_keys(&self) -> PathBuf {
        self.server_home().join(".ssh/authorized_keys")
    }

    /// Private key that is in `authorized_keys` from the start.
    pub fn client_key(&self) -> PathBuf {
        self.dir().join("keys/client")
    }

    pub fn log_path(&self) -> PathBuf {
        self.dir().join("sshd.log")
    }

    pub fn log(&self) -> String {
        fs::read_to_string(self.log_path()).unwrap_or_default()
    }

    /// Makes a new ed25519 key pair in the temp dir. Not authorized.
    /// Returns the private key path; the public key is `<path>.pub`.
    pub fn new_key(&self, name: &str) -> PathBuf {
        let path = self.dir().join("keys").join(name);
        keygen(&path, &self.client_home(), name);
        path
    }

    /// Appends the public key `<key>.pub` to `authorized_keys`.
    pub fn authorize(&self, key: &Path) {
        let mut pubpath = key.as_os_str().to_owned();
        pubpath.push(".pub");
        let line = fs::read_to_string(&pubpath).unwrap();
        let mut f = OpenOptions::new()
            .append(true)
            .open(self.authorized_keys())
            .unwrap();
        f.write_all(line.as_bytes()).unwrap();
    }

    /// `ssh -F <ssh_config>` with a temp `HOME`, no `SSH_AUTH_SOCK` and
    /// stdin from /dev/null. Add `-i <key>`, the alias and the command.
    /// The config has `IdentityFile none`, so without `-i` ssh offers no key
    /// (and never reads the real `~/.ssh/id_*`).
    pub fn ssh(&self) -> Command {
        let mut cmd = Command::new("ssh");
        cmd.arg("-F")
            .arg(self.ssh_config())
            .env("HOME", self.client_home())
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null());
        cmd
    }

    /// Runs `ssh -F <cfg> -i <key> <alias> <remote>`.
    pub fn run(&self, key: &Path, remote: &str) -> Output {
        self.ssh()
            .arg("-i")
            .arg(key)
            .arg(ALIAS)
            .arg(remote)
            .output()
            .unwrap_or_else(|e| panic!("test-support: cannot run ssh: {e}"))
    }

    /// Kills sshd and waits for it.
    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Stops sshd and starts it again on the same port.
    pub fn restart(&mut self) {
        self.stop();
        let port = self.port;
        for _ in 0..ATTEMPTS {
            match self.spawn(port) {
                Ok(()) => return,
                Err(StartError::AddrInUse) => std::thread::sleep(Duration::from_millis(100)),
                Err(StartError::Other(e)) => self.fail(&e),
            }
        }
        self.fail(&format!("restart: port {port} still in use"));
    }

    /// Port, user, paths and the sshd log, for failure messages.
    pub fn diagnostics(&self) -> String {
        format!(
            "--- test sshd diagnostics ---\n{}\nport: {}\ndir: {}\nsshd running: {}\n\
             --- sshd log ({}) ---\n{}--- end sshd log ---",
            env_summary(&self.user),
            self.port,
            self.dir().display(),
            self.child.is_some(),
            self.log_path().display(),
            self.log()
        )
    }

    fn fail(&mut self, msg: &str) -> ! {
        let diag = self.diagnostics();
        self.reported = true;
        self.stop();
        panic!("test-support: sshd failed: {msg}\n{diag}");
    }

    fn setup_files(&self) {
        let d = self.dir();
        let srv_ssh = self.server_home().join(".ssh");
        fs::create_dir_all(&srv_ssh).unwrap();
        fs::set_permissions(self.server_home(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&srv_ssh, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(self.client_home()).unwrap();
        fs::set_permissions(self.client_home(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(d.join("keys")).unwrap();
        for p in [self.client_home(), self.server_home()] {
            check_not_real_home(&p).unwrap_or_else(|e| panic!("{e}"));
        }

        keygen(&d.join("hostkey"), &self.client_home(), "test-sshd-hostkey");
        keygen(&self.client_key(), &self.client_home(), "client");
        let mut pubkey = self.client_key().into_os_string();
        pubkey.push(".pub");
        fs::copy(&pubkey, self.authorized_keys()).unwrap();
        fs::set_permissions(self.authorized_keys(), fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn write_sshd_config(&self, port: u16) {
        let d = self.dir().display();
        let cfg = format!(
            "{extra}ListenAddress 127.0.0.1:{port}\n\
             HostKey {d}/hostkey\n\
             PidFile none\n\
             UsePAM no\n\
             StrictModes yes\n\
             AuthorizedKeysFile {ak}\n\
             SetEnv HOME={home}\n\
             AuthenticationMethods publickey\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             PerSourcePenalties no\n\
             PermitUserRC no\n\
             LogLevel VERBOSE\n",
            ak = self.authorized_keys().display(),
            home = self.server_home().display(),
            extra = self
                .extra_config
                .replace("@DIR@", &d.to_string())
                .replace("@PORT@", &port.to_string()),
        );
        fs::write(self.dir().join("sshd_config"), cfg).unwrap();
    }

    fn write_client_files(&self) {
        let mut hostpub = self.dir().join("hostkey").into_os_string();
        hostpub.push(".pub");
        let hostpub = fs::read_to_string(&hostpub).unwrap();
        let mut fields = hostpub.split_whitespace();
        let (kind, key) = (fields.next().unwrap(), fields.next().unwrap());
        fs::write(
            self.known_hosts(),
            format!("[127.0.0.1]:{} {kind} {key}\n", self.port),
        )
        .unwrap();
        let cfg = format!(
            "Host {ALIAS}\n  \
             HostName 127.0.0.1\n  \
             Port {port}\n  \
             User {user}\n  \
             IdentitiesOnly yes\n  \
             IdentityFile none\n  \
             IdentityAgent none\n  \
             UserKnownHostsFile {kh}\n  \
             GlobalKnownHostsFile /dev/null\n  \
             StrictHostKeyChecking yes\n  \
             BatchMode yes\n  \
             ConnectTimeout 5\n",
            port = self.port,
            user = self.user.name,
            kh = self.known_hosts().display(),
        );
        fs::write(self.ssh_config(), cfg).unwrap();
    }

    fn spawn(&mut self, port: u16) -> Result<(), StartError> {
        self.port = port;
        self.write_sshd_config(port);
        let log_path = self.log_path();
        let offset = fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
        let stderr = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap();
        let mut child = Command::new(SSHD)
            .arg("-D")
            .arg("-E")
            .arg(&log_path)
            .arg("-f")
            .arg(self.dir().join("sshd_config"))
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
            .map_err(|e| StartError::Other(format!("cannot run {SSHD}: {e}")))?;

        let ready = format!("Server listening on 127.0.0.1 port {port}.");
        let start = Instant::now();
        loop {
            let log = fs::read(&log_path).unwrap_or_default();
            let new = String::from_utf8_lossy(log.get(offset as usize..).unwrap_or_default());
            if new.contains(&ready) {
                self.child = Some(child);
                return Ok(());
            }
            let in_use = new.contains("Address already in use");
            if in_use || start.elapsed() > READY_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                return Err(if in_use {
                    StartError::AddrInUse
                } else {
                    StartError::Other(format!("no \"{ready}\" in the log after {READY_TIMEOUT:?}"))
                });
            }
            if let Ok(Some(status)) = child.try_wait() {
                let log = fs::read(&log_path).unwrap_or_default();
                let new = String::from_utf8_lossy(log.get(offset as usize..).unwrap_or_default());
                if new.contains("Address already in use") {
                    return Err(StartError::AddrInUse);
                }
                return Err(StartError::Other(format!("sshd exited early: {status}")));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        if std::thread::panicking() && !self.reported {
            eprintln!("{}", self.diagnostics());
        }
        self.stop();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or_else(|e| panic!("test-support: cannot bind 127.0.0.1:0: {e}"))
}

fn keygen(path: &Path, home: &Path, comment: &str) {
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(path)
        .env("HOME", home)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| {
            panic!("test-support: cannot run ssh-keygen (install openssh-clients): {e}")
        });
    if !out.status.success() {
        panic!(
            "test-support: ssh-keygen failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn env_summary(user: &User) -> String {
    let version = Command::new("ssh")
        .arg("-V")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
        .unwrap_or_else(|e| format!("ssh -V failed: {e}"));
    format!(
        "user: {} uid={} gid={} passwd home={} (exists: {})\nssh: {version}",
        user.name,
        user.uid,
        user.gid,
        user.home.display(),
        user.home.exists()
    )
}
