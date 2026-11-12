//! SSH server provider: checks a key with a test login (FR-3, S-3, S-5).
//!
//! Runs the system `ssh` (SPEC 8) with arguments as a list, never a shell
//! string. Two guards stop a login with another key from counting:
//!
//! 1. Structural (`config.rs`): the target is resolved with `ssh -G` and
//!    checked with a generated temp config in which the key under test is
//!    the target's only identity. Jump hosts keep their own identities.
//! 2. The log (`classify.rs`): `ssh -v -E <log>` must show the key under
//!    test, and only it, logging in. Only the main client writes to that
//!    file; a jump ssh, a server banner and the remote command write to
//!    stderr.
//!
//! `ssh -G` runs `Match exec` commands from the user's config, so a config
//! with them is refused unless the user agreed (S-7), as in the import.

mod classify;
mod config;

use std::collections::{HashSet, VecDeque};
use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use identity_core::{Fingerprint, PublicKey};
use inventory::{LocationKind, Target};
use tokio::process::Command;

pub use classify::classify;

use crate::error::ProviderError;
use crate::netlog::NetLog;
use crate::provider::{AddOpts, KeyRef, Provider, PublicKeyRef, VerifyError, VerifyStatus};

/// Hard limit for one check, on top of `ConnectTimeout`.
const RUN_TIMEOUT: Duration = Duration::from_secs(60);
/// Limit for each `ssh -G` run.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Most jump hosts one target may go through.
const MAX_HOPS: usize = 16;

/// Options that make the check safe and free of side effects. They are
/// written into the target block of the temp config and also passed on the
/// command line. All checked against OpenSSH 10.5p1.
const FIXED_OPTIONS: &[&str] = &[
    // FR-3, S-5: never prompt, never accept an unknown host key.
    "BatchMode=yes",
    "IdentitiesOnly=yes",
    "ConnectTimeout=10",
    "StrictHostKeyChecking=yes",
    "VerifyHostKeyDNS=no",
    // Only key logins count.
    "PreferredAuthentications=publickey",
    "GSSAPIAuthentication=no",
    "HostbasedAuthentication=no",
    // Read-only check: no new host keys in known_hosts, no key added to the
    // user's agent.
    "UpdateHostKeys=no",
    "AddKeysToAgent=no",
    // The fingerprint we compare with is SHA256 (`ssh-keygen -l` default).
    "FingerprintHash=sha256",
    // Never reuse a multiplexed connection: it skips authentication.
    "ControlMaster=no",
    "ControlPath=none",
    // Nothing else may run, listen or be forwarded because of the check.
    "ClearAllForwardings=yes",
    "ForwardAgent=no",
    "ForwardX11=no",
    "PermitLocalCommand=no",
    "RemoteCommand=none",
    "SessionType=default",
    "ForkAfterAuthentication=no",
    "LogVerbose=none",
    "ServerAliveInterval=5",
    "ServerAliveCountMax=3",
];

/// SSH server checks. Tests point it at the test sshd with
/// [`with_config`](Self::with_config) and [`with_known_hosts`](Self::with_known_hosts),
/// since OpenSSH finds `~` from passwd, not `$HOME`.
#[derive(Debug, Clone)]
pub struct SshServer {
    program: PathBuf,
    config: Option<PathBuf>,
    known_hosts: Option<PathBuf>,
    home: Option<PathBuf>,
    no_agent: bool,
    allow_commands: bool,
    netlog: NetLog,
}

impl SshServer {
    pub fn new(netlog: NetLog) -> Self {
        SshServer {
            program: PathBuf::from("ssh"),
            config: None,
            known_hosts: None,
            home: None,
            no_agent: false,
            allow_commands: false,
            netlog,
        }
    }

    /// The `ssh` binary to run.
    pub fn with_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.program = program.into();
        self
    }

    /// The user's ssh config, passed to `ssh -G -F`. Without it, ssh reads
    /// `~/.ssh/config` and `/etc/ssh/ssh_config`.
    pub fn with_config(mut self, config: impl Into<PathBuf>) -> Self {
        self.config = Some(config.into());
        self
    }

    /// Passes `-o UserKnownHostsFile=<file>` for the target.
    pub fn with_known_hosts(mut self, file: impl Into<PathBuf>) -> Self {
        self.known_hosts = Some(file.into());
        self
    }

    /// Sets `HOME` for ssh, and is the home for relative `Include` paths.
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Removes `SSH_AUTH_SOCK` for ssh.
    pub fn without_agent(mut self) -> Self {
        self.no_agent = true;
        self
    }

    /// Run `ssh -G` even if the config has `Match exec` (or an `Include`
    /// we cannot check). Set it only after the user agreed. Default: false.
    pub fn with_allow_commands(mut self, allow: bool) -> Self {
        self.allow_commands = allow;
        self
    }

    /// The arguments for the check (after `ssh`): `config` is the temp
    /// config, `log` the private file for `-E`.
    pub fn verify_args(&self, alias: &str, config: &Path, log: &Path) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec!["-F".into(), config.into()];
        if let Some(kh) = &self.known_hosts {
            let mut opt = OsString::from("UserKnownHostsFile=\"");
            opt.push(kh);
            opt.push("\"");
            args.push("-o".into());
            args.push(opt);
        }
        // -v prints "Server accepts key: ... SHA256:..." and
        // "Authenticated to ...". -E sends the main client's log, and only
        // that, to our file.
        args.push("-v".into());
        args.push("-E".into());
        args.push(log.into());
        args.push("-T".into());
        for opt in FIXED_OPTIONS {
            args.push("-o".into());
            args.push((*opt).into());
        }
        args.push("--".into());
        args.push(alias.into());
        args.push("true".into());
        args
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.program);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(home) = &self.home {
            cmd.env("HOME", home);
        }
        if self.no_agent {
            cmd.env_remove("SSH_AUTH_SOCK");
        }
        cmd
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.home
            .clone()
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
    }

    /// Refuses a config that can make `ssh -G` run commands, unless allowed.
    fn check_commands(&self) -> Result<(), ProviderError> {
        if self.allow_commands {
            return Ok(());
        }
        let home = self.home_dir().unwrap_or_default();
        let files: Vec<PathBuf> = match &self.config {
            Some(cfg) => vec![cfg.clone()],
            None => [
                home.join(".ssh/config"),
                PathBuf::from("/etc/ssh/ssh_config"),
            ]
            .into_iter()
            .filter(|p| p.exists())
            .collect(),
        };
        let mut reasons = Vec::new();
        for file in files {
            let scan = inventory::scan_config(&file, &home)
                .map_err(|e| ProviderError::Config(e.to_string()))?;
            reasons.extend(scan.runs_commands);
        }
        if reasons.is_empty() {
            Ok(())
        } else {
            Err(ProviderError::CommandsNeedConsent(reasons))
        }
    }

    /// `ssh -G [-F config] [extra] -- host`.
    async fn resolve(&self, extra: &[OsString], host: &str) -> Result<config::Options, String> {
        let mut cmd = self.command();
        cmd.arg("-G");
        if let Some(cfg) = &self.config {
            cmd.arg("-F").arg(cfg);
        }
        cmd.args(extra).arg("--").arg(host).stdout(Stdio::piped());
        let out = match tokio::time::timeout(RESOLVE_TIMEOUT, cmd.output()).await {
            Err(_) => return Err(format!("ssh -G {host} took too long; stopped")),
            Ok(Err(e)) => return Err(format!("Cannot run {}: {e}", self.program.display())),
            Ok(Ok(out)) => out,
        };
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let err: Vec<&str> = err
                .lines()
                .filter(|l| !l.starts_with("Pseudo-terminal will not be allocated"))
                .collect();
            return Err(format!("ssh -G {host} failed: {}", err.join(" ").trim()));
        }
        Ok(config::parse_g(&String::from_utf8_lossy(&out.stdout)))
    }

    /// The temp config text: the target block, then one block per jump
    /// host (following each jump's own `ProxyJump`).
    async fn build_config(&self, alias: &str, identity: &Path) -> Result<String, String> {
        let target = self.resolve(&[], alias).await?;
        let mut text = config::target_block(alias, &target, identity, FIXED_OPTIONS);
        let mut queue: VecDeque<config::Hop> = VecDeque::new();
        if let Some(jumps) = config::get(&target, "proxyjump") {
            queue.extend(config::parse_jumps(jumps)?);
        }
        let mut seen: HashSet<String> = HashSet::from([alias.to_string()]);
        let mut hops = 0;
        while let Some(hop) = queue.pop_front() {
            if !seen.insert(hop.host.clone()) {
                continue;
            }
            hops += 1;
            if hops > MAX_HOPS {
                return Err(format!("more than {MAX_HOPS} jump hosts"));
            }
            let mut extra: Vec<OsString> = Vec::new();
            if let Some(u) = &hop.user {
                extra.push("-l".into());
                extra.push(u.into());
            }
            if let Some(p) = hop.port {
                extra.push("-p".into());
                extra.push(p.to_string().into());
            }
            let opts = self.resolve(&extra, &hop.host).await?;
            if let Some(jumps) = config::get(&opts, "proxyjump") {
                queue.extend(config::parse_jumps(jumps)?);
            }
            text.push_str(&config::jump_block(&hop.host, &opts));
        }
        Ok(text)
    }

    async fn run(&self, target: &Target, alias: &str, key: &KeyRef) -> VerifyStatus {
        let fail = |why: String| VerifyStatus::Error(VerifyError::Other(why));
        let Some(identity) = &key.identity_file else {
            return fail("No private key file is known for this key.".into());
        };
        if !config::is_plain_name(alias) {
            return fail(format!("Cannot check the host alias {alias:?}."));
        }
        let work = match Workdir::new(identity) {
            Ok(w) => w,
            Err(e) => return fail(format!("Cannot make a temp dir for the check: {e}")),
        };
        let text = match self.build_config(alias, &work.identity).await {
            Ok(t) => t,
            Err(why) => {
                self.netlog.record(
                    LocationKind::SshServer,
                    target,
                    format!("ssh -G {alias}"),
                    format!("error: {why}"),
                );
                return fail(why);
            }
        };
        if let Err(e) = work.write_config(&text) {
            return fail(format!("Cannot write the temp ssh config: {e}"));
        }
        let args = self.verify_args(alias, &work.config, &work.log);
        let action = render_command(&self.program, &args);
        let mut cmd = self.command();
        cmd.args(&args);
        let (status, outcome) = match tokio::time::timeout(RUN_TIMEOUT, cmd.output()).await {
            Err(_) => {
                let s = VerifyStatus::Error(VerifyError::Unreachable(format!(
                    "no answer within {} seconds",
                    RUN_TIMEOUT.as_secs()
                )));
                (s, "timed out".to_string())
            }
            Ok(Err(e)) => (
                fail(format!("Cannot run {}: {e}", self.program.display())),
                "could not start".to_string(),
            ),
            Ok(Ok(out)) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let log = read_capped(&work.log);
                let s = classify(
                    out.status.code(),
                    &log,
                    &stderr,
                    &work.identity,
                    &key.fingerprint,
                );
                let code = match out.status.code() {
                    Some(c) => format!("exit {c}"),
                    None => "killed".to_string(),
                };
                (s.clone(), format!("{code}, {}", describe(&s)))
            }
        };
        self.netlog
            .record(LocationKind::SshServer, target, action, outcome);
        status
    }
}

/// A private temp dir (0700) for one check, removed on drop:
/// `id` and `id.pub` are symlinks to the key under test (the key is never
/// read, S-1). The fixed name means ssh finds no `<key>-cert.pub` next to
/// it. `config` is the generated config, `log` the `-E` file (both 0600).
struct Workdir {
    _dir: tempfile::TempDir,
    identity: PathBuf,
    config: PathBuf,
    log: PathBuf,
}

impl Workdir {
    fn new(identity: &Path) -> std::io::Result<Workdir> {
        let identity = std::path::absolute(identity)?;
        let dir = tempfile::Builder::new()
            .prefix("key-steward-ssh-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let link = dir.path().join("id");
        std::os::unix::fs::symlink(&identity, &link)?;
        let mut public = identity.into_os_string();
        public.push(".pub");
        let public = PathBuf::from(public);
        if public.exists() {
            std::os::unix::fs::symlink(&public, dir.path().join("id.pub"))?;
        }
        let log = dir.path().join("ssh.log");
        new_private_file(&log)?;
        Ok(Workdir {
            config: dir.path().join("ssh_config"),
            identity: link,
            log,
            _dir: dir,
        })
    }

    fn write_config(&self, text: &str) -> std::io::Result<()> {
        new_private_file(&self.config)?.write_all(text.as_bytes())
    }
}

fn new_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Reads at most 1 MB of the ssh log.
fn read_capped(path: &Path) -> String {
    use std::io::Read;
    let mut buf = Vec::new();
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.take(1_000_000).read_to_end(&mut buf);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn render_command(program: &Path, args: &[OsString]) -> String {
    let mut out = program.display().to_string();
    for a in args {
        out.push(' ');
        out.push_str(&a.to_string_lossy());
    }
    out
}

fn describe(s: &VerifyStatus) -> String {
    match s {
        VerifyStatus::Verified => "verified".into(),
        VerifyStatus::Missing => "missing".into(),
        VerifyStatus::Error(e) => format!("error: {e:?}"),
    }
}

#[async_trait]
impl Provider for SshServer {
    fn kind(&self) -> LocationKind {
        LocationKind::SshServer
    }

    async fn list(&self, _target: &Target) -> Result<Vec<PublicKeyRef>, ProviderError> {
        Err(ProviderError::NotYet("listing keys on an SSH server (M2)"))
    }

    async fn add(
        &self,
        _target: &Target,
        _key: &PublicKey,
        _opts: &AddOpts,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::NotYet("adding a key to an SSH server (M2)"))
    }

    async fn remove(&self, _target: &Target, _key: &Fingerprint) -> Result<(), ProviderError> {
        Err(ProviderError::NotYet(
            "removing a key from an SSH server (M2)",
        ))
    }

    /// Errors with [`ProviderError::CommandsNeedConsent`] if the config can
    /// run commands and [`SshServer::with_allow_commands`] is not set.
    async fn verify(&self, target: &Target, key: &KeyRef) -> Result<VerifyStatus, ProviderError> {
        let Target::Ssh(host) = target else {
            return Err(ProviderError::WrongTarget {
                kind: LocationKind::SshServer,
            });
        };
        self.check_commands()?;
        Ok(self.run(target, &host.alias, key).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_args_are_fixed_and_safe() {
        let p = SshServer::new(NetLog::new()).with_known_hosts("/t/k h");
        let args: Vec<String> = p
            .verify_args("box", Path::new("/p/cfg"), Path::new("/p/log"))
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        let joined = args.join(" ");
        for want in [
            "-F /p/cfg",
            "-o UserKnownHostsFile=\"/t/k h\"",
            "-v",
            "-E /p/log",
            "-o BatchMode=yes",
            "-o IdentitiesOnly=yes",
            "-o StrictHostKeyChecking=yes",
            "-o FingerprintHash=sha256",
            "-o ControlPath=none",
            "-o AddKeysToAgent=no",
            "-o ForwardAgent=no",
            "-o LogVerbose=none",
        ] {
            assert!(joined.contains(want), "{want} not in {joined}");
        }
        assert!(!args.contains(&"-i".to_string()), "{joined}");
        assert_eq!(&args[args.len() - 3..], ["--", "box", "true"]);
    }

    #[test]
    fn workdir_is_private_and_links_the_key() {
        use std::os::unix::fs::MetadataExt;
        let keys = tempfile::tempdir().unwrap();
        let key = keys.path().join("new");
        std::fs::write(&key, "not read").unwrap();
        std::fs::write(keys.path().join("new.pub"), "pub").unwrap();
        std::fs::write(keys.path().join("new-cert.pub"), "cert").unwrap();
        let w = Workdir::new(&key).unwrap();
        let dir = w.identity.parent().unwrap().to_path_buf();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(&w.log).unwrap().mode() & 0o777, 0o600);
        w.write_config("Host x\n").unwrap();
        assert_eq!(std::fs::metadata(&w.config).unwrap().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_link(&w.identity).unwrap(), key);
        assert!(dir.join("id.pub").exists());
        assert!(!dir.join("id-cert.pub").exists());
        drop(w);
        assert!(!dir.exists());
    }
}
