//! SSH server provider: checks a key with a test login (FR-3, S-3, S-5).
//!
//! Runs the system `ssh` (SPEC 8) with arguments as a list, never a shell
//! string. Exit code 0 alone does not prove the key under test logged in:
//! `-i` adds to the `IdentityFile` list of the user's config, so an old key
//! from the config can log in instead (M1 plan, "Open item for T12"). So we
//! run `ssh -v -E <log>` and require that the main client authenticated
//! with `publickey` and that the last key the server accepted is the key
//! under test (by path and SHA256 fingerprint). Only the `-E` file is
//! parsed: a `ProxyJump` ssh, a server banner and the remote command write
//! to stderr, so they cannot fake these lines.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use identity_core::{Fingerprint, PublicKey};
use inventory::{LocationKind, Target};
use tokio::process::Command;

use crate::error::ProviderError;
use crate::netlog::NetLog;
use crate::provider::{AddOpts, KeyRef, Provider, PublicKeyRef, VerifyError, VerifyStatus};

/// Hard limit for one check, on top of `ConnectTimeout`.
const RUN_TIMEOUT: Duration = Duration::from_secs(60);

/// Options that make the check safe and free of side effects whatever the
/// user's config says. Command line options win over the config file.
/// All checked against OpenSSH 10.5p1.
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
            netlog,
        }
    }

    /// The `ssh` binary to run.
    pub fn with_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.program = program.into();
        self
    }

    /// Passes `-F <config>`.
    pub fn with_config(mut self, config: impl Into<PathBuf>) -> Self {
        self.config = Some(config.into());
        self
    }

    /// Passes `-o UserKnownHostsFile=<file>`.
    pub fn with_known_hosts(mut self, file: impl Into<PathBuf>) -> Self {
        self.known_hosts = Some(file.into());
        self
    }

    /// Sets `HOME` for ssh.
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Removes `SSH_AUTH_SOCK` for ssh.
    pub fn without_agent(mut self) -> Self {
        self.no_agent = true;
        self
    }

    /// The arguments for checking `identity` at `alias` (after `ssh`).
    /// `log` is the private file for `-E`.
    pub fn verify_args(&self, alias: &str, identity: &Path, log: &Path) -> Vec<OsString> {
        let mut args: Vec<OsString> = Vec::new();
        if let Some(cfg) = &self.config {
            args.push("-F".into());
            args.push(cfg.into());
        }
        if let Some(kh) = &self.known_hosts {
            let mut opt = OsString::from("UserKnownHostsFile=\"");
            opt.push(kh);
            opt.push("\"");
            args.push("-o".into());
            args.push(opt);
        }
        // -v prints "Server accepts key: ... SHA256:..." and
        // "Authenticated to ...". It wins over LogLevel in the config. -E
        // sends the main client's log, and only that, to our file.
        args.push("-v".into());
        args.push("-E".into());
        args.push(log.into());
        args.push("-T".into());
        for opt in FIXED_OPTIONS {
            args.push("-o".into());
            args.push((*opt).into());
        }
        args.push("-i".into());
        args.push(identity.into());
        args.push("--".into());
        args.push(alias.into());
        args.push("true".into());
        args
    }

    async fn run(&self, target: &Target, alias: &str, key: &KeyRef) -> VerifyStatus {
        let Some(identity) = &key.identity_file else {
            return VerifyStatus::Error(VerifyError::Other(
                "No private key file is known for this key.".into(),
            ));
        };
        let (_dir, log_path) = match private_log_file() {
            Ok(v) => v,
            Err(e) => {
                let s = VerifyStatus::Error(VerifyError::Other(format!(
                    "Cannot make a temp file for the ssh log: {e}"
                )));
                return s;
            }
        };
        let args = self.verify_args(alias, identity, &log_path);
        let action = render_command(&self.program, &args);
        let mut cmd = Command::new(&self.program);
        cmd.args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(home) = &self.home {
            cmd.env("HOME", home);
        }
        if self.no_agent {
            cmd.env_remove("SSH_AUTH_SOCK");
        }
        let (status, outcome) = match tokio::time::timeout(RUN_TIMEOUT, cmd.output()).await {
            Err(_) => {
                let s = VerifyStatus::Error(VerifyError::Unreachable(format!(
                    "no answer within {} seconds",
                    RUN_TIMEOUT.as_secs()
                )));
                (s, "timed out".to_string())
            }
            Ok(Err(e)) => {
                let s = VerifyStatus::Error(VerifyError::Other(format!(
                    "Cannot run {}: {e}",
                    self.program.display()
                )));
                (s, "could not start".to_string())
            }
            Ok(Ok(out)) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let log = read_capped(&log_path);
                let s = classify(out.status.code(), &log, &stderr, identity, &key.fingerprint);
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

/// A private dir (0700) with an empty log file (0600) for `ssh -E`. The
/// dir is removed when the returned guard drops.
fn private_log_file() -> std::io::Result<(tempfile::TempDir, PathBuf)> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = tempfile::Builder::new()
        .prefix("key-steward-ssh-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let path = dir.path().join("ssh.log");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    Ok((dir, path))
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

/// Maps ssh's exit code and its `-v -E` log to a result. All OpenSSH text
/// patterns live here (checked against OpenSSH 10.5p1, SPEC 15).
///
/// `log` is the main client's own log file; only it decides the result.
/// `stderr` (jump hosts, banner, remote command) is used only for an error
/// message when the log has none.
///
/// `Verified` needs all of: exit 0 (the command is `true`), a line
/// `Authenticated to ... using "publickey".`, no partial success, and the
/// last key the server accepted is `identity` with fingerprint `key`, not
/// a certificate.
pub fn classify(
    exit: Option<i32>,
    log: &str,
    stderr: &str,
    identity: &Path,
    key: &Fingerprint,
) -> VerifyStatus {
    let accepted: Vec<Accepted> = log
        .lines()
        .filter_map(|l| l.strip_prefix("debug1: Server accepts key: "))
        .map(|rest| parse_accepted(rest, identity, key))
        .collect();
    let ours_accepted = accepted
        .iter()
        .any(|a| matches!(a, Accepted::Ours | Accepted::OursCert));
    if log
        .lines()
        .any(|l| l.starts_with("Authenticated using ") && l.contains("with partial success"))
    {
        return VerifyStatus::Error(VerifyError::MoreThanOneKey);
    }
    let authenticated = log.lines().find(|l| l.starts_with("Authenticated to "));
    if let Some(line) = authenticated {
        if !line.ends_with(" using \"publickey\".") {
            return VerifyStatus::Error(VerifyError::Other("ssh logged in without a key.".into()));
        }
        if exit != Some(0) {
            return VerifyStatus::Error(VerifyError::Other(format!(
                "ssh logged in, but the test command failed ({}).",
                exit.map_or("killed".to_string(), |c| format!("exit {c}"))
            )));
        }
        return match accepted.last() {
            Some(Accepted::Ours) => VerifyStatus::Verified,
            Some(Accepted::OursCert) => VerifyStatus::Error(VerifyError::CertificateUsed),
            _ if ours_accepted => VerifyStatus::Error(VerifyError::KeyNotUsable),
            _ => VerifyStatus::Missing,
        };
    }
    if exit == Some(0) {
        return VerifyStatus::Error(VerifyError::Other(
            "ssh logged in, but did not say which key it used.".into(),
        ));
    }
    if log.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
        return VerifyStatus::Error(VerifyError::HostKeyChanged);
    }
    if log.contains("Host key verification failed.") {
        return VerifyStatus::Error(VerifyError::UnknownHostKey);
    }
    if log.contains("Permission denied (") {
        return if ours_accepted {
            VerifyStatus::Error(VerifyError::KeyNotUsable)
        } else {
            VerifyStatus::Missing
        };
    }
    const UNREACHABLE: &[&str] = &[
        "Connection refused",
        "Connection timed out",
        "Could not resolve hostname",
        "No route to host",
        "Network is unreachable",
        "Connection closed by",
        "Connection reset by",
    ];
    let message = last_message(log)
        .or_else(|| last_message(stderr))
        .unwrap_or_else(|| "ssh failed with no message".to_string());
    if UNREACHABLE.iter().any(|p| log.contains(p)) {
        return VerifyStatus::Error(VerifyError::Unreachable(message));
    }
    VerifyStatus::Error(VerifyError::Other(message))
}

enum Accepted {
    Ours,
    OursCert,
    Other,
}

/// Reads the rest of `debug1: Server accepts key: <path> <TYPE> SHA256:<fp>
/// [explicit] [token] [agent]`. It is ours only if the path is exactly the
/// `-i` path, the fingerprint is ours and nothing else follows, so an agent
/// key whose comment imitates our line does not match.
fn parse_accepted(rest: &str, identity: &Path, key: &Fingerprint) -> Accepted {
    let Some(after) = identity
        .to_str()
        .and_then(|id| rest.strip_prefix(id))
        .and_then(|r| r.strip_prefix(' '))
    else {
        return Accepted::Other;
    };
    let mut words = after.split(' ');
    let (Some(kind), Some(fp)) = (words.next(), words.next()) else {
        return Accepted::Other;
    };
    if fp != key.as_str() || !words.all(|w| matches!(w, "explicit" | "token" | "agent")) {
        return Accepted::Other;
    }
    if kind.ends_with("-CERT") {
        Accepted::OursCert
    } else {
        Accepted::Ours
    }
}

/// The last line that is not debug output.
fn last_message(text: &str) -> Option<String> {
    text.lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.starts_with("debug") && !l.is_empty())
        .map(str::to_string)
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

    async fn verify(&self, target: &Target, key: &KeyRef) -> Result<VerifyStatus, ProviderError> {
        let Target::Ssh(host) = target else {
            return Err(ProviderError::WrongTarget {
                kind: LocationKind::SshServer,
            });
        };
        Ok(self.run(target, &host.alias, key).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEW: &str = "SHA256:i+Q6tU5ofv97ruxRVjNOiScwa467+cfaBreYtWhdMZE";
    const OLD: &str = "SHA256:lTiAAGWHw8nN4UiFBfg1s7GMPp3o5XmvBsS/HxNB4nE";
    const AUTH: &str = "Authenticated to 127.0.0.1 ([127.0.0.1]:22022) using \"publickey\".\n";

    fn c(exit: i32, log: &str) -> VerifyStatus {
        classify(
            Some(exit),
            log,
            "",
            Path::new("/k/new key"),
            &Fingerprint::Ssh(NEW.into()),
        )
    }

    fn accepts(path: &str, kind: &str, fp: &str) -> String {
        format!("debug1: Server accepts key: {path} {kind} {fp} explicit\n")
    }

    // Lines as OpenSSH 10.5p1 writes them to the -E log, trimmed.
    #[test]
    fn verified_needs_our_key_accepted_last() {
        let ok = accepts("/k/new key", "ED25519", NEW) + AUTH;
        assert_eq!(c(0, &ok), VerifyStatus::Verified);
        // The command is `true`: another exit code is not a clean login.
        assert!(matches!(
            c(1, &ok),
            VerifyStatus::Error(VerifyError::Other(_))
        ));
        let old = accepts("/k/old", "ED25519", OLD) + AUTH;
        assert_eq!(c(0, &old), VerifyStatus::Missing);
        let not_usable = accepts("/k/new key", "ED25519", NEW) + &old;
        assert_eq!(
            c(0, &not_usable),
            VerifyStatus::Error(VerifyError::KeyNotUsable)
        );
        assert!(matches!(
            c(0, ""),
            VerifyStatus::Error(VerifyError::Other(_))
        ));
        let not_key = "Authenticated to h ([127.0.0.1]:22) using \"password\".\n";
        assert!(matches!(
            c(0, &(accepts("/k/new key", "ED25519", NEW) + not_key)),
            VerifyStatus::Error(VerifyError::Other(_))
        ));
    }

    #[test]
    fn certificate_and_partial_success_are_not_verified() {
        let cert = accepts("/k/new key", "ED25519-CERT", NEW) + AUTH;
        assert_eq!(
            c(0, &cert),
            VerifyStatus::Error(VerifyError::CertificateUsed)
        );
        let partial = accepts("/k/new key", "ED25519", NEW)
            + "Authenticated using \"publickey\" with partial success.\n"
            + &accepts("/k/old", "ED25519", OLD)
            + AUTH;
        assert_eq!(
            c(0, &partial),
            VerifyStatus::Error(VerifyError::MoreThanOneKey)
        );
    }

    #[test]
    fn accepted_line_must_match_path_and_end() {
        let k = Fingerprint::Ssh(NEW.into());
        let id = Path::new("/k/new key");
        let ours = |rest: &str| matches!(parse_accepted(rest, id, &k), Accepted::Ours);
        assert!(ours(&format!("/k/new key ED25519 {NEW} explicit")));
        assert!(ours(&format!("/k/new key ED25519 {NEW} explicit agent")));
        assert!(ours(&format!("/k/new key ED25519 {NEW}")));
        assert!(!ours(&format!("/k/new ED25519 {NEW} explicit")));
        assert!(!ours(&format!("/k/other ED25519 {NEW} explicit")));
        assert!(!ours(&format!("/k/new key ED25519 {OLD} explicit")));
        // An agent key whose comment copies our line.
        assert!(!ours(&format!(
            "/k/new key ED25519 {NEW} ED25519 {OLD} agent"
        )));
    }

    #[test]
    fn stderr_mapping() {
        assert_eq!(
            c(255, "dev@127.0.0.1: Permission denied (publickey).\n"),
            VerifyStatus::Missing
        );
        let unknown = "No ED25519 host key is known for [127.0.0.1]:22022 and you have \
                       requested strict checking.\nHost key verification failed.\n";
        assert_eq!(
            c(255, unknown),
            VerifyStatus::Error(VerifyError::UnknownHostKey)
        );
        let changed = "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
                       Host key verification failed.\n";
        assert_eq!(
            c(255, changed),
            VerifyStatus::Error(VerifyError::HostKeyChanged)
        );
        let refused = "debug1: Connecting to 127.0.0.1 [127.0.0.1] port 1.\n\
                       ssh: connect to host 127.0.0.1 port 1: Connection refused\n";
        assert_eq!(
            c(255, refused),
            VerifyStatus::Error(VerifyError::Unreachable(
                "ssh: connect to host 127.0.0.1 port 1: Connection refused".into()
            ))
        );
        assert_eq!(
            c(255, "debug1: x\nsomething odd\ndebug1: y\n"),
            VerifyStatus::Error(VerifyError::Other("something odd".into()))
        );
    }

    #[test]
    fn stderr_never_decides_the_result() {
        let fake = accepts("/k/new key", "ED25519", NEW) + AUTH;
        let got = classify(
            Some(255),
            "",
            &(fake + "dev@h: Permission denied (publickey).\n"),
            Path::new("/k/new key"),
            &Fingerprint::Ssh(NEW.into()),
        );
        assert_eq!(
            got,
            VerifyStatus::Error(VerifyError::Other(
                "dev@h: Permission denied (publickey).".into()
            ))
        );
    }

    #[test]
    fn verify_args_are_fixed_and_safe() {
        let p = SshServer::new(NetLog::new())
            .with_config("/t/cfg")
            .with_known_hosts("/t/k h");
        let args: Vec<String> = p
            .verify_args("-oProxyCommand=x", Path::new("/k/id"), Path::new("/p/log"))
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        let joined = args.join(" ");
        for want in [
            "-F /t/cfg",
            "-o UserKnownHostsFile=\"/t/k h\"",
            "-v",
            "-E /p/log",
            "-o BatchMode=yes",
            "-o IdentitiesOnly=yes",
            "-o ConnectTimeout=10",
            "-o StrictHostKeyChecking=yes",
            "-o FingerprintHash=sha256",
            "-o ControlPath=none",
            "-o AddKeysToAgent=no",
            "-o ForwardAgent=no",
            "-o PreferredAuthentications=publickey",
            "-i /k/id",
        ] {
            assert!(joined.contains(want), "{want} not in {joined}");
        }
        // The alias comes after `--`, so it can never be read as an option.
        assert_eq!(&args[args.len() - 3..], ["--", "-oProxyCommand=x", "true"]);
    }

    #[test]
    fn log_file_is_private() {
        use std::os::unix::fs::MetadataExt;
        let (dir, path) = private_log_file().unwrap();
        assert_eq!(std::fs::metadata(dir.path()).unwrap().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let d = dir.path().to_path_buf();
        drop(dir);
        assert!(!d.exists());
    }
}
