//! SSH server provider: checks a key with a test login (FR-3, S-3, S-5).
//!
//! Runs the system `ssh` (SPEC 8) with arguments as a list, never a shell
//! string. Exit code 0 alone does not prove the key under test logged in:
//! `-i` adds to the `IdentityFile` list of the user's config, so an old key
//! from the config can log in instead (M1 plan, "Open item for T12"). So we
//! run `ssh -v` and require that the last key the server accepted before
//! authentication is the key under test, by SHA256 fingerprint.

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

/// Options that make the check safe whatever the user's config says.
/// Command line options win over the config file.
const FIXED_OPTIONS: &[&str] = &[
    // FR-3, S-5: never prompt, never accept an unknown host key.
    "BatchMode=yes",
    "IdentitiesOnly=yes",
    "ConnectTimeout=10",
    "StrictHostKeyChecking=yes",
    // Read-only check: do not add host keys to known_hosts.
    "UpdateHostKeys=no",
    // The fingerprint we compare with is SHA256 (`ssh-keygen -l` default).
    "FingerprintHash=sha256",
    // Never reuse a multiplexed connection: it skips authentication.
    "ControlMaster=no",
    "ControlPath=none",
    // Nothing else may run or listen because of the check.
    "ClearAllForwardings=yes",
    "PermitLocalCommand=no",
    "RemoteCommand=none",
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
    pub fn verify_args(&self, alias: &str, identity: &Path) -> Vec<OsString> {
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
        // "Authenticated to ...". It wins over LogLevel in the config.
        args.push("-v".into());
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
        let args = self.verify_args(alias, identity);
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
                let s = classify(out.status.code(), &stderr, &key.fingerprint);
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

/// Maps ssh's exit code and `-v` stderr to a result. All OpenSSH text
/// patterns live here (checked against OpenSSH 10.5p1, SPEC 15).
///
/// `Verified` needs both: ssh authenticated, and the last key the server
/// accepted is `key`. The exit code is not used for that: it is the remote
/// command's, and an old key from the config can log in instead (S-3).
pub fn classify(exit: Option<i32>, stderr: &str, key: &Fingerprint) -> VerifyStatus {
    let accepted = accepted_keys(stderr);
    let ours_accepted = accepted.contains(&key.as_str());
    if stderr.lines().any(|l| l.starts_with("Authenticated to ")) {
        return match accepted.last() {
            Some(last) if *last == key.as_str() => VerifyStatus::Verified,
            _ if ours_accepted => VerifyStatus::Error(VerifyError::KeyNotUsable),
            _ => VerifyStatus::Missing,
        };
    }
    if exit == Some(0) {
        return VerifyStatus::Error(VerifyError::Other(
            "ssh logged in, but did not say which key it used.".into(),
        ));
    }
    if stderr.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
        return VerifyStatus::Error(VerifyError::HostKeyChanged);
    }
    if stderr.contains("Host key verification failed.") {
        return VerifyStatus::Error(VerifyError::UnknownHostKey);
    }
    if stderr.contains("Permission denied (") {
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
    let message = last_message(stderr);
    if UNREACHABLE.iter().any(|p| stderr.contains(p)) {
        return VerifyStatus::Error(VerifyError::Unreachable(message));
    }
    VerifyStatus::Error(VerifyError::Other(message))
}

/// SHA256 fingerprints from `debug1: Server accepts key: <path> <type>
/// SHA256:<fp> [explicit|agent]` lines, in order. The path may hold spaces,
/// so the fingerprint is the last word that starts with `SHA256:`.
fn accepted_keys(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter_map(|l| l.strip_prefix("debug1: Server accepts key: "))
        .filter_map(|rest| {
            rest.split_whitespace()
                .rev()
                .find(|w| w.starts_with("SHA256:"))
        })
        .collect()
}

/// The last line that is not debug output.
fn last_message(stderr: &str) -> String {
    stderr
        .lines()
        .rev()
        .find(|l| !l.starts_with("debug") && !l.trim().is_empty())
        .unwrap_or("ssh failed with no message")
        .trim()
        .to_string()
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

    fn new_key() -> Fingerprint {
        Fingerprint::Ssh(NEW.into())
    }

    // Captured from OpenSSH 10.5p1 (`ssh -v`), trimmed.
    fn old_key_logged_in() -> String {
        format!(
            "debug1: Offering public key: /k/new key ED25519 {NEW} explicit\n\
             debug1: Offering public key: /k/old ED25519 {OLD} explicit\n\
             debug1: Server accepts key: /k/old ED25519 {OLD} explicit\n\
             Authenticated to 127.0.0.1 ([127.0.0.1]:22022) using \"publickey\".\n"
        )
    }

    #[test]
    fn verified_needs_our_key_accepted_last() {
        let ok = format!(
            "debug1: Server accepts key: /k/new key ED25519 {NEW} explicit\n\
             Authenticated to 127.0.0.1 ([127.0.0.1]:22022) using \"publickey\".\n"
        );
        assert_eq!(classify(Some(0), &ok, &new_key()), VerifyStatus::Verified);
        // The remote command's exit code does not matter.
        assert_eq!(classify(Some(1), &ok, &new_key()), VerifyStatus::Verified);
        assert_eq!(
            classify(Some(0), &old_key_logged_in(), &new_key()),
            VerifyStatus::Missing
        );
        let not_usable = format!(
            "debug1: Server accepts key: /k/new ED25519 {NEW} explicit\n\
             debug1: Server accepts key: /k/old ED25519 {OLD} explicit\n\
             Authenticated to 127.0.0.1 ([127.0.0.1]:22022) using \"publickey\".\n"
        );
        assert_eq!(
            classify(Some(0), &not_usable, &new_key()),
            VerifyStatus::Error(VerifyError::KeyNotUsable)
        );
        assert!(matches!(
            classify(Some(0), "", &new_key()),
            VerifyStatus::Error(VerifyError::Other(_))
        ));
    }

    #[test]
    fn stderr_mapping() {
        let k = new_key();
        assert_eq!(
            classify(
                Some(255),
                "dev@127.0.0.1: Permission denied (publickey).\n",
                &k
            ),
            VerifyStatus::Missing
        );
        let unknown = "No ED25519 host key is known for [127.0.0.1]:22022 and you have \
                       requested strict checking.\nHost key verification failed.\n";
        assert_eq!(
            classify(Some(255), unknown, &k),
            VerifyStatus::Error(VerifyError::UnknownHostKey)
        );
        let changed = "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
                       Host key verification failed.\n";
        assert_eq!(
            classify(Some(255), changed, &k),
            VerifyStatus::Error(VerifyError::HostKeyChanged)
        );
        let refused = "debug1: Connecting to 127.0.0.1 [127.0.0.1] port 1.\n\
                       ssh: connect to host 127.0.0.1 port 1: Connection refused\n";
        assert_eq!(
            classify(Some(255), refused, &k),
            VerifyStatus::Error(VerifyError::Unreachable(
                "ssh: connect to host 127.0.0.1 port 1: Connection refused".into()
            ))
        );
        assert_eq!(
            classify(Some(255), "debug1: x\nsomething odd\ndebug1: y\n", &k),
            VerifyStatus::Error(VerifyError::Other("something odd".into()))
        );
    }

    #[test]
    fn accepted_key_path_may_hold_spaces() {
        let line = format!("debug1: Server accepts key: /k/a SHA256:x b ED25519 {NEW} agent\n");
        assert_eq!(accepted_keys(&line), vec![NEW]);
    }

    #[test]
    fn verify_args_are_fixed_and_safe() {
        let p = SshServer::new(NetLog::new())
            .with_config("/t/cfg")
            .with_known_hosts("/t/k h");
        let args: Vec<String> = p
            .verify_args("-oProxyCommand=x", Path::new("/k/id"))
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        let joined = args.join(" ");
        for want in [
            "-F /t/cfg",
            "-o UserKnownHostsFile=\"/t/k h\"",
            "-v",
            "-o BatchMode=yes",
            "-o IdentitiesOnly=yes",
            "-o ConnectTimeout=10",
            "-o StrictHostKeyChecking=yes",
            "-o FingerprintHash=sha256",
            "-o ControlPath=none",
            "-i /k/id",
        ] {
            assert!(joined.contains(want), "{want} not in {joined}");
        }
        // The alias comes after `--`, so it can never be read as an option.
        assert_eq!(&args[args.len() - 3..], ["--", "-oProxyCommand=x", "true"]);
    }
}
