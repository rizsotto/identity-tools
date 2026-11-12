//! Reading `~/.ssh/authorized_keys` over ssh (SPEC 9.1, S-3, S-5, S-6).
//!
//! Every run logs in with one given key, pinned as the target's only
//! identity in the generated config of the check (`build_config`), so it
//! reaches the host the check verified. Two guards decide that the run
//! counts: the `-v -E` log must show that key logging in (`classify`),
//! and the script's output must start with its marker line. A forced
//! command (`command=` on the login key's line) or a shell that prints
//! text fails the marker check, before any change.
//!
//! File contents and keys never go into the network log or error text.

use std::process::Stdio;

use inventory::{LocationKind, Purpose, Status, Target};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::authorized_keys::{AuthorizedKeys, EditError, MAX_FILE};
use super::remote::{self, Cksum, ProtocolError, ReadReply, Script};
use super::{RUN_TIMEOUT, SshServer, Workdir, config, read_capped, render_command};
use crate::error::ProviderError;
use crate::provider::{KeyRef, PublicKeyRef, VerifyStatus};

/// Most bytes kept from the script's stdout. More than the read script
/// may send, so a longer answer is refused as too large.
const MAX_STDOUT: usize = MAX_FILE + 4096;
/// Most bytes kept from ssh's stderr (jump hosts, banner, remote errors).
const MAX_STDERR: usize = 64 * 1024;

/// Why reading or editing `authorized_keys` on a server failed. Nothing
/// was changed on the server unless the text says so.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizedKeysError {
    #[error("no key to log in with was given")]
    NoLoginKey,
    #[error("{0}")]
    Unsupported(&'static str),
    /// A local problem before ssh ran (temp dir, config, starting ssh).
    #[error("{0}")]
    Setup(String),
    /// The login with the given key did not work, or used another key.
    #[error("logging in with the given key failed: {}", login_reason(.0))]
    Login(VerifyStatus),
    /// [`ProtocolError::NoMarker`]: a forced command or shell output.
    #[error("{0}")]
    Protocol(#[from] ProtocolError),
    #[error("~/.ssh/authorized_keys on the server is a symlink; Key Steward does not edit it")]
    Symlink,
    #[error("~/.ssh/authorized_keys on the server is not a regular file")]
    NotFile,
    #[error("~/.ssh/authorized_keys does not exist on the server (does sshd read another file?)")]
    Absent,
    #[error("~/.ssh/authorized_keys on the server is larger than {MAX_FILE} bytes")]
    TooLarge,
    /// The script stopped with one of its fixed error words.
    #[error("the script on the server failed ({0})")]
    Script(String),
    #[error(transparent)]
    Edit(#[from] EditError),
}

impl From<ProtocolError> for ProviderError {
    fn from(e: ProtocolError) -> Self {
        AuthorizedKeysError::from(e).into()
    }
}

impl From<EditError> for ProviderError {
    fn from(e: EditError) -> Self {
        AuthorizedKeysError::from(e).into()
    }
}

fn login_reason(s: &VerifyStatus) -> String {
    match s.to_status() {
        Status::Error(why) => why,
        Status::Missing => "the server does not accept the key".into(),
        other => format!("{other:?}"),
    }
}

impl SshServer {
    /// The keys in `~/.ssh/authorized_keys`, logging in with `login`: one
    /// entry per login key line (CA lines left out), purpose `SshAuth`,
    /// `remote_id` the line number, `title` the comment made safe to show.
    pub async fn list_as(
        &self,
        target: &Target,
        login: &KeyRef,
    ) -> Result<Vec<PublicKeyRef>, ProviderError> {
        let (content, _) = self.read_file(target, login).await?;
        let file = AuthorizedKeys::parse(&content)?;
        Ok(file
            .keys()
            .filter(|k| !k.cert_authority)
            .map(|k| PublicKeyRef {
                fingerprint: k.key.fingerprint.clone(),
                purpose: Purpose::SshAuth,
                title: k.key.comment_display().filter(|c| !c.is_empty()),
                remote_id: Some(k.line.to_string()),
            })
            .collect())
    }

    /// The file and its checksum, logging in with `login`.
    pub(super) async fn read_file(
        &self,
        target: &Target,
        login: &KeyRef,
    ) -> Result<(Vec<u8>, Cksum), ProviderError> {
        let out = self
            .run_script(target, login, remote::READ, remote::read_stdin())
            .await?;
        let err = match remote::parse_read(&out)? {
            ReadReply::Present { content, sum } => return Ok((content, sum)),
            ReadReply::Absent => AuthorizedKeysError::Absent,
            ReadReply::Symlink => AuthorizedKeysError::Symlink,
            ReadReply::NotFile => AuthorizedKeysError::NotFile,
            ReadReply::TooLarge => AuthorizedKeysError::TooLarge,
            ReadReply::Failed(what) => AuthorizedKeysError::Script(what),
        };
        Err(err.into())
    }

    /// Runs `script` on the target through the bootstrap command, logged
    /// in with `login` only, and returns its stdout (capped). Fails unless
    /// the log shows `login` logging in.
    pub(super) async fn run_script(
        &self,
        target: &Target,
        login: &KeyRef,
        script: Script,
        stdin: Vec<u8>,
    ) -> Result<Vec<u8>, ProviderError> {
        let Target::Ssh(host) = target else {
            return Err(ProviderError::WrongTarget {
                kind: LocationKind::SshServer,
            });
        };
        let alias = host.alias.as_str();
        self.check_commands()?;
        let setup = |why: String| ProviderError::from(AuthorizedKeysError::Setup(why));
        let identity = login
            .identity_file
            .as_ref()
            .ok_or(AuthorizedKeysError::NoLoginKey)?;
        if !config::is_plain_name(alias) {
            return Err(setup(format!("Cannot use the host alias {alias:?}.")));
        }
        let work = Workdir::new(identity)
            .map_err(|e| setup(format!("Cannot make a temp dir for ssh: {e}")))?;
        let text = match self.build_config(alias, &work.identity).await {
            Ok(t) => t,
            Err(why) => {
                self.netlog.record(
                    LocationKind::SshServer,
                    target,
                    format!("ssh -G {alias}"),
                    format!("error: {why}"),
                );
                return Err(setup(why));
            }
        };
        work.write_config(&text)
            .map_err(|e| setup(format!("Cannot write the temp ssh config: {e}")))?;
        let args = self.ssh_args(alias, &work.config, &work.log, &script.command());
        let action = render_command(&self.program, &args);
        let record = |outcome: String| {
            self.netlog
                .record(LocationKind::SshServer, target, action.clone(), outcome)
        };

        let mut cmd = self.command();
        cmd.args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                record("could not start".into());
                return Err(setup(format!("Cannot run {}: {e}", self.program.display())));
            }
        };
        let (Some(mut input), Some(output), Some(errors)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            record("could not start".into());
            return Err(setup("ssh has no stdin or stdout".into()));
        };
        let run = async {
            let write = async move {
                // A forced command may not read stdin; its answer then
                // fails the marker check.
                let _ = input.write_all(&stdin).await;
                let _ = input.shutdown().await;
            };
            let ((), (stdout, _), (stderr, _)) = tokio::join!(
                write,
                read_capped_async(output, MAX_STDOUT),
                read_capped_async(errors, MAX_STDERR),
            );
            (child.wait().await, stdout, stderr)
        };
        let (status, stdout, stderr) = match tokio::time::timeout(RUN_TIMEOUT, run).await {
            Err(_) => {
                record("timed out".into());
                return Err(AuthorizedKeysError::Login(VerifyStatus::Error(
                    crate::provider::VerifyError::Unreachable(format!(
                        "no answer within {} seconds",
                        RUN_TIMEOUT.as_secs()
                    )),
                ))
                .into());
            }
            Ok((Err(e), ..)) => {
                record("could not wait".into());
                return Err(setup(format!("ssh failed: {e}")));
            }
            Ok((Ok(status), stdout, stderr)) => (status, stdout, stderr),
        };
        let code = status.code();
        // The script's own exit codes are answers; 255 is ssh's error.
        let exit = match code {
            Some(255) | None => code,
            Some(_) => Some(0),
        };
        let log = read_capped(&work.log);
        let stderr = String::from_utf8_lossy(&stderr);
        let login_status = super::classify(exit, &log, &stderr, &work.identity, &login.fingerprint);
        let code = code.map_or("killed".to_string(), |c| format!("exit {c}"));
        if login_status != VerifyStatus::Verified {
            record(format!("{code}, login {}", super::describe(&login_status)));
            return Err(AuthorizedKeysError::Login(login_status).into());
        }
        record(format!(
            "{code}, logged in with {}, {} bytes out",
            login.fingerprint,
            stdout.len()
        ));
        Ok(stdout)
    }
}

/// Reads to the end, keeps at most `cap` bytes; true if there was more.
async fn read_capped_async<R: AsyncRead + Unpin>(mut r: R, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut over = false;
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = cap.saturating_sub(buf.len());
                over |= n > room;
                buf.extend_from_slice(&chunk[..n.min(room)]);
            }
        }
    }
    (buf, over)
}
