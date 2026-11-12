//! Reading and editing `~/.ssh/authorized_keys` over ssh (SPEC 9.1, S-3,
//! S-5, S-6).
//!
//! Every run logs in with one given key, pinned as the target's only
//! identity in the generated config of the check (`build_config`), so it
//! reaches the host the check verified. Two guards decide that the run
//! counts: the `-v -E` log must show that key logging in (`classify`),
//! and the script's output must start with its marker line. A forced
//! command (`command=` on the login key's line) or a shell that prints
//! text fails the marker check, before any change.
//!
//! An edit reads the file, computes the new content in Rust
//! (`authorized_keys.rs`), and sends it to the apply script with the
//! checksum of the file as read. The script writes nothing if the file
//! changed in between. Its answer must name the checksum of the content
//! sent. Add logs in with the old key (`like`), remove with the new key
//! (`keep`): if the new key cannot run the script, the old key stays.
//!
//! File contents and keys never go into the network log or error text.

use std::process::Stdio;

use identity_core::{Fingerprint, SshPublicKey};
use inventory::{LocationKind, Purpose, Status, Target};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::authorized_keys::{AuthorizedKeys, EditError, MAX_FILE};
use super::remote::{self, ApplyReply, Cksum, ProtocolError, ReadReply, Script};
use super::{RUN_TIMEOUT, SshServer, Workdir, config, read_capped, render_command};
use crate::error::ProviderError;
use crate::provider::{KeyRef, PublicKeyRef, RemoveOpts, VerifyError, VerifyStatus};

/// Most bytes kept from the script's stdout. More than the read script
/// may send, so a longer answer is refused as too large.
const MAX_STDOUT: usize = MAX_FILE + 4096;
/// Most bytes kept from ssh's stderr (jump hosts, banner, remote errors).
const MAX_STDERR: usize = 64 * 1024;

/// Why reading or editing `authorized_keys` on a server failed. Nothing
/// was changed on the server, except after [`NotConfirmed`] (the file
/// was replaced) and [`MayHaveWritten`] (not known): list to check.
///
/// [`NotConfirmed`]: AuthorizedKeysError::NotConfirmed
/// [`MayHaveWritten`]: AuthorizedKeysError::MayHaveWritten
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizedKeysError {
    #[error("no key to log in with was given")]
    NoLoginKey,
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
    #[error("~/.ssh/authorized_keys changed on the server since it was read; nothing was written")]
    Changed,
    #[error("the new file did not arrive whole; nothing was written")]
    Short,
    /// The file was replaced, but the script reports another checksum
    /// than the content sent. Check the file on the server.
    #[error(
        "the server reports a different file than the one sent; check ~/.ssh/authorized_keys there"
    )]
    NotConfirmed,
    /// ssh logged in, then the run ended without a clear answer (timeout,
    /// lost connection). Only a read script ran, so nothing changed.
    #[error("the connection ended while the script ran on the server: {0}")]
    Interrupted(String),
    /// Like [`AuthorizedKeysError::Interrupted`] or a garbled answer, but
    /// for the apply script: the file may have been written.
    #[error(
        "the edit of ~/.ssh/authorized_keys gave no clear answer ({0}); \
         the file may have been written; list the keys to check"
    )]
    MayHaveWritten(String),
}

/// The result of [`SshServer::remove_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshRemoved {
    /// False if the old key was not in the file (nothing written).
    pub changed: bool,
    /// Line numbers (from 1) of `cert-authority` lines with the old key.
    /// They stay: the old private key can still sign a certificate that
    /// logs in. Tell the user, keep the location flagged.
    pub ca_lines_with_old_key: Vec<usize>,
}

/// The result of [`SshServer::check_old_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OldKeyCheck {
    /// The server refuses the old key.
    Refused,
    /// The server still accepts the old key (alone, or as one of several
    /// keys). Do not retire it.
    StillAccepted,
    /// No proof either way (host unreachable, host key, key not offered,
    /// a log ssh wrote in a way we do not know). The reason, for the user.
    Unknown(String),
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
        Status::Missing => "the server does not accept the key (a `from=` option on its \
                            line in authorized_keys may refuse this client)"
            .into(),
        other => format!("{other:?}"),
    }
}

impl SshServer {
    /// Adds `key` after each line of `like` (same options), logging in
    /// with `like`. Returns false if the file already had it (nothing
    /// written).
    pub async fn add_key(
        &self,
        target: &Target,
        key: &SshPublicKey,
        like: &KeyRef,
    ) -> Result<bool, ProviderError> {
        let (content, sum) = self.read_file(target, like).await?;
        let new = AuthorizedKeys::parse(&content)?.add_like(&like.fingerprint, key)?;
        if new == content {
            return Ok(false);
        }
        self.apply(target, like, sum, &new).await?;
        Ok(true)
    }

    /// Drops every login key line of `old`, logging in with `opts.keep`,
    /// which must stay in the file. The login fails (and nothing changes)
    /// if `keep` cannot log in and run the script, for example because its
    /// line has a forced command.
    pub async fn remove_key(
        &self,
        target: &Target,
        old: &Fingerprint,
        opts: &RemoveOpts,
    ) -> Result<SshRemoved, ProviderError> {
        if opts.purpose != Purpose::SshAuth {
            return Err(ProviderError::Unsupported(
                "an SSH server holds only login keys".into(),
            ));
        }
        let keep = opts.keep.as_ref().ok_or(AuthorizedKeysError::NoLoginKey)?;
        let (content, sum) = self.read_file(target, keep).await?;
        let removed = AuthorizedKeys::parse(&content)?.remove(old, &keep.fingerprint)?;
        let changed = removed.bytes != content;
        if changed {
            self.apply(target, keep, sum, &removed.bytes).await?;
        }
        Ok(SshRemoved {
            changed,
            ca_lines_with_old_key: removed.ca_lines_with_old_key,
        })
    }

    /// After a removal: logs in with the old key through the same pinned
    /// config. `Refused` needs proof in the log that ssh offered the key
    /// and the server said no ([`super::classify::refused`]). A key the
    /// server accepts but ssh cannot use, accepts as one of several, or
    /// accepts through a certificate counts as still accepted.
    pub async fn check_old_key(
        &self,
        target: &Target,
        old: &KeyRef,
    ) -> Result<OldKeyCheck, ProviderError> {
        let Target::Ssh(host) = target else {
            return Err(ProviderError::WrongTarget {
                kind: LocationKind::SshServer,
            });
        };
        self.check_commands()?;
        let (status, refused) = self.run(target, &host.alias, old).await;
        Ok(match status {
            VerifyStatus::Verified
            | VerifyStatus::Error(
                VerifyError::KeyNotUsable
                | VerifyError::MoreThanOneKey
                | VerifyError::CertificateUsed,
            ) => OldKeyCheck::StillAccepted,
            VerifyStatus::Missing if refused => OldKeyCheck::Refused,
            VerifyStatus::Missing => OldKeyCheck::Unknown(
                "ssh did not show the server refusing the key (is the private key file \
                 there and readable?)"
                    .into(),
            ),
            other => OldKeyCheck::Unknown(login_reason(&other)),
        })
    }

    async fn apply(
        &self,
        target: &Target,
        login: &KeyRef,
        old: Cksum,
        new: &[u8],
    ) -> Result<(), ProviderError> {
        let unclear = |why: String| ProviderError::from(AuthorizedKeysError::MayHaveWritten(why));
        let out = match self
            .run_script(target, login, remote::APPLY, remote::apply_stdin(old, new))
            .await
        {
            Err(ProviderError::AuthorizedKeys(AuthorizedKeysError::Interrupted(why))) => {
                return Err(unclear(why));
            }
            other => other?,
        };
        let reply = remote::parse_apply(&out).map_err(|e| unclear(e.to_string()))?;
        let err = match reply {
            ApplyReply::Done(sum) if sum == remote::cksum(new) => return Ok(()),
            ApplyReply::Done(_) => AuthorizedKeysError::NotConfirmed,
            ApplyReply::Changed => AuthorizedKeysError::Changed,
            ApplyReply::Short => AuthorizedKeysError::Short,
            ApplyReply::Symlink => AuthorizedKeysError::Symlink,
            ApplyReply::Absent => AuthorizedKeysError::Absent,
            ApplyReply::NotFile => AuthorizedKeysError::NotFile,
            ApplyReply::BadInput => AuthorizedKeysError::Script("badinput".into()),
            ApplyReply::NoTemp => AuthorizedKeysError::Script("notmp".into()),
            ApplyReply::Failed(what) => AuthorizedKeysError::Script(what),
        };
        Err(err.into())
    }

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
            let ((), stdout, stderr) = tokio::join!(
                write,
                read_capped_async(output, MAX_STDOUT),
                read_capped_async(errors, MAX_STDERR),
            );
            (child.wait().await, stdout, stderr)
        };
        let (status, stdout, stderr) = match tokio::time::timeout(RUN_TIMEOUT, run).await {
            Err(_) => {
                record("timed out".into());
                return Err(AuthorizedKeysError::Interrupted(format!(
                    "no answer within {} seconds",
                    RUN_TIMEOUT.as_secs()
                ))
                .into());
            }
            Ok((Err(e), ..)) => {
                record("could not wait".into());
                return Err(AuthorizedKeysError::Interrupted(format!("ssh failed: {e}")).into());
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
            // After a login the remote command may have run.
            if log.lines().any(|l| l.starts_with("Authenticated to ")) {
                return Err(AuthorizedKeysError::Interrupted(login_reason(&login_status)).into());
            }
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

/// Reads to the end, keeps at most `cap` bytes.
async fn read_capped_async<R: AsyncRead + Unpin>(mut r: R, cap: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = cap.saturating_sub(buf.len());
                buf.extend_from_slice(&chunk[..n.min(room)]);
            }
        }
    }
    buf
}
