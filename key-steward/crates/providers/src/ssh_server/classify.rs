//! The second guard: reading the main client's `-v -E` log.
//!
//! The first guard is structural (see `config.rs`): the target host is
//! offered only the key under test. This module still checks that the log
//! shows exactly that key logging in.

use std::path::Path;

use identity_core::Fingerprint;

use crate::provider::{VerifyError, VerifyStatus};

/// Maps ssh's exit code and its `-v -E` log to a result. All OpenSSH text
/// patterns live here (checked against OpenSSH 10.5p1, SPEC 15).
///
/// `log` is the main client's own log file; only it decides the result.
/// `stderr` (jump hosts, banner, remote command) is used only for an error
/// message when the log has none.
///
/// `Verified` needs all of: exit 0 (the command is `true`), a line
/// `Authenticated to ... using "publickey".`, no partial success, the last
/// key the server accepted is `identity` with fingerprint `key` and not a
/// certificate, and no other key was offered or tried between that accept
/// and the authentication.
pub fn classify(
    exit: Option<i32>,
    log: &str,
    stderr: &str,
    identity: &Path,
    key: &Fingerprint,
) -> VerifyStatus {
    let lines: Vec<&str> = log.lines().collect();
    let accepted: Vec<(usize, Accepted)> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| {
            l.strip_prefix("debug1: Server accepts key: ")
                .map(|rest| (i, parse_accepted(rest, identity, key)))
        })
        .collect();
    let ours_accepted = accepted
        .iter()
        .any(|(_, a)| matches!(a, Accepted::Ours | Accepted::OursCert));
    if lines
        .iter()
        .any(|l| l.starts_with("Authenticated using ") && l.contains("with partial success"))
    {
        return VerifyStatus::Error(VerifyError::MoreThanOneKey);
    }
    if let Some(auth_at) = lines
        .iter()
        .position(|l| l.starts_with("Authenticated to "))
    {
        if !lines[auth_at].ends_with(" using \"publickey\".") {
            return VerifyStatus::Error(VerifyError::Other("ssh logged in without a key.".into()));
        }
        if exit != Some(0) {
            return VerifyStatus::Error(VerifyError::Other(format!(
                "ssh logged in, but the test command failed ({}).",
                exit.map_or("killed".to_string(), |c| format!("exit {c}"))
            )));
        }
        let last = accepted.iter().rev().find(|(i, _)| *i < auth_at);
        let Some((accept_at, which)) = last else {
            return VerifyStatus::Missing;
        };
        let other_key_after = lines[accept_at + 1..auth_at].iter().any(|l| {
            l.starts_with("debug1: Offering public key:")
                || l.starts_with("debug1: Trying private key:")
        });
        return match which {
            Accepted::Ours if !other_key_after => VerifyStatus::Verified,
            Accepted::OursCert if !other_key_after => {
                VerifyStatus::Error(VerifyError::CertificateUsed)
            }
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
/// [explicit] [token] [agent]`. It is ours only if the path is exactly our
/// identity path, the fingerprint is ours and nothing else follows.
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

    /// Re-review: our key is accepted but cannot sign, then a key with no
    /// public half signs without an "accepts" line of its own.
    #[test]
    fn other_key_tried_after_our_accept_is_not_verified() {
        let log = accepts("/k/new key", "ED25519", NEW)
            + "debug1: Trying private key: /k/oldpem\n"
            + AUTH;
        assert_eq!(c(0, &log), VerifyStatus::Error(VerifyError::KeyNotUsable));
        let log = accepts("/k/new key", "ED25519", NEW)
            + &format!("debug1: Offering public key: /k/other ED25519 {OLD} explicit\n")
            + AUTH;
        assert_eq!(c(0, &log), VerifyStatus::Error(VerifyError::KeyNotUsable));
        // Lines before our accept do not matter.
        let log = "debug1: Trying private key: /k/oldpem\n".to_string()
            + &accepts("/k/new key", "ED25519", NEW)
            + AUTH;
        assert_eq!(c(0, &log), VerifyStatus::Verified);
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
}
