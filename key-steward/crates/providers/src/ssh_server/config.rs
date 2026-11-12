//! The first guard: a generated ssh config in which the target host can
//! be offered only the key under test (S-3).
//!
//! `-i` adds to the `IdentityFile` list of the user's config and
//! `IdentityFile none` does not clear it, so with the user's config ssh can
//! log in with another key. Instead we resolve the target with `ssh -G`
//! and write a temp config: the target block copies only connection and
//! host key options from a fixed list, and its only identity is the key
//! under test. Jump hosts get their own blocks that keep their own
//! identities (a jump may need the old key) but pin the safety options.
//! An option we do not copy falls back to ssh's default; at worst the check
//! then fails, it can never pass with another key.

use std::fmt::Write as _;
use std::path::Path;

/// Options from `ssh -G`, in output order (some repeat).
pub(super) type Options = Vec<(String, String)>;

/// Connection and host key options copied for the target and for jump
/// hosts. Everything else gets ssh's default.
const COPY_CONNECTION: &[&str] = &[
    "hostname",
    "port",
    "user",
    "addressfamily",
    "bindaddress",
    "bindinterface",
    "checkhostip",
    "ciphers",
    "compression",
    "connectionattempts",
    "globalknownhostsfile",
    "hostkeyalgorithms",
    "hostkeyalias",
    "ipqos",
    "kexalgorithms",
    "knownhostscommand",
    "macs",
    "nohostauthenticationforlocalhost",
    "proxycommand",
    "proxyjump",
    "proxyusefdpass",
    "pubkeyacceptedalgorithms",
    "rekeylimit",
    "requiredrsasize",
    "tcpkeepalive",
    "userknownhostsfile",
];

/// Also copied for the target: the agent may hold the key under test (for
/// a key with a passphrase). With `IdentitiesOnly yes` ssh uses only agent
/// keys that match an `IdentityFile`, so no other agent key is offered.
const COPY_TARGET_ONLY: &[&str] = &["identityagent"];

/// Also copied for jump hosts: they log in the way the user's config says.
const COPY_JUMP_ONLY: &[&str] = &[
    "identityfile",
    "certificatefile",
    "identityagent",
    "identitiesonly",
    "pkcs11provider",
    "securitykeyprovider",
    "preferredauthentications",
    "gssapiauthentication",
];

/// Pinned for the target, before anything copied (ssh keeps the first
/// value). `IdentityFile` comes first, see [`target_block`].
const TARGET_PINNED: &[&str] = &[
    "IdentitiesOnly yes",
    "PubkeyAuthentication yes",
    "PreferredAuthentications publickey",
    "PasswordAuthentication no",
    "KbdInteractiveAuthentication no",
    "GSSAPIAuthentication no",
    "HostbasedAuthentication no",
    "BatchMode yes",
    "LogVerbose none",
];

/// Pinned for jump hosts. No `SessionType`, `RemoteCommand` or
/// `ClearAllForwardings`: the jump runs `ssh -W`.
const JUMP_PINNED: &[&str] = &[
    "BatchMode yes",
    "StrictHostKeyChecking yes",
    "VerifyHostKeyDNS no",
    "UpdateHostKeys no",
    "AddKeysToAgent no",
    "ControlMaster no",
    "ControlPath none",
    "ForwardAgent no",
    "ForwardX11 no",
    "PermitLocalCommand no",
    "ConnectTimeout 10",
    "ServerAliveInterval 5",
    "ServerAliveCountMax 3",
    "LogVerbose none",
];

pub(super) fn parse_g(text: &str) -> Options {
    text.lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub(super) fn get<'a>(opts: &'a Options, key: &str) -> Option<&'a str> {
    opts.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// One `ProxyJump` hop: `[user@]host[:port]` or `ssh://[user@]host[:port]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Hop {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

pub(super) fn parse_jumps(value: &str) -> Result<Vec<Hop>, String> {
    if value.eq_ignore_ascii_case("none") {
        return Ok(Vec::new());
    }
    value.split(',').map(parse_hop).collect()
}

fn parse_hop(spec: &str) -> Result<Hop, String> {
    let bad = || format!("cannot read ProxyJump host {spec:?}");
    let s = spec.strip_prefix("ssh://").unwrap_or(spec);
    let (user, rest) = match s.rsplit_once('@') {
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, s),
    };
    let (host, port) = if let Some(r) = rest.strip_prefix('[') {
        let (h, after) = r.split_once(']').ok_or_else(bad)?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse().map_err(|_| bad())?),
            None if after.is_empty() => None,
            None => return Err(bad()),
        };
        (h.to_string(), port)
    } else {
        match rest.split_once(':') {
            Some((h, p)) => (h.to_string(), Some(p.parse().map_err(|_| bad())?)),
            None => (rest.to_string(), None),
        }
    };
    if !is_plain_name(&host) {
        return Err(bad());
    }
    Ok(Hop { user, host, port })
}

/// A host name we can put after `Host` and on a command line as is.
pub(super) fn is_plain_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// A user `ProxyCommand` inherits ssh's open files, including the `-E` log
/// (fd 3 in OpenSSH 10.5). ssh runs it as `exec <command>` in a shell, so
/// closing fds 3 to 9 in front keeps the log out of its reach.
fn proxy_command(value: &str) -> String {
    if value == "-" || value.eq_ignore_ascii_case("none") {
        return value.to_string();
    }
    let cmd = value.strip_prefix("exec ").unwrap_or(value);
    format!("3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- {cmd}")
}

fn copy(out: &mut String, opts: &Options, keys: &[&[&str]]) {
    for (k, v) in opts {
        if !keys.iter().any(|list| list.contains(&k.as_str())) {
            continue;
        }
        let v = if k == "proxycommand" {
            proxy_command(v)
        } else {
            v.clone()
        };
        let _ = writeln!(out, "  {k} {v}");
    }
}

/// The target block: the key under test is its only identity.
pub(super) fn target_block(alias: &str, opts: &Options, identity: &Path, fixed: &[&str]) -> String {
    let mut out = format!("Host {alias}\n  IdentityFile \"{}\"\n", identity.display());
    for line in TARGET_PINNED {
        let _ = writeln!(out, "  {line}");
    }
    for opt in fixed {
        let _ = writeln!(out, "  {}", opt.replacen('=', " ", 1));
    }
    copy(&mut out, opts, &[COPY_CONNECTION, COPY_TARGET_ONLY]);
    out
}

/// A jump host block: its own identities, with the safety options pinned.
pub(super) fn jump_block(name: &str, opts: &Options) -> String {
    let mut out = format!("Host {name}\n");
    for line in JUMP_PINNED {
        let _ = writeln!(out, "  {line}");
    }
    copy(&mut out, opts, &[COPY_CONNECTION, COPY_JUMP_ONLY]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(text: &str) -> Options {
        parse_g(text)
    }

    #[test]
    fn target_block_has_only_our_identity() {
        let o = opts(
            "hostname 127.0.0.1\nport 2222\nuser me\nidentityfile ~/.ssh/old\n\
             certificatefile ~/.ssh/old-cert.pub\nidentityagent /run/agent\n\
             pkcs11provider /usr/lib/p11.so\naddkeystoagent true\nforwardagent yes\n\
             proxyjump jmp\nproxycommand exec nc %h %p\nloglevel QUIET\n",
        );
        let b = target_block("box", &o, Path::new("/tmp/x/id"), &["BatchMode=yes"]);
        assert!(
            b.starts_with("Host box\n  IdentityFile \"/tmp/x/id\"\n"),
            "{b}"
        );
        let identity_lines: Vec<_> = b
            .lines()
            .filter(|l| l.to_lowercase().contains("identityfile"))
            .collect();
        assert_eq!(identity_lines.len(), 1, "{b}");
        for absent in [
            "certificatefile",
            "pkcs11",
            "addkeystoagent",
            "forwardagent",
            "loglevel",
        ] {
            assert!(!b.to_lowercase().contains(absent), "{absent} in {b}");
        }
        for present in [
            "  IdentitiesOnly yes\n",
            "  BatchMode yes\n",
            "  hostname 127.0.0.1\n",
            "  port 2222\n",
            "  identityagent /run/agent\n",
            "  proxyjump jmp\n",
            "  proxycommand 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- nc %h %p\n",
        ] {
            assert!(b.contains(present), "{present:?} not in {b}");
        }
        // Pinned lines come before copied ones: ssh keeps the first value.
        assert!(b.find("BatchMode").unwrap() < b.find("hostname").unwrap());
    }

    #[test]
    fn jump_block_keeps_its_identities_and_pins_safety() {
        let o = opts(
            "hostname 10.0.0.1\nidentityfile ~/.ssh/old\nidentityagent none\n\
             addkeystoagent yes\nstricthostkeychecking accept-new\n",
        );
        let b = jump_block("jmp", &o);
        assert!(b.contains("  identityfile ~/.ssh/old\n"), "{b}");
        assert!(b.contains("  AddKeysToAgent no\n"), "{b}");
        assert!(b.contains("  StrictHostKeyChecking yes\n"), "{b}");
        assert!(!b.contains("accept-new"), "{b}");
        assert!(!b.contains("addkeystoagent yes"), "{b}");
    }

    #[test]
    fn parses_jump_hops() {
        assert_eq!(
            parse_jumps("a,bob@b:2201,ssh://c@[::1]:22,[fe80::1]").unwrap(),
            vec![
                Hop {
                    user: None,
                    host: "a".into(),
                    port: None
                },
                Hop {
                    user: Some("bob".into()),
                    host: "b".into(),
                    port: Some(2201)
                },
                Hop {
                    user: Some("c".into()),
                    host: "::1".into(),
                    port: Some(22)
                },
                Hop {
                    user: None,
                    host: "fe80::1".into(),
                    port: None
                },
            ]
        );
        assert!(parse_jumps("none").unwrap().is_empty());
        assert!(parse_jumps("-oProxyCommand=x").is_err());
        assert!(parse_jumps("a b").is_err());
        assert!(parse_jumps("a:port").is_err());
    }
}
