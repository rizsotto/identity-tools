use std::fmt;
use std::time::SystemTime;

use identity_core::Fingerprint;

/// Where a key can be installed (FR-2). M1 checks the first four.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocationKind {
    SshServer,
    GitHub,
    GitLab,
    Forgejo,
    Vks,
    Wkd,
}

impl LocationKind {
    pub const ALL: [LocationKind; 6] = [
        LocationKind::SshServer,
        LocationKind::GitHub,
        LocationKind::GitLab,
        LocationKind::Forgejo,
        LocationKind::Vks,
        LocationKind::Wkd,
    ];

    /// Stable name, used in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            LocationKind::SshServer => "ssh_server",
            LocationKind::GitHub => "github",
            LocationKind::GitLab => "gitlab",
            LocationKind::Forgejo => "forgejo",
            LocationKind::Vks => "vks",
            LocationKind::Wkd => "wkd",
        }
    }

    pub fn parse(s: &str) -> Option<LocationKind> {
        LocationKind::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

impl fmt::Display for LocationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An SSH host from the user's ssh config or added by hand.
///
/// `alias` is what `ssh` is called with, so the user's config (ProxyJump,
/// keys, options) applies. The other fields are what `ssh -G` resolved, for
/// display only.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SshHost {
    pub alias: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
}

impl SshHost {
    pub fn new(alias: impl Into<String>) -> Self {
        SshHost {
            alias: alias.into(),
            hostname: None,
            user: None,
            port: None,
        }
    }
}

/// The place inside a location kind: an SSH host, or an account on a web
/// service (forge base URL plus user name).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Target {
    Ssh(SshHost),
    Account { base_url: String, account: String },
}

impl Target {
    /// Short text for logs and the UI.
    pub fn label(&self) -> String {
        match self {
            Target::Ssh(h) => h.alias.clone(),
            Target::Account { base_url, account } => format!("{account} at {base_url}"),
        }
    }
}

/// What the key is used for at that location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    SshAuth,
    SshSigning,
    OpenPgp,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::SshAuth => "ssh_auth",
            Purpose::SshSigning => "ssh_signing",
            Purpose::OpenPgp => "openpgp",
        }
    }

    pub fn parse(s: &str) -> Option<Purpose> {
        [Purpose::SshAuth, Purpose::SshSigning, Purpose::OpenPgp]
            .into_iter()
            .find(|p| p.as_str() == s)
    }
}

/// Result of the last check (FR-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Verified,
    Unverified,
    Missing,
    /// The check could not run or gave no answer. The text says why. It
    /// must never hold a token (S-4).
    Error(String),
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Verified => "verified",
            Status::Unverified => "unverified",
            Status::Missing => "missing",
            Status::Error(_) => "error",
        }
    }
}

pub type LocationId = i64;

/// A location to add. It starts as [`Status::Unverified`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLocation {
    pub kind: LocationKind,
    pub target: Target,
    pub key: Fingerprint,
    pub purpose: Purpose,
}

/// A stored location (FR-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub id: LocationId,
    pub kind: LocationKind,
    pub target: Target,
    pub key: Fingerprint,
    pub purpose: Purpose,
    pub status: Status,
    pub last_checked: Option<SystemTime>,
}
