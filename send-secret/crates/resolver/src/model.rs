//! What sources return (plan.md "Model and the KeySource trait").

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use identity_core::{Fingerprint, LineError, PublicKey, UserId};
use tokio::time::Instant;

use crate::net::{Net, NetError};
use crate::query::Query;

/// The key sources of SPEC 4, in SPEC 4 order. The order is the rank:
/// earlier is better.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceKind {
    Contacts,
    Keyring,
    Wkd,
    Vks,
    GitHub,
    GitLab,
    Pasted,
}

impl SourceKind {
    /// Whether this source makes network requests.
    pub fn is_network(self) -> bool {
        matches!(
            self,
            SourceKind::Wkd | SourceKind::Vks | SourceKind::GitHub | SourceKind::GitLab
        )
    }

    pub fn label(self) -> &'static str {
        match self {
            SourceKind::Contacts => "contacts",
            SourceKind::Keyring => "GnuPG keyring",
            SourceKind::Wkd => "WKD",
            SourceKind::Vks => "keys.openpgp.org",
            SourceKind::GitHub => "GitHub",
            SourceKind::GitLab => "GitLab",
            SourceKind::Pasted => "pasted",
        }
    }
}

impl fmt::Display for SourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Where a key was found (S-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub kind: SourceKind,
    /// Final URL, keyring path, "contacts" or "pasted".
    pub location: String,
    /// The URL first asked, when a redirect changed it.
    pub first_url: Option<String>,
}

/// What to encrypt to: exactly one key.
#[derive(Clone, PartialEq, Eq)]
pub enum KeyBytes {
    /// `<type> <base64>`, no comment.
    Ssh(String),
    /// `age1...`
    Age(String),
    /// One OpenPGP key, binary or armored.
    OpenPgp(Vec<u8>),
}

impl fmt::Debug for KeyBytes {
    /// Key bytes are never printed, only their kind and length.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyBytes::Ssh(s) => write!(f, "Ssh({} bytes)", s.len()),
            KeyBytes::Age(s) => write!(f, "Age({} bytes)", s.len()),
            KeyBytes::OpenPgp(b) => write!(f, "OpenPgp({} bytes)", b.len()),
        }
    }
}

/// Why a found key can not be encrypted to (FR-4 skip note). Such keys are
/// shown with the note, never dropped silently, never used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unusable {
    #[error("ECDSA SSH keys are not age recipients")]
    EcdsaNotAge,
    #[error("security key (sk-) SSH keys can not decrypt age files")]
    SkKey,
    #[error("RSA {0} bits: age takes RSA keys from 2048 to 4096 bits")]
    RsaSize(u32),
    #[error("this SSH key type is not an age recipient")]
    SshType,
    #[error("the key has no usable encryption subkey")]
    NoEncryptionSubkey,
    #[error("the key is revoked")]
    Revoked,
    #[error("the key has expired")]
    Expired,
}

/// One key a source found.
#[derive(Clone, PartialEq, Eq)]
pub struct FoundKey {
    /// Parsed by identity-core; the fingerprint comes from here, never
    /// from the server.
    pub key: PublicKey,
    pub bytes: KeyBytes,
    pub source: Source,
    pub usable: Result<(), Unusable>,
    /// The user IDs to show. WKD and keys.openpgp.org: only those matching
    /// the queried email (S-6).
    pub shown_user_ids: Vec<UserId>,
}

impl FoundKey {
    pub fn fingerprint(&self) -> Fingerprint {
        self.key.fingerprint()
    }
}

impl fmt::Debug for FoundKey {
    /// No key material, only what identifies the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FoundKey")
            .field("kind", &self.key.kind())
            .field("algo", &self.key.algo())
            .field("fingerprint", &self.fingerprint().as_str())
            .field("bytes", &self.bytes)
            .field("source", &self.source)
            .field("usable", &self.usable)
            .finish_non_exhaustive()
    }
}

/// Why a fetched key was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RejectReason {
    /// S-6: no valid user ID with the queried email.
    #[error("no valid user ID with the email you looked up")]
    EmailMismatch,
    #[error("the answer holds too many keys")]
    TooManyKeys,
    /// A line of a `.keys` list that holds no usable key.
    #[error("line {line}: {error}")]
    BadLine { line: usize, error: LineError },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub fingerprint: Option<Fingerprint>,
    pub source: Source,
    pub reason: RejectReason,
}

/// What one source returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    pub keys: Vec<FoundKey>,
    pub rejected: Vec<Rejected>,
}

/// Why one source gave no result. Shown per source; never fatal alone.
/// The text never holds fetched data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    #[error("not found")]
    NotFound,
    #[error("timed out")]
    Timeout,
    #[error("rate limited{}", retry_text(*.retry_after))]
    RateLimited { retry_after: Option<Duration> },
    #[error("the answer is too large")]
    TooLarge,
    #[error("malformed answer: {0}")]
    Malformed(String),
    #[error("HTTP {0}")]
    Http(u16),
    #[error("{0}")]
    Net(String),
    #[error("GnuPG keyring: {0}")]
    Keyring(String),
}

fn retry_text(wait: Option<Duration>) -> String {
    match wait {
        Some(d) => format!("; try again in {} s", d.as_secs().max(1)),
        None => String::new(),
    }
}

impl From<NetError> for SourceError {
    fn from(e: NetError) -> Self {
        match e {
            NetError::NotFound => SourceError::NotFound,
            NetError::Timeout => SourceError::Timeout,
            NetError::TooLarge => SourceError::TooLarge,
            NetError::RateLimited { retry_after } => SourceError::RateLimited { retry_after },
            NetError::CoolingDown { wait, .. } => SourceError::RateLimited {
                retry_after: Some(wait),
            },
            NetError::Http(code) => SourceError::Http(code),
            other => SourceError::Net(other.to_string()),
        }
    }
}

/// One key source of SPEC 4.
#[async_trait]
pub trait KeySource: Send + Sync {
    fn kind(&self) -> SourceKind;
    fn accepts(&self, q: &Query) -> bool;
    /// `net` is `Some` only for network sources ([`SourceKind::is_network`])
    /// in [`crate::Mode::Full`]. Local sources always get `None`.
    async fn lookup(
        &self,
        q: &Query,
        net: Option<&Net>,
        deadline: Instant,
    ) -> Result<Found, SourceError>;
}
