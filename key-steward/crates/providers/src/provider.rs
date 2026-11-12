use std::path::PathBuf;

use async_trait::async_trait;
use identity_core::{Fingerprint, PublicKey};
use inventory::{LocationKind, Purpose, Status, Target};

use crate::error::ProviderError;

/// The local key a check is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRef {
    pub fingerprint: Fingerprint,
    pub purpose: Purpose,
    /// The private key file, for SSH server checks (`ssh -i`). The file is
    /// passed to `ssh` by path; Key Steward never reads it (S-1).
    pub identity_file: Option<PathBuf>,
}

/// A key as a location reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyRef {
    /// Computed locally from the key text, never taken from the server.
    pub fingerprint: Fingerprint,
    pub purpose: Purpose,
    pub title: Option<String>,
    /// The location's own id for the key, needed to remove it later.
    pub remote_id: Option<String>,
}

/// Options for [`Provider::add`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddOpts {
    pub title: Option<String>,
}

/// Why a check gave no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The server's host key is not known. It is never accepted silently
    /// (S-5).
    UnknownHostKey,
    /// The server's host key differs from the known one.
    HostKeyChanged,
    /// Could not reach the host.
    Unreachable(String),
    /// The location accepts the key, but it could not be used to log in
    /// (for example it needs a passphrase and no agent holds it).
    KeyNotUsable,
    /// The login used a certificate made from the key (`<key>-cert.pub`).
    /// That does not show the key itself is installed.
    CertificateUsed,
    /// The server needs more than one key ("partial success"). Removing any
    /// of them could lock the user out.
    MoreThanOneKey,
    Other(String),
}

/// Result of [`Provider::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyStatus {
    Verified,
    Missing,
    Error(VerifyError),
}

impl VerifyStatus {
    /// The stored status, with a reason the user can act on.
    pub fn to_status(&self) -> Status {
        match self {
            VerifyStatus::Verified => Status::Verified,
            VerifyStatus::Missing => Status::Missing,
            VerifyStatus::Error(e) => Status::Error(match e {
                VerifyError::UnknownHostKey => "The host key is not known. Connect once in a \
                    terminal and check the fingerprint, then check again."
                    .into(),
                VerifyError::HostKeyChanged => "The host key has changed. This can be an \
                    attack. Find out why before you connect."
                    .into(),
                VerifyError::Unreachable(why) => format!("Cannot reach the host: {why}"),
                VerifyError::KeyNotUsable => "The server accepts the key, but ssh could not \
                    use it. Add it to the ssh agent or check its passphrase."
                    .into(),
                VerifyError::CertificateUsed => "The login worked with a certificate for \
                    this key, not with the key itself. The key may not be in authorized_keys."
                    .into(),
                VerifyError::MoreThanOneKey => "The server needs more than one key to log \
                    in. Key Steward does not handle this yet."
                    .into(),
                VerifyError::Other(why) => why.clone(),
            }),
        }
    }
}

/// One location kind (SPEC 7.1). Every provider implements all methods
/// (SPEC 14). In M1, `add` and `remove` return [`ProviderError::NotYet`];
/// M2 replaces them, with mock tests, before any UI calls them.
#[async_trait]
pub trait Provider: Send + Sync {
    fn kind(&self) -> LocationKind;

    /// Keys installed at the target.
    async fn list(&self, target: &Target) -> Result<Vec<PublicKeyRef>, ProviderError>;

    async fn add(
        &self,
        target: &Target,
        key: &PublicKey,
        opts: &AddOpts,
    ) -> Result<(), ProviderError>;

    async fn remove(&self, target: &Target, key: &Fingerprint) -> Result<(), ProviderError>;

    /// Checks whether the key is installed at the target.
    async fn verify(&self, target: &Target, key: &KeyRef) -> Result<VerifyStatus, ProviderError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_status_maps_to_store_status() {
        assert_eq!(VerifyStatus::Verified.to_status(), Status::Verified);
        assert_eq!(VerifyStatus::Missing.to_status(), Status::Missing);
        let s = VerifyStatus::Error(VerifyError::UnknownHostKey).to_status();
        assert!(
            matches!(&s, Status::Error(r) if r.contains("terminal")),
            "{s:?}"
        );
    }
}
