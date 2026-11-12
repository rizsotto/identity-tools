//! Forge providers: GitHub, GitLab, Forgejo/Gitea/Codeberg (FR-4).
//!
//! `list` reads SSH auth keys, SSH signing keys and GPG keys through the
//! API. Fingerprints are always computed here from the key text, never
//! taken from the forge. `verify` is `list` plus a fingerprint compare.
//! Endpoints, fields and pagination: SPEC 15, fact 1.

mod github;
mod gitlab;

use std::path::PathBuf;
use std::sync::Arc;

use identity_core::{Fingerprint, Gpg, OpenPgpBackend, PublicKey, parse_public_keys};
use inventory::{LocationKind, Purpose, Target};
use serde_json::Value;

use crate::error::ProviderError;
use crate::http::{AuthStyle, HttpClient};
use crate::netlog::NetLog;
use crate::provider::{KeyRef, PublicKeyRef, VerifyError, VerifyStatus};
use crate::token::{TokenKey, TokenSource};

pub use github::GitHub;
pub use gitlab::GitLab;

/// Reads armored OpenPGP keys from forge answers with GnuPG, without
/// importing them. A gpgme context is not `Send`, so each read makes its
/// own, on a blocking thread.
#[derive(Debug, Clone, Default)]
pub struct OpenPgpReader {
    home: Option<PathBuf>,
}

impl OpenPgpReader {
    /// Uses gpg's default home (`GNUPGHOME` or `~/.gnupg`).
    pub fn user_default() -> Self {
        OpenPgpReader { home: None }
    }

    /// Uses `home` as the GnuPG home. Tests pass a temp dir.
    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        OpenPgpReader {
            home: Some(home.into()),
        }
    }

    /// Primary key fingerprints of the keys in `armored`.
    async fn fingerprints(&self, armored: String) -> Result<Vec<Fingerprint>, ProviderError> {
        let home = self.home.clone();
        tokio::task::spawn_blocking(move || {
            let mut gpg = match &home {
                Some(h) => Gpg::with_home(h),
                None => Gpg::user_default(),
            }
            .map_err(|e| ProviderError::OpenPgp(e.to_string()))?;
            let keys = gpg
                .read_keys(armored.as_bytes())
                .map_err(|e| ProviderError::OpenPgp(e.to_string()))?;
            Ok(keys.into_iter().map(|k| k.fingerprint).collect())
        })
        .await
        .map_err(|e| ProviderError::OpenPgp(e.to_string()))?
    }
}

/// What every forge provider needs: where tokens come from, how to read
/// OpenPGP keys, and the network log.
#[derive(Clone)]
pub(crate) struct ForgeCore {
    tokens: Arc<dyn TokenSource>,
    openpgp: OpenPgpReader,
    netlog: NetLog,
}

impl ForgeCore {
    fn new(tokens: Arc<dyn TokenSource>, openpgp: OpenPgpReader, netlog: NetLog) -> Self {
        ForgeCore {
            tokens,
            openpgp,
            netlog,
        }
    }

    /// The HTTP client for the account in `target`, with its token.
    async fn client(
        &self,
        kind: LocationKind,
        target: &Target,
        api_url: &str,
        auth: AuthStyle,
        headers: &[(&'static str, &str)],
    ) -> Result<HttpClient, ProviderError> {
        let key = TokenKey::for_target(kind, target).ok_or(ProviderError::WrongTarget { kind })?;
        let token = self
            .tokens
            .token(&key)
            .await?
            .ok_or_else(|| ProviderError::NoToken(target.label()))?;
        HttpClient::new(
            kind,
            target,
            api_url,
            auth,
            Some(token),
            headers,
            self.netlog.clone(),
        )
    }
}

/// The base URL of an account target, without a trailing `/`.
fn base_url(kind: LocationKind, target: &Target) -> Result<&str, ProviderError> {
    match target {
        Target::Account { base_url, .. } => Ok(base_url.trim_end_matches('/')),
        Target::Ssh(_) => Err(ProviderError::WrongTarget { kind }),
    }
}

/// A forge GPG key whose full fingerprint we could not get (no armored
/// key, or one gpg cannot read). Only its 16 hex long key ID is known.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnreadGpgKey {
    key_id: Option<String>,
}

/// All keys of one account.
#[derive(Debug, Default)]
struct Listing {
    keys: Vec<PublicKeyRef>,
    unread_gpg: Vec<UnreadGpgKey>,
}

impl Listing {
    /// Adds an SSH key line from the forge for each purpose. A line we
    /// cannot parse (for example an unknown key type) is skipped: it
    /// cannot be one of our keys, which we could parse.
    fn add_ssh(&mut self, item: &Value, purposes: &[Purpose], title: Option<String>) {
        let Some(fingerprint) = item["key"].as_str().and_then(ssh_fingerprint) else {
            return;
        };
        for &purpose in purposes {
            self.keys.push(PublicKeyRef {
                fingerprint: fingerprint.clone(),
                purpose,
                title: title.clone(),
                remote_id: remote_id(item),
            });
        }
    }

    /// Adds the keys in one forge GPG entry. `armored` is the field that
    /// holds the armored key.
    async fn add_gpg(
        &mut self,
        reader: &OpenPgpReader,
        item: &Value,
        armored: &str,
        title: Option<String>,
    ) {
        let fprs = match item[armored].as_str() {
            Some(text) if !text.is_empty() => reader
                .fingerprints(text.to_string())
                .await
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        if fprs.is_empty() {
            self.unread_gpg.push(UnreadGpgKey {
                key_id: item["key_id"].as_str().map(str::to_ascii_uppercase),
            });
            return;
        }
        for fingerprint in fprs {
            self.keys.push(PublicKeyRef {
                fingerprint,
                purpose: Purpose::OpenPgp,
                title: title.clone(),
                remote_id: remote_id(item),
            });
        }
    }

    /// FR-4: the key is verified if a listed key has its fingerprint and
    /// purpose. A GPG entry we could not read whose long key ID matches
    /// the key gives an error, not `Missing`.
    fn verify(&self, key: &KeyRef) -> VerifyStatus {
        if self
            .keys
            .iter()
            .any(|k| k.purpose == key.purpose && k.fingerprint == key.fingerprint)
        {
            return VerifyStatus::Verified;
        }
        if let Fingerprint::OpenPgp(fpr) = &key.fingerprint
            && key.purpose == Purpose::OpenPgp
        {
            let fpr = fpr.to_ascii_uppercase();
            let maybe = self.unread_gpg.iter().any(|u| match &u.key_id {
                Some(id) => id.len() == 16 && fpr.ends_with(id.as_str()),
                None => true,
            });
            if maybe {
                return VerifyStatus::Error(VerifyError::Other(
                    "The forge lists a GPG key that may be this one, but did not send the \
                     full key, so its fingerprint cannot be checked."
                        .into(),
                ));
            }
        }
        VerifyStatus::Missing
    }
}

/// The SHA256 fingerprint of a forge key line (`<type> <base64>`).
fn ssh_fingerprint(line: &str) -> Option<Fingerprint> {
    let parsed = parse_public_keys(line.as_bytes()).ok()?;
    match parsed.as_slice() {
        [one] => match &one.key {
            Ok(PublicKey::Ssh(k)) => Some(k.fingerprint.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn remote_id(item: &Value) -> Option<String> {
    match &item["id"] {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn title(item: &Value, field: &str) -> Option<String> {
    item[field]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Each item must be a JSON object.
fn check_objects(kind: LocationKind, items: &[Value]) -> Result<(), ProviderError> {
    if items.iter().all(Value::is_object) {
        Ok(())
    } else {
        Err(ProviderError::BadResponse {
            forge: kind,
            what: "a list item is not an object".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(fpr: Fingerprint, purpose: Purpose) -> KeyRef {
        KeyRef {
            fingerprint: fpr,
            purpose,
            identity_file: None,
        }
    }

    #[test]
    fn unread_gpg_key_with_matching_id_is_error() {
        let fpr = "1D13978E2745938FF18F6CE8B5F9441847F263E7";
        let mut l = Listing::default();
        l.unread_gpg.push(UnreadGpgKey {
            key_id: Some("B5F9441847F263E7".into()),
        });
        let k = key(Fingerprint::OpenPgp(fpr.into()), Purpose::OpenPgp);
        assert!(matches!(l.verify(&k), VerifyStatus::Error(_)));

        l.unread_gpg[0].key_id = Some("0000000000000000".into());
        assert_eq!(l.verify(&k), VerifyStatus::Missing);
    }

    #[test]
    fn purpose_must_match() {
        let fpr = Fingerprint::Ssh("SHA256:abc".into());
        let l = Listing {
            keys: vec![PublicKeyRef {
                fingerprint: fpr.clone(),
                purpose: Purpose::SshSigning,
                title: None,
                remote_id: None,
            }],
            unread_gpg: vec![],
        };
        assert_eq!(
            l.verify(&key(fpr.clone(), Purpose::SshSigning)),
            VerifyStatus::Verified
        );
        assert_eq!(l.verify(&key(fpr, Purpose::SshAuth)), VerifyStatus::Missing);
    }
}
