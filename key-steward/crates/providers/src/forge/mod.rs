//! Forge providers: GitHub, GitLab, Forgejo/Gitea/Codeberg (FR-4).
//!
//! `list` reads SSH auth keys, SSH signing keys and GPG keys through the
//! API. Fingerprints are always computed here from the key text, never
//! taken from the forge. `verify` is `list` plus a fingerprint compare.
//! Endpoints, fields and pagination: SPEC 15, fact 1.

mod forgejo;
mod github;
mod gitlab;
mod write;

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

pub use forgejo::Forgejo;
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

    /// Primary key fingerprints of the keys in `data` (armored or
    /// binary). A lone public key packet is enough.
    async fn fingerprints(&self, data: Vec<u8>) -> Result<Vec<Fingerprint>, ProviderError> {
        let home = self.home.clone();
        tokio::task::spawn_blocking(move || {
            let mut gpg = match &home {
                Some(h) => Gpg::with_home(h),
                None => Gpg::user_default(),
            }
            .map_err(|e| ProviderError::OpenPgp(e.to_string()))?;
            let keys = gpg
                .read_keys(&data)
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

/// Checks that the token belongs to the target account: the key lists
/// are those of the token's owner (`GET /user`). `field` is the user name
/// field (`login` or `username`). Compared without case, as the forges do.
async fn check_owner(
    kind: LocationKind,
    client: &HttpClient,
    target: &Target,
    field: &str,
) -> Result<(), ProviderError> {
    let Target::Account { account, .. } = target else {
        return Err(ProviderError::WrongTarget { kind });
    };
    let user = client.get_json("/user").await?;
    let owner = user[field]
        .as_str()
        .ok_or_else(|| ProviderError::BadResponse {
            forge: kind,
            what: format!("/user has no {field}"),
        })?;
    if owner.eq_ignore_ascii_case(account) {
        Ok(())
    } else {
        Err(ProviderError::TokenOwner {
            account: account.clone(),
            owner: owner
                .chars()
                .filter(|c| !c.is_control())
                .take(100)
                .collect(),
        })
    }
}

/// The base URL of an account target, without a trailing `/`.
fn base_url(kind: LocationKind, target: &Target) -> Result<&str, ProviderError> {
    match target {
        Target::Account { base_url, .. } => Ok(base_url.trim_end_matches('/')),
        Target::Ssh(_) => Err(ProviderError::WrongTarget { kind }),
    }
}

/// Why a forge GPG entry gave no fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Unread {
    /// The forge sent no key data we can decode.
    NotSent,
    /// GnuPG read the data and found no key in it.
    NoKey,
    /// GnuPG itself failed (a local problem, or data it refused).
    Gpg(String),
}

/// A forge GPG key whose full fingerprint we could not get. Only its 16
/// hex long key ID is known.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnreadGpgKey {
    key_id: Option<String>,
    why: Unread,
}

/// All keys of one account.
#[derive(Debug, Default)]
struct Listing {
    keys: Vec<PublicKeyRef>,
    unread_gpg: Vec<UnreadGpgKey>,
    /// SSH keys we read but cannot place, with the reason (for example
    /// an unknown GitLab usage type). Writes refuse to touch them.
    unusable_ssh: Vec<(Fingerprint, String)>,
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

    /// Adds the keys in one forge GPG entry. `data` is the key the forge
    /// sent (armored or binary), `None` if it sent none we can decode.
    async fn add_gpg(
        &mut self,
        reader: &OpenPgpReader,
        item: &Value,
        data: Option<Vec<u8>>,
        title: Option<String>,
    ) {
        let read = match data {
            Some(d) if !d.is_empty() => reader
                .fingerprints(d)
                .await
                .map_err(|e| Unread::Gpg(e.to_string())),
            _ => Err(Unread::NotSent),
        };
        let fprs = match read {
            Ok(f) if f.is_empty() => Err(Unread::NoKey),
            other => other,
        };
        let fprs = match fprs {
            Ok(f) => f,
            Err(why) => {
                self.unread_gpg.push(UnreadGpgKey {
                    key_id: item["key_id"].as_str().map(str::to_ascii_uppercase),
                    why,
                });
                return;
            }
        };
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
            let maybe: Vec<&Unread> = self
                .unread_gpg
                .iter()
                .filter(|u| match &u.key_id {
                    Some(id) => id.len() == 16 && fpr.ends_with(id.as_str()),
                    None => true,
                })
                .map(|u| &u.why)
                .collect();
            // A local GnuPG failure is named first: it is not the forge's fault.
            let why = maybe
                .iter()
                .find(|w| matches!(w, Unread::Gpg(_)))
                .or(maybe.first());
            if let Some(why) = why {
                let text = match why {
                    Unread::Gpg(e) => format!(
                        "GnuPG failed to read a GPG key from the forge that may be this \
                         one, so its fingerprint cannot be checked: {e}"
                    ),
                    Unread::NotSent => "The forge lists a GPG key that may be this one, but \
                        did not send the key, so its fingerprint cannot be checked."
                        .into(),
                    Unread::NoKey => "The forge lists a GPG key that may be this one, but \
                        GnuPG found no key in what it sent, so its fingerprint cannot be \
                        checked."
                        .into(),
                };
                return VerifyStatus::Error(VerifyError::Other(text));
            }
        }
        VerifyStatus::Missing
    }
}

/// A text field as bytes, for an armored key.
fn text_bytes(item: &Value, field: &str) -> Option<Vec<u8>> {
    item[field].as_str().map(|s| s.as_bytes().to_vec())
}

/// A standard base64 field, decoded (Forgejo's binary key packet).
fn base64_bytes(item: &Value, field: &str) -> Option<Vec<u8>> {
    use base64ct::Encoding;
    base64ct::Base64::decode_vec(item[field].as_str()?.trim()).ok()
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
            why: Unread::NotSent,
        });
        let k = key(Fingerprint::OpenPgp(fpr.into()), Purpose::OpenPgp);
        let text = |l: &Listing| match l.verify(&k) {
            VerifyStatus::Error(VerifyError::Other(t)) => t,
            other => panic!("{other:?}"),
        };
        assert!(text(&l).contains("did not send the key"), "{}", text(&l));

        l.unread_gpg[0].why = Unread::NoKey;
        assert!(text(&l).contains("found no key"), "{}", text(&l));

        // A local GnuPG failure is not blamed on the forge, also when
        // another entry was not sent.
        l.unread_gpg.push(UnreadGpgKey {
            key_id: None,
            why: Unread::Gpg("cannot start gpg".into()),
        });
        let t = text(&l);
        assert!(
            t.contains("GnuPG failed") && t.contains("cannot start gpg"),
            "{t}"
        );
        assert!(!t.contains("did not send"), "{t}");
        l.unread_gpg.pop();

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
            unusable_ssh: vec![],
        };
        assert_eq!(
            l.verify(&key(fpr.clone(), Purpose::SshSigning)),
            VerifyStatus::Verified
        );
        assert_eq!(l.verify(&key(fpr, Purpose::SshAuth)), VerifyStatus::Missing);
    }
}
