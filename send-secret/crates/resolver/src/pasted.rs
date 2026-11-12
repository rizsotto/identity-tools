//! Pasted key source (SPEC 4 item 7, plan.md "Sources").
//!
//! OpenPGP (armored or binary) goes through `split_keys`; anything else is
//! read as SSH public key lines and age recipients. At most 1 MB (S-7).
//! A paste is the user's own input, so one bad line refuses the whole
//! paste, naming the line.

use async_trait::async_trait;
use identity_core::{KeyAlgo, MAX_KEY_INPUT, PublicKey, parse_public_keys};
use tokio::time::Instant;

use crate::model::{
    Found, FoundKey, KeyBytes, KeySource, RejectReason, Rejected, Source, SourceError, SourceKind,
    Unusable,
};
use crate::net::Net;
use crate::openpgp::{Split, split_blob, usable, valid_user_ids};
use crate::query::Query;

/// A key the user pasted or gave as a file.
#[derive(Debug, Default, Clone, Copy)]
pub struct PastedSource;

impl PastedSource {
    pub fn new() -> Self {
        PastedSource
    }
}

fn source() -> Source {
    Source {
        kind: SourceKind::Pasted,
        location: "pasted".to_string(),
        first_url: None,
    }
}

#[async_trait]
impl KeySource for PastedSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Pasted
    }

    fn accepts(&self, q: &Query) -> bool {
        matches!(q, Query::Pasted(_))
    }

    async fn lookup(
        &self,
        q: &Query,
        _net: Option<&Net>,
        deadline: Instant,
    ) -> Result<Found, SourceError> {
        let Query::Pasted(bytes) = q else {
            return Err(SourceError::NotFound);
        };
        if bytes.len() > MAX_KEY_INPUT {
            return Err(SourceError::TooLarge);
        }
        if is_openpgp(bytes) {
            openpgp(bytes.clone(), deadline).await
        } else {
            lines(bytes)
        }
    }
}

/// Binary OpenPGP starts with a packet tag byte (bit 7 set); armor has a
/// `-----BEGIN PGP` line.
fn is_openpgp(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(|b| b & 0x80 != 0)
        || bytes.windows(14).any(|w| w == b"-----BEGIN PGP")
}

async fn openpgp(bytes: Vec<u8>, deadline: Instant) -> Result<Found, SourceError> {
    let keys = match split_blob(bytes, deadline).await? {
        Split::Keys(keys) => keys,
        Split::TooManyKeys => {
            return Ok(Found {
                keys: Vec::new(),
                rejected: vec![Rejected {
                    fingerprint: None,
                    source: source(),
                    reason: RejectReason::TooManyKeys,
                }],
            });
        }
    };
    if keys.is_empty() {
        return Err(SourceError::Malformed("no OpenPGP key found".into()));
    }
    let keys = keys
        .into_iter()
        .map(|(key, bytes)| FoundKey {
            usable: usable(&key),
            shown_user_ids: valid_user_ids(&key),
            key: PublicKey::OpenPgp(key),
            bytes: KeyBytes::OpenPgp(bytes),
            source: source(),
        })
        .collect();
    Ok(Found {
        keys,
        rejected: Vec::new(),
    })
}

fn lines(bytes: &[u8]) -> Result<Found, SourceError> {
    let parsed = parse_public_keys(bytes).map_err(|e| match e {
        identity_core::KeyError::TooLarge { .. } => SourceError::TooLarge,
        e => SourceError::Malformed(e.to_string()),
    })?;
    if parsed.is_empty() {
        return Err(SourceError::Malformed("no key found".into()));
    }
    let mut found = Found::default();
    for line in parsed {
        let key = line
            .key
            .map_err(|e| SourceError::Malformed(format!("line {}: {e}", line.line)))?;
        let bytes = match &key {
            PublicKey::Ssh(k) => KeyBytes::Ssh(k.encoded.clone()),
            PublicKey::Age(r) => KeyBytes::Age(r.as_str().to_string()),
            PublicKey::OpenPgp(_) => {
                return Err(SourceError::Malformed("unexpected OpenPGP key".into()));
            }
        };
        found.keys.push(FoundKey {
            usable: age_usable(&key),
            key,
            bytes,
            source: source(),
            shown_user_ids: Vec::new(),
        });
    }
    Ok(found)
}

/// The FR-4 skip note for an SSH key or age recipient.
fn age_usable(key: &PublicKey) -> Result<(), Unusable> {
    if key.is_age_recipient() {
        return Ok(());
    }
    Err(match key.algo() {
        KeyAlgo::SkEd25519 | KeyAlgo::SkEcdsa(_) => Unusable::SkKey,
        KeyAlgo::Rsa(bits) => Unusable::RsaSize(bits),
        _ => Unusable::EcdsaNotAge,
    })
}
