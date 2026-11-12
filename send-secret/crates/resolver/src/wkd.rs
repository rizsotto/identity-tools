//! WKD source (SPEC 4 item 3, SPEC 9 "WKD", plan.md "Sources").
//!
//! - DNS check of `openpgpkey.<domain>`. If it has an address, only the
//!   advanced URL is asked; else only the direct URL. A 404, timeout or TLS
//!   error at the advanced host is never a reason to fall back (draft 3.1).
//! - The answer may be binary or armored and may hold several keys.
//! - S-6: a key is kept only if a valid user ID has the queried email, and
//!   only those user IDs are shown. Other keys are rejected.

use async_trait::async_trait;
use identity_core::{PublicKey, WkdUrls};
use tokio::time::Instant;
use url::Url;

use crate::model::{
    Found, FoundKey, KeyBytes, KeySource, RejectReason, Rejected, Source, SourceError, SourceKind,
};
use crate::net::Net;
use crate::openpgp::{Split, split_blob, usable};
use crate::query::Query;

/// Looks up an email address in the Web Key Directory of its domain.
#[derive(Debug, Default, Clone, Copy)]
pub struct WkdSource;

impl WkdSource {
    pub fn new() -> Self {
        WkdSource
    }
}

#[async_trait]
impl KeySource for WkdSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Wkd
    }

    fn accepts(&self, q: &Query) -> bool {
        matches!(q, Query::Email(_))
    }

    async fn lookup(
        &self,
        q: &Query,
        net: Option<&Net>,
        deadline: Instant,
    ) -> Result<Found, SourceError> {
        let Query::Email(email) = q else {
            return Err(SourceError::NotFound);
        };
        let net = net.ok_or_else(|| SourceError::Net("network lookups are off for WKD".into()))?;
        let address = email.address();
        let urls = WkdUrls::for_address(&address).map_err(|e| SourceError::Net(e.to_string()))?;
        let advanced_host = format!("openpgpkey.{}", email.domain());
        let url = if net.host_has_address(&advanced_host, deadline).await? {
            urls.advanced
        } else {
            urls.direct
        };
        let url = Url::parse(&url).map_err(|_| SourceError::Net("bad WKD URL".into()))?;
        let fetched = net.get(&url, deadline).await?;
        let source = Source {
            kind: SourceKind::Wkd,
            location: fetched.url.to_string(),
            first_url: (fetched.url != fetched.first_url).then(|| fetched.first_url.to_string()),
        };

        let keys = match split_blob(fetched.body, deadline).await? {
            Split::Keys(keys) => keys,
            Split::TooManyKeys => {
                return Ok(Found {
                    keys: Vec::new(),
                    rejected: vec![Rejected {
                        fingerprint: None,
                        source,
                        reason: RejectReason::TooManyKeys,
                    }],
                });
            }
        };
        if keys.is_empty() {
            return Err(SourceError::Malformed(
                "no OpenPGP key in the answer".into(),
            ));
        }

        let mut found = Found::default();
        for (mut key, bytes) in keys {
            let matching: Vec<_> = key
                .user_ids
                .iter()
                .filter(|u| u.has_email(&address))
                .cloned()
                .collect();
            if matching.is_empty() {
                found.rejected.push(Rejected {
                    fingerprint: Some(key.fingerprint.clone()),
                    source: source.clone(),
                    reason: RejectReason::EmailMismatch,
                });
                continue;
            }
            // Other user IDs are never shown, not even from the summary.
            key.user_ids = matching.clone();
            found.keys.push(FoundKey {
                usable: usable(&key),
                key: PublicKey::OpenPgp(key),
                bytes: KeyBytes::OpenPgp(bytes),
                source: source.clone(),
                shown_user_ids: matching,
            });
        }
        Ok(found)
    }
}
