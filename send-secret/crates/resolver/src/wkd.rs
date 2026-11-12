//! WKD source (SPEC 4 item 3, SPEC 9 "WKD", plan.md "Sources").
//!
//! - DNS check of `openpgpkey.<domain>`. If it has an address, only the
//!   advanced URL is asked; else only the direct URL. A 404, timeout or TLS
//!   error at the advanced host is never a reason to fall back (draft 3.1).
//! - The answer may be binary or armored and may hold several keys.
//! - S-6: a key is kept only if a valid user ID has the queried email, and
//!   only those user IDs are shown. Other keys are rejected.

use async_trait::async_trait;
use identity_core::WkdUrls;
use tokio::time::Instant;
use url::Url;

use crate::found::{SplitBlob, keep_matching, need_net, source_of, split_blob};
use crate::model::{Found, KeySource, SourceError, SourceKind};
use crate::net::Net;
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
        let net = need_net(net)?;
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
        let source = source_of(SourceKind::Wkd, &fetched);

        let mut found = Found::default();
        let keys = match split_blob(fetched.body, &source, deadline).await? {
            SplitBlob::Keys(keys) => keys,
            SplitBlob::TooMany(rejected) => {
                found.rejected.push(rejected);
                return Ok(found);
            }
        };
        if keys.is_empty() {
            return Err(SourceError::Malformed(
                "no OpenPGP key in the answer".into(),
            ));
        }
        keep_matching(keys, &address, &source, &mut found);
        Ok(found)
    }
}
