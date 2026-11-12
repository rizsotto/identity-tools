//! keys.openpgp.org source (SPEC 4 item 4, SPEC 9).
//!
//! `GET https://keys.openpgp.org/vks/v1/by-email/<percent-encoded email>`.
//! 200 is an armored key, 404 "not found", 429 rate limited (one by-email
//! request per minute, burst 50). Every key must have a valid user ID with
//! the queried email (S-6); only those user IDs are shown.

use async_trait::async_trait;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use tokio::time::Instant;
use url::Url;

use crate::found::{SplitBlob, keep_matching, need_net, source_of, split_blob};
use crate::model::{Found, KeySource, SourceError, SourceKind};
use crate::net::Net;
use crate::query::Query;

const BASE: &str = "https://keys.openpgp.org/vks/v1/by-email/";

/// Every byte but ASCII letters, digits, `-`, `.`, `_`, `~` and `@` is
/// escaped, so `+` reaches the server as `%2B` and no decoder can read it
/// as a space.
const EMAIL_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'@');

#[derive(Debug, Default, Clone, Copy)]
pub struct VksSource;

#[async_trait]
impl KeySource for VksSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Vks
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
        let url = by_email_url(&address)?;
        let fetched = net.get(&url, deadline).await?;
        let source = source_of(SourceKind::Vks, &fetched);
        let mut found = Found::default();
        match split_blob(fetched.body, &source, deadline).await? {
            SplitBlob::Keys(keys) if keys.is_empty() => {
                return Err(SourceError::Malformed("no key in the answer".into()));
            }
            SplitBlob::Keys(keys) => keep_matching(keys, &address, &source, &mut found),
            SplitBlob::TooMany(rejected) => found.rejected.push(rejected),
        }
        Ok(found)
    }
}

/// The by-email URL. The address is fully escaped (only `[A-Za-z0-9-._~@%]`
/// is left), so appending it can not change anything but the last segment.
fn by_email_url(address: &str) -> Result<Url, SourceError> {
    let escaped = utf8_percent_encode(address, EMAIL_SEGMENT).to_string();
    Url::parse(&format!("{BASE}{escaped}"))
        .map_err(|_| SourceError::Net("cannot build the request URL".into()))
}
