//! GitHub and GitLab sources (SPEC 4 items 5 and 6, SPEC 9 "GitHub").
//!
//! - `.keys` is an `authorized_keys` list, parsed by identity-core.
//! - GitHub's `.gpg` is armor that may hold no key at all; zero keys means
//!   "no OpenPGP key", whatever the text. No email check (S-6 names only
//!   WKD and keys.openpgp.org).
//! - One request per URL per lookup, never a retry.

use async_trait::async_trait;
use tokio::time::Instant;
use url::Url;

use crate::found::{SplitBlob, need_net, openpgp_found, source_of, split_blob, ssh_list};
use crate::model::{Found, KeySource, SourceError, SourceKind};
use crate::net::Net;
use crate::query::Query;

/// `github:<user>`: `https://github.com/<user>.keys` and `.gpg`, at once.
#[derive(Debug, Default, Clone, Copy)]
pub struct GitHubSource;

/// `gitlab:<user>` or `gitlab:<host>/<user>`: `https://<host>/<user>.keys`,
/// with `gitlab.com` as the default host.
#[derive(Debug, Default, Clone, Copy)]
pub struct GitLabSource;

#[async_trait]
impl KeySource for GitHubSource {
    fn kind(&self) -> SourceKind {
        SourceKind::GitHub
    }

    fn accepts(&self, q: &Query) -> bool {
        matches!(q, Query::GitHub { .. })
    }

    async fn lookup(
        &self,
        q: &Query,
        net: Option<&Net>,
        deadline: Instant,
    ) -> Result<Found, SourceError> {
        let Query::GitHub { user } = q else {
            return Err(SourceError::NotFound);
        };
        let net = need_net(net)?;
        let keys_url = user_url("github.com", None, user, "keys")?;
        let gpg_url = user_url("github.com", None, user, "gpg")?;
        let (keys, gpg) = tokio::join!(
            ssh_keys(net, SourceKind::GitHub, &keys_url, deadline),
            gpg_keys(net, &gpg_url, deadline),
        );
        combine(keys, gpg)
    }
}

#[async_trait]
impl KeySource for GitLabSource {
    fn kind(&self) -> SourceKind {
        SourceKind::GitLab
    }

    fn accepts(&self, q: &Query) -> bool {
        matches!(q, Query::GitLab { .. })
    }

    async fn lookup(
        &self,
        q: &Query,
        net: Option<&Net>,
        deadline: Instant,
    ) -> Result<Found, SourceError> {
        let Query::GitLab { host, user } = q else {
            return Err(SourceError::NotFound);
        };
        let net = need_net(net)?;
        let url = match host {
            Some(h) => user_url(h.name(), h.port(), user, "keys")?,
            None => user_url(GITLAB_COM, None, user, "keys")?,
        };
        ssh_keys(net, SourceKind::GitLab, &url, deadline).await
    }
}

const GITLAB_COM: &str = "gitlab.com";

/// `https://<host>[:port]/<user>.<ext>`, built with `Url` APIs only. The
/// host and user were checked by the query parser.
fn user_url(host: &str, port: Option<u16>, user: &str, ext: &str) -> Result<Url, SourceError> {
    let bad = || SourceError::Net("cannot build the request URL".into());
    let mut url = Url::parse("https://gitlab.com/").map_err(|_| bad())?;
    url.set_host(Some(host)).map_err(|_| bad())?;
    url.set_port(port).map_err(|_| bad())?;
    url.path_segments_mut()
        .map_err(|_| bad())?
        .clear()
        .push(&format!("{user}.{ext}"));
    Ok(url)
}

async fn ssh_keys(
    net: &Net,
    kind: SourceKind,
    url: &Url,
    deadline: Instant,
) -> Result<Found, SourceError> {
    let fetched = net.get(url, deadline).await?;
    ssh_list(&fetched.body, &source_of(kind, &fetched))
}

async fn gpg_keys(net: &Net, url: &Url, deadline: Instant) -> Result<Found, SourceError> {
    let fetched = net.get(url, deadline).await?;
    let source = source_of(SourceKind::GitHub, &fetched);
    let mut found = Found::default();
    match split_blob(fetched.body, &source, deadline).await? {
        SplitBlob::Keys(keys) => {
            for (key, bytes) in keys {
                let shown = key.user_ids.clone();
                found.keys.push(openpgp_found(key, bytes, &source, shown));
            }
        }
        SplitBlob::TooMany(rejected) => found.rejected.push(rejected),
    }
    Ok(found)
}

/// Both answers together. 404 on one is fine; both 404 is "not found". An
/// error is only reported when nothing was found: a part that failed must
/// not look like "this user has no key".
fn combine(
    keys: Result<Found, SourceError>,
    gpg: Result<Found, SourceError>,
) -> Result<Found, SourceError> {
    let mut found = Found::default();
    let mut error = None;
    let mut not_found = 0;
    for part in [keys, gpg] {
        match part {
            Ok(f) => {
                found.keys.extend(f.keys);
                found.rejected.extend(f.rejected);
            }
            Err(SourceError::NotFound) => not_found += 1,
            Err(e) => {
                error.get_or_insert(e);
            }
        }
    }
    if not_found == 2 {
        return Err(SourceError::NotFound);
    }
    match error {
        Some(e) if found.keys.is_empty() => Err(e),
        _ => Ok(found),
    }
}
