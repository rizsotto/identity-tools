//! GnuPG keyring source (SPEC 4 item 2, plan.md "Sources").
//!
//! Finds keys whose valid user ID has the queried email, or whose primary
//! fingerprint is the query (a subkey fingerprint does not match). No
//! match is `NotFound`. Reads only; never imports. gpgme contexts are
//! not `Send`, so all gpgme work runs on a blocking thread under the
//! source's deadline.

use std::path::PathBuf;

use async_trait::async_trait;
use identity_core::{Gpg, OpenPgpBackend};
use tokio::time::{Instant, timeout_at};

use crate::found::{openpgp_found, valid_user_ids};
use crate::model::{Found, KeySource, Source, SourceError, SourceKind};
use crate::net::Net;
use crate::query::Query;

/// The user's GnuPG keyring, or the one in a given home dir.
#[derive(Debug, Clone, Default)]
pub struct KeyringSource {
    home: Option<PathBuf>,
}

impl KeyringSource {
    /// gpg's own default home (`GNUPGHOME` or `~/.gnupg`). The app uses
    /// this; tests use [`KeyringSource::with_home`].
    pub fn user_default() -> Self {
        KeyringSource { home: None }
    }

    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        KeyringSource {
            home: Some(home.into()),
        }
    }
}

#[async_trait]
impl KeySource for KeyringSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Keyring
    }

    fn accepts(&self, q: &Query) -> bool {
        matches!(q, Query::Email(_) | Query::Fingerprint(_))
    }

    async fn lookup(
        &self,
        q: &Query,
        _net: Option<&Net>,
        deadline: Instant,
    ) -> Result<Found, SourceError> {
        let wanted = match q {
            Query::Email(e) => Wanted::Email(e.address()),
            Query::Fingerprint(f) => Wanted::Fingerprint(f.clone()),
            _ => return Err(SourceError::NotFound),
        };
        let home = self.home.clone();
        let task = tokio::task::spawn_blocking(move || search(home, &wanted));
        let found = match timeout_at(deadline, task).await {
            Err(_) => return Err(SourceError::Timeout),
            Ok(Err(_)) => return Err(SourceError::Keyring("reading the keyring failed".into())),
            Ok(Ok(r)) => r?,
        };
        if found.keys.is_empty() {
            return Err(SourceError::NotFound);
        }
        Ok(found)
    }
}

enum Wanted {
    Email(String),
    Fingerprint(String),
}

fn search(home: Option<PathBuf>, wanted: &Wanted) -> Result<Found, SourceError> {
    let err = |e: identity_core::GpgError| SourceError::Keyring(e.to_string());
    let mut gpg = match &home {
        Some(h) => Gpg::with_home(h),
        None => Gpg::user_default(),
    }
    .map_err(err)?;
    let location = gpg
        .effective_home()
        .map(|h| h.display().to_string())
        .unwrap_or_else(|| "GnuPG keyring".to_string());
    let source = Source {
        kind: SourceKind::Keyring,
        location,
        first_url: None,
    };
    let matches: Vec<_> = gpg
        .public_keys()
        .map_err(err)?
        .into_iter()
        .filter(|k| match wanted {
            Wanted::Email(addr) => k.user_ids.iter().any(|u| u.has_email(addr)),
            Wanted::Fingerprint(f) => k.fingerprint.as_str().eq_ignore_ascii_case(f),
        })
        .collect();
    let mut found = Found::default();
    for key in matches {
        let bytes = gpg.export_key(key.fingerprint.as_str()).map_err(err)?;
        let shown = valid_user_ids(&key);
        found.keys.push(openpgp_found(key, bytes, &source, shown));
    }
    Ok(found)
}
