//! GitHub: `/user/keys`, `/user/ssh_signing_keys`, `/user/gpg_keys`
//! (SPEC 15, fact 1).

use std::sync::Arc;

use async_trait::async_trait;
use identity_core::{Fingerprint, PublicKey};
use inventory::{LocationKind, Purpose, Target};

use super::{ForgeCore, Listing, OpenPgpReader, base_url, check_objects, title};
use crate::error::ProviderError;
use crate::http::AuthStyle;
use crate::netlog::NetLog;
use crate::provider::{AddOpts, KeyRef, Provider, PublicKeyRef, VerifyStatus};
use crate::token::TokenSource;

const API: &str = "https://api.github.com";
const API_VERSION: &str = "2026-03-10";
const KIND: LocationKind = LocationKind::GitHub;

/// GitHub provider. The target is `https://github.com` plus the account
/// name. The token must belong to that account: the API lists the keys of
/// the token's owner.
#[derive(Clone)]
pub struct GitHub {
    core: ForgeCore,
    api_url: Option<String>,
}

impl GitHub {
    pub fn new(tokens: Arc<dyn TokenSource>, openpgp: OpenPgpReader, netlog: NetLog) -> Self {
        GitHub {
            core: ForgeCore::new(tokens, openpgp, netlog),
            api_url: None,
        }
    }

    /// Uses `url` as the API root instead of `https://api.github.com`.
    /// Tests point it at wiremock.
    pub fn with_api_url(mut self, url: impl Into<String>) -> Self {
        self.api_url = Some(url.into());
        self
    }

    fn api_url(&self, target: &Target) -> Result<String, ProviderError> {
        if let Some(url) = &self.api_url {
            return Ok(url.clone());
        }
        match base_url(KIND, target)? {
            "https://github.com" => Ok(API.to_string()),
            _ => Err(ProviderError::WrongTarget { kind: KIND }),
        }
    }

    async fn listing(&self, target: &Target) -> Result<Listing, ProviderError> {
        let client = self
            .core
            .client(
                KIND,
                target,
                &self.api_url(target)?,
                AuthStyle::Bearer,
                &[
                    ("accept", "application/vnd.github+json"),
                    ("x-github-api-version", API_VERSION),
                ],
            )
            .await?;
        let mut out = Listing::default();
        for (path, purpose) in [
            ("/user/keys?per_page=100", Purpose::SshAuth),
            ("/user/ssh_signing_keys?per_page=100", Purpose::SshSigning),
        ] {
            let items = client.get_all_pages(path).await?;
            check_objects(KIND, &items)?;
            for item in &items {
                out.add_ssh(item, &[purpose], title(item, "title"));
            }
        }
        let items = client.get_all_pages("/user/gpg_keys?per_page=100").await?;
        check_objects(KIND, &items)?;
        for item in &items {
            out.add_gpg(&self.core.openpgp, item, "raw_key", title(item, "name"))
                .await;
        }
        Ok(out)
    }
}

#[async_trait]
impl Provider for GitHub {
    fn kind(&self) -> LocationKind {
        KIND
    }

    async fn list(&self, target: &Target) -> Result<Vec<PublicKeyRef>, ProviderError> {
        Ok(self.listing(target).await?.keys)
    }

    async fn add(
        &self,
        _target: &Target,
        _key: &PublicKey,
        _opts: &AddOpts,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::NotYet("adding a key to GitHub"))
    }

    async fn remove(&self, _target: &Target, _key: &Fingerprint) -> Result<(), ProviderError> {
        Err(ProviderError::NotYet("removing a key from GitHub"))
    }

    async fn verify(&self, target: &Target, key: &KeyRef) -> Result<VerifyStatus, ProviderError> {
        Ok(self.listing(target).await?.verify(key))
    }
}
