//! GitLab, gitlab.com or self-hosted: `/api/v4/user/keys` and
//! `/api/v4/user/gpg_keys` (SPEC 15, fact 1).

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

const KIND: LocationKind = LocationKind::GitLab;

/// GitLab provider. The target's base URL is the instance
/// (`https://gitlab.com` or a self-hosted one); the API is under
/// `<base>/api/v4`. The token must belong to the target account: the API
/// lists the keys of the token's owner.
#[derive(Clone)]
pub struct GitLab {
    core: ForgeCore,
}

impl GitLab {
    pub fn new(tokens: Arc<dyn TokenSource>, openpgp: OpenPgpReader, netlog: NetLog) -> Self {
        GitLab {
            core: ForgeCore::new(tokens, openpgp, netlog),
        }
    }

    async fn listing(&self, target: &Target) -> Result<Listing, ProviderError> {
        let api = format!("{}/api/v4", base_url(KIND, target)?);
        let client = self
            .core
            .client(KIND, target, &api, AuthStyle::PrivateToken, &[])
            .await?;
        let mut out = Listing::default();
        let items = client.get_all_pages("/user/keys?per_page=100").await?;
        check_objects(KIND, &items)?;
        for item in &items {
            out.add_ssh(
                item,
                purposes(item["usage_type"].as_str()),
                title(item, "title"),
            );
        }
        let items = client.get_all_pages("/user/gpg_keys?per_page=100").await?;
        check_objects(KIND, &items)?;
        for item in &items {
            out.add_gpg(&self.core.openpgp, item, "key", None).await;
        }
        Ok(out)
    }
}

/// `usage_type` of a GitLab SSH key. Missing means the default,
/// `auth_and_signing`. An unknown value counts for nothing.
fn purposes(usage: Option<&str>) -> &'static [Purpose] {
    match usage {
        Some("auth") => &[Purpose::SshAuth],
        Some("signing") => &[Purpose::SshSigning],
        Some("auth_and_signing") | None => &[Purpose::SshAuth, Purpose::SshSigning],
        Some(_) => &[],
    }
}

#[async_trait]
impl Provider for GitLab {
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
        Err(ProviderError::NotYet("adding a key to GitLab"))
    }

    async fn remove(&self, _target: &Target, _key: &Fingerprint) -> Result<(), ProviderError> {
        Err(ProviderError::NotYet("removing a key from GitLab"))
    }

    async fn verify(&self, target: &Target, key: &KeyRef) -> Result<VerifyStatus, ProviderError> {
        Ok(self.listing(target).await?.verify(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_type_to_purposes() {
        assert_eq!(purposes(Some("auth")), &[Purpose::SshAuth]);
        assert_eq!(purposes(Some("signing")), &[Purpose::SshSigning]);
        let both = &[Purpose::SshAuth, Purpose::SshSigning];
        assert_eq!(purposes(Some("auth_and_signing")), both);
        assert_eq!(purposes(None), both);
        assert!(purposes(Some("future")).is_empty());
    }
}
