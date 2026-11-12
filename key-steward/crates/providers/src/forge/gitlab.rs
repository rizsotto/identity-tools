//! GitLab, gitlab.com or self-hosted: `/api/v4/user/keys` and
//! `/api/v4/user/gpg_keys` (SPEC 15, fact 1).

use std::sync::Arc;

use async_trait::async_trait;
use identity_core::{Fingerprint, PublicKey, SshPublicKey};
use inventory::{LocationKind, Purpose, Target};
use serde_json::{Value, json};

use super::write::{self, ForgeWrites, Op};
use super::{
    ForgeCore, Listing, OpenPgpReader, base_url, check_objects, check_owner, ssh_fingerprint,
    text_bytes, title,
};
use crate::error::ProviderError;
use crate::http::{AuthStyle, HttpClient};
use crate::netlog::NetLog;
use crate::provider::{AddOpts, KeyRef, Provider, PublicKeyRef, RemoveOpts, VerifyStatus};
use crate::token::TokenSource;

const KIND: LocationKind = LocationKind::GitLab;

/// GitLab provider. The target's base URL is the instance
/// (`https://gitlab.com` or a self-hosted one); the API is under
/// `<base>/api/v4`. The API lists the keys of the token's owner, so every listing
/// first checks with `GET /user` that the owner is the target account.
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
        let client = self.session(target).await?;
        let mut out = self.ssh_keys(&client).await?;
        let items = client.get_all_pages("/user/gpg_keys?per_page=100").await?;
        check_objects(KIND, &items)?;
        for item in &items {
            out.add_gpg(&self.core.openpgp, item, text_bytes(item, "key"), None)
                .await;
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

/// The new key's `usage_type`: what the old key (`like`) serves, plus
/// `purpose`. Without an old key in the list, `purpose` alone.
fn usage_type(listing: &Listing, like: Option<&KeyRef>, purpose: Purpose) -> &'static str {
    let serves = |p: Purpose| {
        purpose == p
            || like.is_some_and(|l| {
                listing
                    .keys
                    .iter()
                    .any(|k| k.fingerprint == l.fingerprint && k.purpose == p)
            })
    };
    match (serves(Purpose::SshAuth), serves(Purpose::SshSigning)) {
        (true, true) => "auth_and_signing",
        (true, false) => "auth",
        _ => "signing",
    }
}

#[async_trait]
impl ForgeWrites for GitLab {
    fn kind(&self) -> LocationKind {
        KIND
    }

    async fn session(&self, target: &Target) -> Result<HttpClient, ProviderError> {
        let api = format!("{}/api/v4", base_url(KIND, target)?);
        let client = self
            .core
            .client(KIND, target, &api, AuthStyle::PrivateToken, &[])
            .await?;
        check_owner(KIND, &client, target, "username").await?;
        Ok(client)
    }

    async fn ssh_keys(&self, client: &HttpClient) -> Result<Listing, ProviderError> {
        let mut out = Listing::default();
        let items = client.get_all_pages("/user/keys?per_page=100").await?;
        check_objects(KIND, &items)?;
        for item in &items {
            let usage = item["usage_type"].as_str();
            let serves = purposes(usage);
            if serves.is_empty()
                && let Some(fpr) = item["key"].as_str().and_then(ssh_fingerprint)
            {
                let usage: String = usage
                    .unwrap_or_default()
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(40)
                    .collect();
                out.unusable_ssh.push((
                    fpr,
                    format!("a usage type Key Steward does not know ({usage})"),
                ));
            }
            out.add_ssh(item, serves, title(item, "title"));
        }
        Ok(out)
    }

    fn add_request(
        &self,
        key: &SshPublicKey,
        title: &str,
        purpose: Purpose,
        like: Option<&KeyRef>,
        listing: &Listing,
    ) -> (String, Value) {
        (
            "/user/keys".into(),
            json!({
                "title": title,
                "key": key.encoded,
                "usage_type": usage_type(listing, like, purpose),
            }),
        )
    }

    fn delete_path(&self, _purpose: Purpose, id: &str) -> String {
        format!("/user/keys/{id}")
    }

    fn scopes(&self, _op: Op, _purpose: Purpose) -> String {
        "the api scope (read_user cannot write)".into()
    }

    /// `Key` model: `validates :title, length: { maximum: 255 }`.
    fn max_title(&self) -> Option<usize> {
        Some(255)
    }

    /// One object per key: GitLab refuses the same key twice, and the
    /// API cannot change the usage type of a key it has.
    fn check_add(
        &self,
        listing: &Listing,
        key: &SshPublicKey,
        purpose: Purpose,
    ) -> Result<(), ProviderError> {
        if listing
            .keys
            .iter()
            .any(|k| k.fingerprint == key.fingerprint)
        {
            let want = match purpose {
                Purpose::SshSigning => "signing",
                _ => "authentication",
            };
            return Err(ProviderError::Unsupported(format!(
                "the key is already on GitLab, but not for {want}, and GitLab cannot \
                 change the usage type of a key it has. In GitLab, delete the key and add \
                 it again with usage type \"Authentication & Signing\", then check again."
            )));
        }
        Ok(())
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
        target: &Target,
        key: &PublicKey,
        opts: &AddOpts,
    ) -> Result<(), ProviderError> {
        write::add(self, target, key, opts).await
    }

    async fn remove(
        &self,
        target: &Target,
        key: &Fingerprint,
        opts: &RemoveOpts,
    ) -> Result<(), ProviderError> {
        write::remove(self, target, key, opts).await
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
