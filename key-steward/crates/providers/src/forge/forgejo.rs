//! Forgejo, Gitea and Codeberg: `/api/v1/user/keys` and
//! `/api/v1/user/gpg_keys` (SPEC 15, fact 1). There is no separate SSH
//! signing key list: these forges check SSH commit signatures with the
//! same keys, so each SSH key counts for auth and for signing. A GPG key's
//! `public_key` is standard base64 of the bare binary public key packet
//! (no armor, no user ID); GnuPG reads it for the fingerprint.

use std::sync::Arc;

use async_trait::async_trait;
use identity_core::{Fingerprint, PublicKey, SshPublicKey};
use inventory::{LocationKind, Purpose, Target};
use serde_json::{Value, json};

use super::write::{self, ForgeWrites, Op};
use super::{
    ForgeCore, Listing, OpenPgpReader, base_url, base64_bytes, check_objects, check_owner, title,
};
use crate::error::ProviderError;
use crate::http::{AuthStyle, HttpClient};
use crate::netlog::NetLog;
use crate::provider::{AddOpts, KeyRef, Provider, PublicKeyRef, RemoveOpts, VerifyStatus};
use crate::token::TokenSource;

const KIND: LocationKind = LocationKind::Forgejo;
/// Forgejo's default largest page (`[api] MAX_RESPONSE_ITEMS`).
const PAGE: &str = "limit=50";

/// Forgejo provider, also for Gitea and Codeberg. The target's base URL
/// is the instance (`https://codeberg.org`); the API is under
/// `<base>/api/v1`. The API lists the keys of the token's owner, so every listing
/// first checks with `GET /user` that the owner is the target account.
#[derive(Clone)]
pub struct Forgejo {
    core: ForgeCore,
}

impl Forgejo {
    pub fn new(tokens: Arc<dyn TokenSource>, openpgp: OpenPgpReader, netlog: NetLog) -> Self {
        Forgejo {
            core: ForgeCore::new(tokens, openpgp, netlog),
        }
    }

    async fn listing(&self, target: &Target) -> Result<Listing, ProviderError> {
        let client = self.session(target).await?;
        let mut out = self.ssh_keys(&client).await?;
        let items = client
            .get_all_pages(&format!("/user/gpg_keys?{PAGE}"))
            .await?;
        check_objects(KIND, &items)?;
        for item in &items {
            out.add_gpg(
                &self.core.openpgp,
                item,
                base64_bytes(item, "public_key"),
                None,
            )
            .await;
        }
        Ok(out)
    }
}

#[async_trait]
impl ForgeWrites for Forgejo {
    fn kind(&self) -> LocationKind {
        KIND
    }

    async fn session(&self, target: &Target) -> Result<HttpClient, ProviderError> {
        let api = format!("{}/api/v1", base_url(KIND, target)?);
        let client = self
            .core
            .client(KIND, target, &api, AuthStyle::TokenPrefix, &[])
            .await?;
        check_owner(KIND, &client, target, "login").await?;
        Ok(client)
    }

    async fn ssh_keys(&self, client: &HttpClient) -> Result<Listing, ProviderError> {
        let mut out = Listing::default();
        let items = client.get_all_pages(&format!("/user/keys?{PAGE}")).await?;
        check_objects(KIND, &items)?;
        for item in &items {
            // The `fingerprint` field is not used: we compute our own.
            out.add_ssh(
                item,
                &[Purpose::SshAuth, Purpose::SshSigning],
                title(item, "title"),
            );
        }
        Ok(out)
    }

    fn add_request(
        &self,
        key: &SshPublicKey,
        title: &str,
        _purpose: Purpose,
        _like: Option<&KeyRef>,
        _listing: &Listing,
    ) -> (String, Value) {
        (
            "/user/keys".into(),
            json!({ "title": title, "key": key.encoded }),
        )
    }

    fn delete_path(&self, _purpose: Purpose, id: &str) -> String {
        format!("/user/keys/{id}")
    }

    fn scopes(&self, _op: Op, _purpose: Purpose) -> String {
        "the write:user scope".into()
    }
}

#[async_trait]
impl Provider for Forgejo {
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
