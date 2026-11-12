//! GitHub: `/user/keys`, `/user/ssh_signing_keys`, `/user/gpg_keys`
//! (SPEC 15, fact 1).

use std::sync::Arc;

use async_trait::async_trait;
use identity_core::{Fingerprint, PublicKey, SshPublicKey};
use inventory::{LocationKind, Purpose, Target};
use serde_json::{Value, json};

use super::write::{self, ForgeWrites, Op};
use super::{
    ForgeCore, Listing, OpenPgpReader, base_url, check_objects, check_owner, text_bytes, title,
};
use crate::error::ProviderError;
use crate::http::{AuthStyle, HttpClient};
use crate::netlog::NetLog;
use crate::provider::{AddOpts, KeyRef, Provider, PublicKeyRef, RemoveOpts, VerifyStatus};
use crate::token::TokenSource;

const API: &str = "https://api.github.com";
const API_VERSION: &str = "2026-03-10";
const KIND: LocationKind = LocationKind::GitHub;

/// GitHub provider. The target is `https://github.com` plus the account
/// name. The API lists the keys of the token's owner, so every listing
/// first checks with `GET /user` that the owner is the target account.
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
        let client = self.session(target).await?;
        let mut out = self.ssh_keys(&client).await?;
        let items = client.get_all_pages("/user/gpg_keys?per_page=100").await?;
        check_objects(KIND, &items)?;
        for item in &items {
            out.add_gpg(
                &self.core.openpgp,
                item,
                text_bytes(item, "raw_key"),
                title(item, "name"),
            )
            .await;
        }
        Ok(out)
    }
}

/// The SSH key lists: auth keys and signing keys are separate objects.
const SSH_LISTS: [(&str, Purpose); 2] = [
    ("/user/keys", Purpose::SshAuth),
    ("/user/ssh_signing_keys", Purpose::SshSigning),
];

fn list_path(purpose: Purpose) -> &'static str {
    match purpose {
        Purpose::SshSigning => SSH_LISTS[1].0,
        _ => SSH_LISTS[0].0,
    }
}

#[async_trait]
impl ForgeWrites for GitHub {
    fn kind(&self) -> LocationKind {
        KIND
    }

    async fn session(&self, target: &Target) -> Result<HttpClient, ProviderError> {
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
        check_owner(KIND, &client, target, "login").await?;
        Ok(client)
    }

    async fn ssh_keys(&self, client: &HttpClient) -> Result<Listing, ProviderError> {
        let mut out = Listing::default();
        for (path, purpose) in SSH_LISTS {
            let items = client
                .get_all_pages(&format!("{path}?per_page=100"))
                .await?;
            check_objects(KIND, &items)?;
            for item in &items {
                out.add_ssh(item, &[purpose], title(item, "title"));
            }
        }
        Ok(out)
    }

    fn add_request(
        &self,
        key: &SshPublicKey,
        title: &str,
        purpose: Purpose,
        _like: Option<&KeyRef>,
        _listing: &Listing,
    ) -> (String, Value) {
        (
            list_path(purpose).to_string(),
            json!({ "title": title, "key": key.encoded }),
        )
    }

    fn delete_path(&self, purpose: Purpose, id: &str) -> String {
        format!("{}/{id}", list_path(purpose))
    }

    fn scopes(&self, op: Op, purpose: Purpose) -> String {
        let (classic, fine) = match (op, purpose) {
            (Op::Add, Purpose::SshSigning) => ("write:ssh_signing_key", "SSH signing keys"),
            (Op::Remove, Purpose::SshSigning) => ("admin:ssh_signing_key", "SSH signing keys"),
            (Op::Add, _) => ("write:public_key", "Git SSH keys"),
            (Op::Remove, _) => ("admin:public_key", "Git SSH keys"),
        };
        format!(
            "the classic scope {classic}, or for a fine-grained token \"{fine}\" with write access"
        )
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
