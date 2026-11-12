//! The providers the engine works through. The engine never calls ssh or
//! HTTP itself (plan.md, "Crates touched").

use std::collections::HashMap;

use async_trait::async_trait;
use identity_core::Fingerprint;
use inventory::{LocationKind, Target};
use providers::authorized_keys::KeyLine;
use providers::{
    KeyRef, OldKeyCheck, Provider, ProviderError, PublicKeyRef, RemoveOpts, SshServer,
};

/// What a removal reports beyond success.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Removed {
    /// SSH: `cert-authority` lines (numbers from 1) that still hold the
    /// old key. They are kept, but the old private key can still sign a
    /// certificate that logs in there.
    pub ca_lines_with_old_key: Vec<usize>,
}

/// One provider per location kind. Methods beyond [`Provider`] are the
/// seam for what the SSH provider does more (it logs in with a chosen
/// key, reports `cert-authority` lines, and checks that the old key is
/// refused); their defaults use the plain [`Provider`] calls.
#[async_trait]
pub trait Providers: Send + Sync {
    fn provider(&self, kind: LocationKind) -> Option<&dyn Provider>;

    /// The keys at `target`. SSH logs in with `login`: the old key while
    /// settling `install` and in the rollback gate, the new key while
    /// settling `remove_old` and in the S-3 gate. The default ignores
    /// `login`.
    async fn list_as(
        &self,
        kind: LocationKind,
        target: &Target,
        login: &KeyRef,
    ) -> Result<Vec<PublicKeyRef>, ProviderError> {
        let _ = login;
        let p = self
            .provider(kind)
            .ok_or(ProviderError::WrongTarget { kind })?;
        p.list(target).await
    }

    /// Whether the old key still logs in at `target`, after its removal.
    /// Only [`OldKeyCheck::Refused`] counts as gone. The default does not
    /// know.
    async fn check_old_key(
        &self,
        kind: LocationKind,
        target: &Target,
        old: &KeyRef,
    ) -> Result<OldKeyCheck, ProviderError> {
        let _ = (kind, target, old);
        Ok(OldKeyCheck::Unknown("this provider cannot check".into()))
    }

    /// SSH: every key line of `authorized_keys` with its options, logging
    /// in with `login`. Read only; for the dry-run. The default has none.
    async fn ssh_lines(
        &self,
        target: &Target,
        login: &KeyRef,
    ) -> Result<Vec<KeyLine>, ProviderError> {
        let _ = (target, login);
        Err(ProviderError::WrongTarget {
            kind: LocationKind::SshServer,
        })
    }

    /// [`Provider::remove`] plus its report. The default reports nothing
    /// more.
    async fn remove_key(
        &self,
        kind: LocationKind,
        target: &Target,
        key: &Fingerprint,
        opts: &RemoveOpts,
    ) -> Result<Removed, ProviderError> {
        let p = self
            .provider(kind)
            .ok_or(ProviderError::WrongTarget { kind })?;
        p.remove(target, key, opts).await?;
        Ok(Removed::default())
    }
}

/// Providers by kind, with the SSH provider kept as its own type so its
/// extra methods are reached without a downcast.
#[derive(Default)]
pub struct ProviderMap {
    ssh: Option<SshServer>,
    map: HashMap<LocationKind, Box<dyn Provider>>,
}

impl ProviderMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `p` for its kind, replacing any earlier one. Use
    /// [`ProviderMap::with_ssh`] for SSH servers.
    pub fn with(mut self, p: Box<dyn Provider>) -> Self {
        if p.kind() == LocationKind::SshServer {
            self.ssh = None;
        }
        self.map.insert(p.kind(), p);
        self
    }

    pub fn with_ssh(mut self, ssh: SshServer) -> Self {
        self.map.remove(&LocationKind::SshServer);
        self.ssh = Some(ssh);
        self
    }

    fn ssh(&self, kind: LocationKind) -> Option<&SshServer> {
        self.ssh
            .as_ref()
            .filter(|_| kind == LocationKind::SshServer)
    }
}

#[async_trait]
impl Providers for ProviderMap {
    fn provider(&self, kind: LocationKind) -> Option<&dyn Provider> {
        match self.ssh(kind) {
            Some(s) => Some(s),
            None => self.map.get(&kind).map(|p| p.as_ref()),
        }
    }

    async fn list_as(
        &self,
        kind: LocationKind,
        target: &Target,
        login: &KeyRef,
    ) -> Result<Vec<PublicKeyRef>, ProviderError> {
        match self.ssh(kind) {
            Some(s) => s.list_as(target, login).await,
            None => {
                let p = self
                    .provider(kind)
                    .ok_or(ProviderError::WrongTarget { kind })?;
                p.list(target).await
            }
        }
    }

    async fn check_old_key(
        &self,
        kind: LocationKind,
        target: &Target,
        old: &KeyRef,
    ) -> Result<OldKeyCheck, ProviderError> {
        match self.ssh(kind) {
            Some(s) => s.check_old_key(target, old).await,
            None => Ok(OldKeyCheck::Unknown("this provider cannot check".into())),
        }
    }

    async fn ssh_lines(
        &self,
        target: &Target,
        login: &KeyRef,
    ) -> Result<Vec<KeyLine>, ProviderError> {
        match self.ssh(LocationKind::SshServer) {
            Some(s) => s.lines_as(target, login).await,
            None => Err(ProviderError::WrongTarget {
                kind: LocationKind::SshServer,
            }),
        }
    }

    async fn remove_key(
        &self,
        kind: LocationKind,
        target: &Target,
        key: &Fingerprint,
        opts: &RemoveOpts,
    ) -> Result<Removed, ProviderError> {
        if let Some(s) = self.ssh(kind) {
            let r = s.remove_key(target, key, opts).await?;
            return Ok(Removed {
                ca_lines_with_old_key: r.ca_lines_with_old_key,
            });
        }
        let p = self
            .provider(kind)
            .ok_or(ProviderError::WrongTarget { kind })?;
        p.remove(target, key, opts).await?;
        Ok(Removed::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use providers::NetLog;

    #[test]
    fn ssh_provider_is_reached_by_kind() {
        let map = ProviderMap::new().with_ssh(SshServer::new(NetLog::new()));
        assert!(map.ssh(LocationKind::SshServer).is_some());
        assert!(map.ssh(LocationKind::GitHub).is_none());
        let p = map.provider(LocationKind::SshServer).unwrap();
        assert_eq!(p.kind(), LocationKind::SshServer);
        assert!(map.provider(LocationKind::GitLab).is_none());
    }
}
