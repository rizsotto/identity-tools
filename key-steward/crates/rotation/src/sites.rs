//! The providers the engine works through. The engine never calls ssh or
//! HTTP itself (plan.md, "Crates touched").

use std::collections::HashMap;

use async_trait::async_trait;
use identity_core::Fingerprint;
use inventory::{LocationKind, Target};
use providers::{Provider, ProviderError, RemoveOpts};

/// What a removal reports beyond success.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Removed {
    /// SSH: `cert-authority` lines (numbers from 1) that still hold the
    /// old key. They are kept, but the old private key can still sign a
    /// certificate that logs in there.
    pub ca_lines_with_old_key: Vec<usize>,
}

/// One provider per location kind.
#[async_trait]
pub trait Providers: Send + Sync {
    fn provider(&self, kind: LocationKind) -> Option<&dyn Provider>;

    /// [`Provider::remove`] plus its report. The default reports nothing
    /// more; the SSH provider fills in the `cert-authority` lines once
    /// its `remove` returns them.
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

/// Providers by kind.
#[derive(Default)]
pub struct ProviderMap {
    map: HashMap<LocationKind, Box<dyn Provider>>,
}

impl ProviderMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `p` for its kind, replacing any earlier one.
    pub fn with(mut self, p: Box<dyn Provider>) -> Self {
        self.map.insert(p.kind(), p);
        self
    }
}

impl Providers for ProviderMap {
    fn provider(&self, kind: LocationKind) -> Option<&dyn Provider> {
        self.map.get(&kind).map(|p| p.as_ref())
    }
}
