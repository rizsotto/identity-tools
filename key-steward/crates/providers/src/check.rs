//! Check runner: verifies every location of a key and writes the result
//! to the store (FR-2, FR-3, FR-4).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use identity_core::Fingerprint;
use inventory::{LocationId, LocationKind, Status, Store, StoreError};

use crate::provider::{KeyRef, Provider};

/// What happened to one location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// Checked; this status and the time are now in the store.
    Checked(Status),
    /// No provider for this location kind. The store is not changed.
    NoProvider,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub location: LocationId,
    pub kind: LocationKind,
    pub outcome: CheckOutcome,
}

/// Runs checks with one provider per location kind.
#[derive(Default, Clone)]
pub struct CheckRunner {
    providers: HashMap<LocationKind, Arc<dyn Provider>>,
}

impl CheckRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a provider for its kind, replacing an earlier one.
    pub fn with(mut self, provider: Arc<dyn Provider>) -> Self {
        self.providers.insert(provider.kind(), provider);
        self
    }

    /// Checks every stored location of `key`, one after the other, and
    /// writes each status with the check time. `identity_file` is the
    /// private key file for SSH server checks; it is passed to `ssh` by
    /// path and never read (S-1). A provider error is stored as
    /// [`Status::Error`] with its text, which never holds a token (S-4).
    /// Only store errors fail the run.
    pub async fn check_key(
        &self,
        store: &mut Store,
        key: &Fingerprint,
        identity_file: Option<&Path>,
    ) -> Result<Vec<CheckResult>, StoreError> {
        let mut results = Vec::new();
        for loc in store.list_for_key(key)? {
            let Some(provider) = self.providers.get(&loc.kind) else {
                results.push(CheckResult {
                    location: loc.id,
                    kind: loc.kind,
                    outcome: CheckOutcome::NoProvider,
                });
                continue;
            };
            let key_ref = KeyRef {
                fingerprint: loc.key.clone(),
                purpose: loc.purpose,
                identity_file: identity_file.map(PathBuf::from),
            };
            let status = match provider.verify(&loc.target, &key_ref).await {
                Ok(v) => v.to_status(),
                Err(e) => Status::Error(e.to_string()),
            };
            store.set_status(loc.id, &status, SystemTime::now())?;
            results.push(CheckResult {
                location: loc.id,
                kind: loc.kind,
                outcome: CheckOutcome::Checked(status),
            });
        }
        Ok(results)
    }
}
