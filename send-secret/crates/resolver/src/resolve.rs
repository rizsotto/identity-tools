//! Run the sources, merge by fingerprint, order by SPEC 4 rank
//! (plan.md "Resolve, merge and order").

use futures_util::future::join_all;
use identity_core::Fingerprint;
use tokio::time::{Instant, timeout_at};

use crate::ResolverConfig;
use crate::model::{Found, FoundKey, KeySource, Rejected, Source, SourceError, SourceKind};
use crate::net::Net;
use crate::netlog::NetLogEntry;
use crate::query::Query;

/// Which sources run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Contacts, keyring and pasted only. No network.
    LocalOnly,
    /// Every source that accepts the query.
    Full,
}

/// One key, merged over every source that found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub fingerprint: Fingerprint,
    /// The copy from the best ranked source.
    pub key: FoundKey,
    /// Every source that found it, in SPEC 4 order.
    pub sources: Vec<Source>,
}

/// The result of one lookup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolution {
    /// Merged and ordered.
    pub candidates: Vec<Candidate>,
    pub rejected: Vec<Rejected>,
    /// Per source, in SPEC 4 order. Shown, never fatal alone.
    pub errors: Vec<(SourceKind, SourceError)>,
    /// Sources that returned keys but had a part fail ([`Found::incomplete`]).
    /// Keys from these may be missing: never narrow a pin on them.
    pub partial: Vec<(SourceKind, SourceError)>,
    /// Every DNS check and HTTP request of this lookup (NFR-2): the
    /// resolver's `NetLog` entries added while it ran. Lookups that run at
    /// the same time on one `Net` mix their entries here.
    pub requests: Vec<NetLogEntry>,
}

pub struct Resolver {
    sources: Vec<Box<dyn KeySource>>,
    net: Option<Net>,
    cfg: ResolverConfig,
}

impl Resolver {
    /// `net` may be `None` when only [`Mode::LocalOnly`] will be used; in
    /// [`Mode::Full`] network sources then report an error.
    pub fn new(cfg: ResolverConfig, net: Option<Net>, sources: Vec<Box<dyn KeySource>>) -> Self {
        Resolver { sources, net, cfg }
    }

    pub fn net(&self) -> Option<&Net> {
        self.net.as_ref()
    }

    /// Runs every source that accepts `q` (and fits `mode`) at once, each
    /// with its own timeout, then merges the results.
    pub async fn resolve(&self, q: &Query, mode: Mode) -> Resolution {
        let log_start = self.net.as_ref().map(|n| n.log().len());
        let runs = self
            .sources
            .iter()
            .filter(|s| mode == Mode::Full || !s.kind().is_network())
            .filter(|s| s.accepts(q))
            .map(|s| async move { (s.kind(), self.run(s.as_ref(), q).await) });
        let mut results = join_all(runs).await;
        results.sort_by_key(|(kind, _)| *kind);

        let mut out = Resolution::default();
        for (kind, result) in results {
            match result {
                Ok(mut found) => {
                    out.partial
                        .extend(found.incomplete.drain(..).map(|e| (kind, e)));
                    merge(&mut out, found);
                }
                Err(e) => out.errors.push((kind, e)),
            }
        }
        if let (Some(net), Some(start)) = (&self.net, log_start) {
            out.requests = net.log().entries_since(start);
        }
        out
    }

    async fn run(&self, source: &dyn KeySource, q: &Query) -> Result<Found, SourceError> {
        let net = if source.kind().is_network() {
            Some(self.net.as_ref().ok_or_else(|| {
                SourceError::Net("network lookups are off for this resolver".into())
            })?)
        } else {
            None
        };
        let deadline = Instant::now() + self.cfg.source_timeout;
        match timeout_at(deadline, source.lookup(q, net, deadline)).await {
            Ok(r) => r,
            Err(_) => Err(SourceError::Timeout),
        }
    }
}

/// Adds one source's result. Sources come in rank order, so the first copy
/// of a fingerprint is the best ranked one. A usable copy replaces an
/// unusable better ranked one (an expired key in the keyring, renewed on
/// WKD); every source stays listed (S-3).
fn merge(out: &mut Resolution, found: Found) {
    for key in found.keys {
        let fpr = key.fingerprint();
        match out.candidates.iter_mut().find(|c| c.fingerprint == fpr) {
            Some(c) => {
                if !c.sources.contains(&key.source) {
                    c.sources.push(key.source.clone());
                }
                if c.key.usable.is_err() && key.usable.is_ok() {
                    c.key = key;
                }
            }
            None => out.candidates.push(Candidate {
                fingerprint: fpr,
                sources: vec![key.source.clone()],
                key,
            }),
        }
    }
    out.rejected.extend(found.rejected);
}
