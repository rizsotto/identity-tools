//! Recipient resolution: sources, ordering, result model.

use std::time::Duration;

mod forge;
mod found;
mod model;
mod net;
mod netlog;
mod query;
mod resolve;

pub use forge::{GitHubSource, GitLabSource};
pub use model::{
    Found, FoundKey, KeyBytes, KeySource, RejectReason, Rejected, Source, SourceError, SourceKind,
    Unusable,
};
pub use net::{Fetched, Net, NetError, OriginMap};
pub use netlog::{NetLog, NetLogEntry};
pub use query::{Email, Host, Query, QueryError, parse_query};
pub use resolve::{Candidate, Mode, Resolution, Resolver};

/// Limits for one resolver. Tests use short timeouts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverConfig {
    /// Total time for one source, all its requests included (SPEC 7: 5 s).
    pub source_timeout: Duration,
    /// Most redirects one request may follow, each https (5).
    pub max_redirects: u8,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        ResolverConfig {
            source_timeout: Duration::from_secs(5),
            max_redirects: 5,
        }
    }
}
