//! Places a key is installed: servers, forges, keyservers, WKD.
//!
//! One provider per location kind. Every provider logs each network call
//! in a [`NetLog`] (NFR-2) and never writes a token anywhere (S-4).

mod error;
mod netlog;
mod provider;
mod token;

pub use error::ProviderError;
pub use inventory::{LocationKind, Purpose, SshHost, Target};
pub use netlog::{NetLog, NetLogEntry};
pub use provider::{AddOpts, KeyRef, Provider, PublicKeyRef, VerifyError, VerifyStatus};
pub use token::{InMemoryTokenSource, Token, TokenError, TokenKey, TokenSource};
