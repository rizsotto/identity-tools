//! Places a key is installed: servers, forges, keyservers, WKD.
//!
//! One provider per location kind. Every provider logs each network call
//! in a [`NetLog`] (NFR-2) and never writes a token anywhere (S-4).

mod check;
mod error;
mod forge;
mod http;
mod netlog;
mod provider;
mod secret_service;
mod ssh_server;
mod token;

pub use check::{CheckOutcome, CheckResult, CheckRunner};
pub use error::ProviderError;
pub use forge::{Forgejo, GitHub, GitLab, OpenPgpReader};
pub use http::{AuthStyle, HttpClient, HttpReply};
pub use inventory::{LocationKind, Purpose, SshHost, Target};
pub use netlog::{NetLog, NetLogEntry};
pub use provider::{
    AddOpts, KeyRef, Provider, PublicKeyRef, RemoveOpts, VerifyError, VerifyStatus,
};
pub use secret_service::SecretServiceTokens;
pub use ssh_server::SshServer;
pub use token::{InMemoryTokenSource, Token, TokenError, TokenKey, TokenSource};
