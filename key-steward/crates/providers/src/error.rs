use inventory::LocationKind;

use crate::token::TokenError;

/// Provider errors. The text never holds a token (S-4).
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// Not built yet. `add` and `remove` come in M2.
    #[error("{0} is not available yet")]
    NotYet(&'static str),
    #[error("a {kind} provider cannot use this target")]
    WrongTarget { kind: LocationKind },
    #[error("cannot run {program}: {reason}")]
    Spawn { program: String, reason: String },
    #[error(transparent)]
    Token(#[from] TokenError),
    /// The ssh config can make `ssh -G` run commands (`Match exec`). Ask
    /// the user, then allow it.
    #[error("the ssh config can run commands when it is read: {}", .0.join("; "))]
    CommandsNeedConsent(Vec<String>),
    #[error("cannot read the ssh config: {0}")]
    Config(String),
    /// The token is scrubbed from the text.
    #[error("HTTP request failed: {0}")]
    Http(String),
    /// No token is stored for this forge account.
    #[error("no token is stored for {0}")]
    NoToken(String),
    /// The token belongs to another account than the target. The forge
    /// lists the token owner's keys, so no answer about the target is
    /// possible.
    #[error("the token is for the account {owner}, not {account}")]
    TokenOwner { account: String, owner: String },
    /// The forge answered with JSON we do not understand.
    #[error("unexpected answer from {forge}: {what}")]
    BadResponse { forge: LocationKind, what: String },
    #[error("cannot read OpenPGP keys: {0}")]
    OpenPgp(String),
    #[error("HTTP {status} from {url}")]
    HttpStatus { status: u16, url: String },
    #[error(transparent)]
    AuthorizedKeys(#[from] crate::ssh_server::AuthorizedKeysError),
}
