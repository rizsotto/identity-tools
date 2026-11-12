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
}
