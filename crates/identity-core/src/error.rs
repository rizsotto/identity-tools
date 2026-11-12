use thiserror::Error;

/// Errors from reading and parsing keys.
///
/// Messages never echo the input: it may be hostile, and it may end up in
/// logs.
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("key input is larger than {limit} bytes")]
    TooLarge { limit: usize },
    #[error("key input is not UTF-8 text")]
    NotText,
    #[error("line {line}: {reason}")]
    Malformed { line: usize, reason: String },
    #[error("unsupported key format: {0}")]
    UnsupportedFormat(&'static str),
    #[error("no public key found")]
    Empty,
    #[error("cannot read key file: {0}")]
    Io(#[from] std::io::Error),
}
