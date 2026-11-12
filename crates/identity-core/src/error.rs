use thiserror::Error;

/// Errors for a whole key input or file.
///
/// Messages are fixed text and never echo the input: it may be hostile
/// (terminal escapes, fake text) and it may end up in logs.
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("key input is larger than {limit} bytes")]
    TooLarge { limit: usize },
    #[error("key input is not UTF-8 text")]
    NotText,
    #[error("unsupported key format: {0}")]
    UnsupportedFormat(&'static str),
    #[error("cannot read key file: {0}")]
    Io(#[from] std::io::Error),
}

/// Why one line of a key list was skipped. Fixed text, never the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum LineError {
    #[error("unknown key type")]
    UnknownType,
    #[error("SSH certificates are not supported")]
    Certificate,
    #[error("authorized_keys options are not supported")]
    Options,
    #[error("malformed SSH public key")]
    Malformed,
    #[error("malformed age recipient")]
    BadAgeRecipient,
}
