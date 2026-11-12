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
    #[error("expected exactly one key")]
    NotOneKey,
    #[error(transparent)]
    Line(#[from] LineError),
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

/// Errors from the GnuPG backend. Fixed text, never the key input.
#[derive(Debug, Error)]
pub enum GpgError {
    /// An error reported by gpgme or gpg. The text comes from libgpg-error.
    #[error("GnuPG error: {0}")]
    Gpgme(String),
    #[error("key input is larger than {limit} bytes")]
    TooLarge { limit: usize },
    /// A home dir path with a NUL byte.
    #[error("unsafe GnuPG home dir path")]
    UnsafePath,
    #[error("cannot read the GnuPG config: {0}")]
    Io(#[from] std::io::Error),
}

impl From<gpgme::Error> for GpgError {
    fn from(e: gpgme::Error) -> Self {
        GpgError::Gpgme(e.to_string())
    }
}

/// Why WKD URLs cannot be built for an address. Fixed text, never the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WkdError {
    #[error("not an email address")]
    NotAnAddress,
    #[error("the address's domain is not a plain ASCII host name")]
    BadDomain,
}
