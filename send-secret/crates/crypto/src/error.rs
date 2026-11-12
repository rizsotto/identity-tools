//! Error types. Messages name recipients by label only. They never hold
//! plaintext, ciphertext, passphrases or key material (S-5).

use std::fmt;
use std::io;

use crate::Format;

/// Errors from `encrypt` and `decrypt`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input is not OpenPGP or age (FR-7).
    #[error("input is not an OpenPGP or age message")]
    UnknownFormat,
    /// A message plan holds a key that does not match its format. A guard:
    /// `plan` never builds such a plan.
    #[error("message for {label}: key does not match the {format} format")]
    WrongFormat { label: String, format: Format },
    /// A message plan has no keys.
    #[error("message for {label}: no keys to encrypt to")]
    NoKeys { label: String },
    /// None of the available keys can open the message.
    #[error("no available key can decrypt this message")]
    NoMatchingKey,
    /// A protected key needs a passphrase and none was given, or it was wrong.
    #[error("could not unlock the key")]
    KeyLocked,
    /// The message is damaged or was changed.
    #[error("the message is damaged or was changed")]
    Corrupt,
    /// The age backend failed. The text comes from the `age` crate.
    #[error("age: {0}")]
    Age(String),
    /// The OpenPGP backend failed. The text comes from gpgme.
    #[error("OpenPGP: {0}")]
    OpenPgp(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Errors from planning messages, before any output is written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// A recipient has no usable key, or none in the forced format
    /// (FR-3, FR-11). Never dropped silently.
    #[error("{}", unreachable_text(.label, *.format))]
    Unreachable {
        label: String,
        format: Option<Format>,
    },
    /// The self copy (FR-12) was forced to a format the sender has no
    /// usable key for. Raised before any output is written. The CLI adds
    /// the hint to skip the self copy.
    #[error("no {format} key of your own that can encrypt the self copy")]
    NoSelfKey { format: Format },
}

fn unreachable_text(label: &str, format: Option<Format>) -> String {
    match format {
        Some(format) => format!("{label} has no usable {format} key"),
        None => format!("{label} has no usable key"),
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Format::OpenPgp => "OpenPGP",
            Format::Age => "age",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_names_the_recipient() {
        let any = PlanError::Unreachable {
            label: "alice".into(),
            format: None,
        };
        assert_eq!(any.to_string(), "alice has no usable key");
        let forced = PlanError::Unreachable {
            label: "bob".into(),
            format: Some(Format::Age),
        };
        assert_eq!(forced.to_string(), "bob has no usable age key");
    }

    #[test]
    fn no_self_key_names_the_format() {
        let err = PlanError::NoSelfKey {
            format: Format::OpenPgp,
        };
        assert_eq!(
            err.to_string(),
            "no OpenPGP key of your own that can encrypt the self copy"
        );
    }

    #[test]
    fn wrong_format_names_label_and_format() {
        let err = Error::WrongFormat {
            label: "carol".into(),
            format: Format::OpenPgp,
        };
        assert_eq!(
            err.to_string(),
            "message for carol: key does not match the OpenPGP format"
        );
    }

    #[test]
    fn io_errors_convert() {
        let err: Error = io::Error::new(io::ErrorKind::BrokenPipe, "pipe").into();
        assert!(matches!(err, Error::Io(_)));
    }
}
