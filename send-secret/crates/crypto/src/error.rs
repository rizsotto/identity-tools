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
    /// A recipient's key can not be used. The reason is fixed text.
    #[error("key for {label}: {reason}")]
    BadKey { label: String, reason: String },
    /// The user's gpg.conf has an option that would add a key or a signer
    /// to every message, and gpgme can not turn it off (S-8).
    #[error("{}: the gpg option \"{option}\" would {}; remove it to send OpenPGP messages", .file.display(), gpg_conf_effect(.option))]
    GpgConf {
        file: std::path::PathBuf,
        option: String,
    },
    /// Signing is on, but there is no OpenPGP secret key that can sign.
    #[error("no OpenPGP secret key that can sign")]
    NoSigner,
    /// The message decrypted, but its signature is bad.
    #[error("the signature is bad: the message was changed or forged")]
    BadSignature,
    /// A key file is over the size limit (S-7).
    #[error("key is larger than {limit} bytes")]
    KeyTooLarge { limit: usize },
    /// An identity (private key) file could not be used. Fixed text.
    #[error("identity: {0}")]
    Identity(&'static str),
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
}

fn gpg_conf_effect(option: &str) -> &'static str {
    if option == "local-user" {
        "add a second signature by another key"
    } else {
        "add another key to every message"
    }
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
