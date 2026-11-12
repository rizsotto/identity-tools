//! Encrypt and decrypt facade over OpenPGP (gpgme) and age.

mod age_backend;
mod detect;
mod error;
mod facade;
mod self_identity;

pub use age_backend::{AgeKey, SkipReason, Skipped, age_key};
pub use detect::{DETECT_LEN, Detected, Detection, MessageReader, detect_format, open_message};
pub use error::{Error, PlanError};
pub use facade::{DecryptCtx, Decrypted, decrypt};
pub use self_identity::{SelfIdentity, self_identity_path};

/// The two message formats (SPEC section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    OpenPgp,
    Age,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
