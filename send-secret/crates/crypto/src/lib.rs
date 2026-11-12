//! Encrypt and decrypt facade over OpenPGP (gpgme) and age.

mod detect;
mod error;
mod recipient_file;

pub use detect::{DETECT_LEN, Detected, Detection, detect_format};
pub use error::{Error, PlanError};
pub use recipient_file::{RecipientFile, RecipientFileError};

/// The two message formats (SPEC section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    OpenPgp,
    Age,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
