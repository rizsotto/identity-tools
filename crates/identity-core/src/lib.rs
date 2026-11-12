//! Key parsing, fingerprints and the GnuPG wrapper. Shared by Key Steward and Send Secret.
//!
//! Rules (decision 0001): no GTK, no network, no app-specific types. Public
//! signatures use only this crate's types, never `ssh_key` or `gpgme` ones.

mod age;
mod error;
mod key;
mod openpgp;
mod parse;
mod private_header;
mod scan;
mod ssh;
mod weak;
mod wkd;

pub use error::{GpgError, KeyError, LineError, WkdError};
pub use key::{
    AgeRecipient, Fingerprint, KeyAlgo, KeyKind, OpenPgpKey, OpenPgpSubkey, PublicKey,
    SshPublicKey, UserId,
};
pub use openpgp::{Gpg, MAX_SPLIT_KEYS, MAX_SPLIT_SUBKEYS, MAX_SPLIT_USER_IDS, OpenPgpBackend};
pub use parse::{MAX_KEY_INPUT, ParsedLine, parse_public_keys, read_key_file};
pub use private_header::{PrivateKeyProtection, private_key_protection};
pub use scan::{SshKeyFile, SshScan, scan_ssh_dir};
pub use weak::{KeyWarning, MIN_RSA_BITS, Severity, WeakReason, weak_key_warnings};
pub use wkd::{WkdUrls, wkd_hash};
