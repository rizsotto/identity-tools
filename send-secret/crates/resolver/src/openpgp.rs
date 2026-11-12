//! OpenPGP helpers shared by the sources: split a fetched or pasted blob
//! under the source's deadline, and the FR-4 skip note for a key.

use identity_core::{Gpg, GpgError, OpenPgpKey};
use tokio::time::{Instant, timeout_at};

use crate::model::{SourceError, Unusable};

/// What splitting a blob gave.
pub(crate) enum Split {
    Keys(Vec<(OpenPgpKey, Vec<u8>)>),
    /// More than [`identity_core::MAX_SPLIT_KEYS`] keys.
    TooManyKeys,
}

/// [`Gpg::split_keys`] on a blocking thread, before `deadline` (S-7: gpg's
/// time grows with the packets in the blob). Errors never hold the input.
pub(crate) async fn split_blob(bytes: Vec<u8>, deadline: Instant) -> Result<Split, SourceError> {
    let task = tokio::task::spawn_blocking(move || Gpg::split_keys(&bytes));
    match timeout_at(deadline, task).await {
        Err(_) => Err(SourceError::Timeout),
        Ok(Err(_)) => Err(SourceError::Malformed("reading the keys failed".into())),
        Ok(Ok(Ok(keys))) => Ok(Split::Keys(keys)),
        Ok(Ok(Err(GpgError::TooManyKeys { .. }))) => Ok(Split::TooManyKeys),
        Ok(Ok(Err(GpgError::TooLarge { .. }))) => Err(SourceError::TooLarge),
        Ok(Ok(Err(e @ GpgError::TooComplex { .. }))) => Err(SourceError::Malformed(e.to_string())),
        Ok(Ok(Err(_))) => Err(SourceError::Malformed("not a valid OpenPGP key".into())),
    }
}

/// The FR-4 skip note for an OpenPGP key, or `Ok` when it can be
/// encrypted to.
pub(crate) fn usable(key: &OpenPgpKey) -> Result<(), Unusable> {
    if key.revoked {
        return Err(Unusable::Revoked);
    }
    if key.expired {
        return Err(Unusable::Expired);
    }
    if key.can_encrypt && !key.disabled && !key.invalid {
        return Ok(());
    }
    let expired_subkey = key
        .subkeys
        .iter()
        .any(|s| s.can_encrypt && s.expired && !s.revoked);
    if expired_subkey && !key.disabled && !key.invalid {
        Err(Unusable::Expired)
    } else {
        Err(Unusable::NoEncryptionSubkey)
    }
}
