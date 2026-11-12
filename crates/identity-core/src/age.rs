use bech32::Bech32;
use bech32::primitives::decode::CheckedHrpstring;

use crate::error::LineError;
use crate::key::AgeRecipient;

const HRP: &str = "age";

/// Parse an age X25519 recipient (`age1...`, Bech32, 32 bytes).
pub(crate) fn parse_recipient(s: &str) -> Result<AgeRecipient, LineError> {
    // Like age, accept only the lower case form.
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(LineError::BadAgeRecipient);
    }
    let checked = CheckedHrpstring::new::<Bech32>(s).map_err(|_| LineError::BadAgeRecipient)?;
    if checked.hrp().as_str() != HRP || checked.byte_iter().count() != 32 {
        return Err(LineError::BadAgeRecipient);
    }
    Ok(AgeRecipient(s.to_string()))
}
