use bech32::Bech32;
use bech32::primitives::decode::CheckedHrpstring;

use crate::key::{Fingerprint, KeyAlgo, KeyKind, PublicKey};

const HRP: &str = "age";

/// Parse an age X25519 recipient (`age1...`, Bech32, 32 bytes).
pub(crate) fn parse_recipient(s: &str) -> Result<PublicKey, String> {
    // Like age, accept only the lower case form.
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err("age recipient must be lower case".to_string());
    }
    let checked = CheckedHrpstring::new::<Bech32>(s).map_err(|e| e.to_string())?;
    if checked.hrp().as_str() != HRP {
        return Err("not an age recipient".to_string());
    }
    if checked.byte_iter().count() != 32 {
        return Err("age recipient must hold 32 bytes".to_string());
    }
    Ok(PublicKey {
        kind: KeyKind::Age,
        algo: KeyAlgo::X25519,
        fingerprint: Fingerprint::Age(s.to_string()),
        comment: None,
        created: None,
        expiry: None,
        encoded: s.to_string(),
    })
}
