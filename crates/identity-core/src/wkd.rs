//! Web Key Directory hash and URLs (draft-koch-openpgp-webkey-service-22,
//! section 3.1). No network here: callers fetch the URLs.

use sha1::{Digest, Sha1};

use crate::error::WkdError;

/// z-base-32 alphabet, RFC 6189 section 5.1.6.
const ZBASE32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// The WKD hash of an address's local part: only ASCII `A`-`Z` are
/// lowered (other characters are kept as is), then SHA-1, then z-base-32.
/// Always 32 characters.
pub fn wkd_hash(local_part: &str) -> String {
    let digest = Sha1::digest(local_part.to_ascii_lowercase().as_bytes());
    zbase32(&digest)
}

fn zbase32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ZBASE32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ZBASE32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The two WKD URLs for an address. Try `advanced` first; use `direct` only
/// when `openpgpkey.<domain>` has no address (draft section 3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WkdUrls {
    /// `https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>?l=<local>`
    pub advanced: String,
    /// `https://<domain>/.well-known/openpgpkey/hu/<hash>?l=<local>`
    pub direct: String,
}

impl WkdUrls {
    /// The URLs for `address` (`local@domain`). The domain is lower-cased
    /// and must be plain ASCII (`xn--` form for IDNs): labels of `a-z`,
    /// `0-9` and `-`, at least two labels, no IP literal. `l=` is the local
    /// part unchanged, percent-escaped.
    pub fn for_address(address: &str) -> Result<WkdUrls, WkdError> {
        let (local, domain) = address.rsplit_once('@').ok_or(WkdError::NotAnAddress)?;
        if local.is_empty() || local.contains('@') {
            return Err(WkdError::NotAnAddress);
        }
        let domain = domain.to_ascii_lowercase();
        if !valid_domain(&domain) {
            return Err(WkdError::BadDomain);
        }
        let hash = wkd_hash(local);
        let l = percent_escape(local);
        Ok(WkdUrls {
            advanced: format!(
                "https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{hash}?l={l}"
            ),
            direct: format!("https://{domain}/.well-known/openpgpkey/hu/{hash}?l={l}"),
        })
    }
}

fn valid_domain(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    labels.len() >= 2
        && domain.len() <= 253
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && !labels
            .last()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
}

/// RFC 3986 percent-encoding: unreserved characters stay, every other byte
/// becomes `%XX`.
fn percent_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zbase32_of_known_bytes() {
        // RFC 6189 alphabet: 0 -> 'y', 31 -> '9'.
        assert_eq!(zbase32(&[0, 0, 0, 0, 0]), "yyyyyyyy");
        assert_eq!(zbase32(&[0xff; 5]), "99999999");
        assert_eq!(zbase32(&[]), "");
    }

    #[test]
    fn percent_escape_keeps_unreserved() {
        assert_eq!(percent_escape("Joe.Doe_x~-1"), "Joe.Doe_x~-1");
        assert_eq!(percent_escape("a+b c/?&="), "a%2Bb%20c%2F%3F%26%3D");
        assert_eq!(percent_escape("Ü"), "%C3%9C");
    }
}
