use std::io::Read;
use std::path::Path;

use crate::error::KeyError;
use crate::key::PublicKey;
use crate::{age, ssh};

/// Largest key input we parse: 1 MiB (Send Secret S-7).
pub const MAX_KEY_INPUT: usize = 1024 * 1024;

/// Read a key file, refusing files larger than [`MAX_KEY_INPUT`]. Reads at
/// most one byte past the limit.
pub fn read_key_file(path: &Path) -> Result<Vec<u8>, KeyError> {
    let mut buf = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_KEY_INPUT as u64 + 1)
        .read_to_end(&mut buf)?;
    if buf.len() > MAX_KEY_INPUT {
        return Err(KeyError::TooLarge {
            limit: MAX_KEY_INPUT,
        });
    }
    Ok(buf)
}

/// Parse SSH public key lines and age X25519 recipients, one per line.
///
/// This covers `.pub` files, forge `.keys` lists and age recipient files.
/// Blank lines and `#` comments are skipped. Every key is returned,
/// including types age can not use (see [`PublicKey::is_age_recipient`]).
/// Any other line is an error. OpenPGP keys are not parsed here.
pub fn parse_public_keys(input: &[u8]) -> Result<Vec<PublicKey>, KeyError> {
    if input.len() > MAX_KEY_INPUT {
        return Err(KeyError::TooLarge {
            limit: MAX_KEY_INPUT,
        });
    }
    let text = std::str::from_utf8(input).map_err(|_| KeyError::NotText)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if text.contains("-----BEGIN PGP") {
        return Err(KeyError::UnsupportedFormat("OpenPGP"));
    }
    if text.contains("PRIVATE KEY-----") || text.contains("AGE-SECRET-KEY-") {
        return Err(KeyError::UnsupportedFormat("private key"));
    }

    let mut keys = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parsed = if line.starts_with("age1") {
            age::parse_recipient(line)
        } else {
            ssh::parse_line(line)
        };
        keys.push(parsed.map_err(|reason| KeyError::Malformed {
            line: i + 1,
            reason,
        })?);
    }
    if keys.is_empty() {
        return Err(KeyError::Empty);
    }
    Ok(keys)
}
