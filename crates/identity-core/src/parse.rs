use std::io::Read;
use std::path::Path;

use crate::error::{KeyError, LineError};
use crate::key::PublicKey;
use crate::{age, ssh};

/// Largest key input we parse: 1 MB (Send Secret S-7).
pub const MAX_KEY_INPUT: usize = 1_000_000;

/// The result for one key line. `line` counts from 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLine {
    pub line: usize,
    pub key: Result<PublicKey, LineError>,
}

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
/// Blank lines and `#` comments are ignored. Every other line gives one
/// [`ParsedLine`], so the caller can use the good keys and skip the rest
/// with a note (Send Secret FR-4). Keys age can not use are still returned
/// (see [`PublicKey::is_age_recipient`]).
///
/// Whole-input errors: too large, not UTF-8, OpenPGP armor (not parsed
/// here), or a private key.
pub fn parse_public_keys(input: &[u8]) -> Result<Vec<ParsedLine>, KeyError> {
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

    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = if line.starts_with("age1") {
            age::parse_recipient(line).map(PublicKey::Age)
        } else {
            ssh::parse_line(line).map(PublicKey::Ssh)
        };
        out.push(ParsedLine { line: i + 1, key });
    }
    Ok(out)
}
