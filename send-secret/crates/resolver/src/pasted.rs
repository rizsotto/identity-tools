//! Pasted key source (SPEC 4 item 7, plan.md "Sources").
//!
//! Binary OpenPGP goes through `split_keys`. Text may hold OpenPGP armor
//! blocks and SSH or age lines, even both: armor blocks go through
//! `split_keys`, the other lines through the `.keys` list reader (bad lines
//! become rejects, unusable keys get a note). A paste with an armor block
//! and other lines that hold no key at all is refused, so nothing is
//! dropped silently. At most 1 MB (S-7).

use async_trait::async_trait;
use identity_core::MAX_KEY_INPUT;
use tokio::time::Instant;

use crate::found::{SplitBlob, openpgp_found, split_blob, ssh_list, valid_user_ids};
use crate::model::{Found, KeySource, Source, SourceError, SourceKind};
use crate::net::Net;
use crate::query::Query;

/// A key the user pasted or gave as a file.
#[derive(Debug, Default, Clone, Copy)]
pub struct PastedSource;

impl PastedSource {
    pub fn new() -> Self {
        PastedSource
    }
}

fn source() -> Source {
    Source {
        kind: SourceKind::Pasted,
        location: "pasted".to_string(),
        first_url: None,
    }
}

#[async_trait]
impl KeySource for PastedSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Pasted
    }

    fn accepts(&self, q: &Query) -> bool {
        matches!(q, Query::Pasted(_))
    }

    async fn lookup(
        &self,
        q: &Query,
        _net: Option<&Net>,
        deadline: Instant,
    ) -> Result<Found, SourceError> {
        let Query::Pasted(bytes) = q else {
            return Err(SourceError::NotFound);
        };
        if bytes.len() > MAX_KEY_INPUT {
            return Err(SourceError::TooLarge);
        }
        let bytes = bytes.strip_prefix("\u{feff}".as_bytes()).unwrap_or(bytes);
        // Binary OpenPGP starts with a packet tag byte (bit 7 set).
        if bytes.first().is_some_and(|b| b & 0x80 != 0) {
            return openpgp(bytes.to_vec(), deadline).await;
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Err(SourceError::Malformed("not a key".into()));
        };
        let (armor, rest) = split_armor(text);
        if armor.is_empty() {
            let found = ssh_list(rest.as_bytes(), &source())?;
            if found.keys.is_empty() && found.rejected.is_empty() {
                return Err(SourceError::Malformed("no key found".into()));
            }
            return Ok(found);
        }
        let mut found = openpgp(armor.into_bytes(), deadline).await?;
        if rest
            .lines()
            .any(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        {
            let lines = ssh_list(rest.as_bytes(), &source()).map_err(|_| {
                SourceError::Malformed(
                    "the paste has an OpenPGP key and other text that is not a key; \
                     paste only keys"
                        .into(),
                )
            })?;
            found.keys.extend(lines.keys);
            found.rejected.extend(lines.rejected);
        }
        Ok(found)
    }
}

/// Splits text into its OpenPGP armor blocks (from a `-----BEGIN PGP` line
/// to the next `-----END PGP` line) and the other lines. Only lines are
/// sorted here; the armor is read by gpg.
fn split_armor(text: &str) -> (String, String) {
    let (mut armor, mut rest) = (String::new(), String::new());
    let mut inside = false;
    for line in text.lines() {
        let t = line.trim();
        if !inside && t.starts_with("-----BEGIN PGP") {
            inside = true;
        }
        let out = if inside { &mut armor } else { &mut rest };
        out.push_str(line);
        out.push('\n');
        if inside && t.starts_with("-----END PGP") {
            inside = false;
        }
    }
    (armor, rest)
}

async fn openpgp(bytes: Vec<u8>, deadline: Instant) -> Result<Found, SourceError> {
    let src = source();
    let keys = match split_blob(bytes, &src, deadline).await? {
        SplitBlob::Keys(keys) => keys,
        SplitBlob::TooMany(rejected) => {
            return Ok(Found {
                rejected: vec![rejected],
                ..Found::default()
            });
        }
    };
    if keys.is_empty() {
        return Err(SourceError::Malformed("no OpenPGP key found".into()));
    }
    let keys = keys
        .into_iter()
        .map(|(key, bytes)| {
            let shown = valid_user_ids(&key);
            openpgp_found(key, bytes, &src, shown)
        })
        .collect();
    Ok(Found {
        keys,
        ..Found::default()
    })
}
