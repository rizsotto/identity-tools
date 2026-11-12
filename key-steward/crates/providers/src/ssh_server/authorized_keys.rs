//! `authorized_keys` parser and editor, pure (FR-6, SPEC 9.1).
//!
//! The file comes from a server, so it is treated as hostile: at most
//! [`MAX_FILE`] bytes, and a line we do not understand is kept as it is.
//! Every line keeps its raw bytes and its line ending (LF, CRLF, or none
//! for a last line without newline). An edit only adds or drops whole
//! lines; all other bytes stay the same.
//!
//! Options follow sshd(8), "AUTHORIZED_KEYS FILE FORMAT": they end at the
//! first space or tab outside double quotes, and `\"` is a literal quote.
//! Lines with the `cert-authority` option hold a CA, not a login key: they
//! never match a fingerprint and are never changed.

use identity_core::{Fingerprint, PublicKey, SshPublicKey, parse_public_keys};

/// Largest file we read or write: 1 MB.
pub const MAX_FILE: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EditError {
    #[error("the authorized_keys file is larger than {MAX_FILE} bytes")]
    TooLarge,
    #[error("the old key is not in the authorized_keys file")]
    OldKeyMissing,
    #[error("the new key is not in the authorized_keys file, so the old key stays")]
    NewKeyMissing,
    #[error("the old and the new key are the same key")]
    SameKey,
    #[error("the new key's comment has a control character")]
    BadComment,
}

/// One login key line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLine {
    /// Line number, from 1.
    pub line: usize,
    /// The options exactly as written, if any.
    pub options: Option<String>,
    pub key: SshPublicKey,
    /// A CA line (`cert-authority`): never matched, never changed.
    pub cert_authority: bool,
}

#[derive(Debug, Clone)]
struct Line {
    /// The line without its ending.
    text: Vec<u8>,
    ending: &'static [u8],
    key: Option<KeyLine>,
}

/// A parsed `authorized_keys` file.
#[derive(Debug, Clone)]
pub struct AuthorizedKeys {
    lines: Vec<Line>,
}

impl AuthorizedKeys {
    /// Parses the file. Only a file over [`MAX_FILE`] is an error.
    pub fn parse(bytes: &[u8]) -> Result<Self, EditError> {
        if bytes.len() > MAX_FILE {
            return Err(EditError::TooLarge);
        }
        let mut lines = Vec::new();
        let mut rest = bytes;
        while !rest.is_empty() {
            let (text, ending, next) = match rest.iter().position(|&b| b == b'\n') {
                Some(i) if i > 0 && rest[i - 1] == b'\r' => {
                    (&rest[..i - 1], b"\r\n" as &'static [u8], &rest[i + 1..])
                }
                Some(i) => (&rest[..i], b"\n" as &'static [u8], &rest[i + 1..]),
                None => (rest, b"" as &'static [u8], &rest[rest.len()..]),
            };
            let key = parse_key_line(text, lines.len() + 1);
            lines.push(Line {
                text: text.to_vec(),
                ending,
                key,
            });
            rest = next;
        }
        Ok(AuthorizedKeys { lines })
    }

    /// All key lines, CA lines included (see [`KeyLine::cert_authority`]).
    pub fn keys(&self) -> impl Iterator<Item = &KeyLine> {
        self.lines.iter().filter_map(|l| l.key.as_ref())
    }

    /// The file as bytes, unchanged.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for l in &self.lines {
            out.extend_from_slice(&l.text);
            out.extend_from_slice(l.ending);
        }
        out
    }

    /// After each line with `old`, adds a line with the same options and
    /// the new key, with the same line ending. A line with the new key and
    /// the same options already there is not added again, so a second run
    /// changes nothing. Refuses if no line has `old`.
    pub fn add_like(&self, old: &Fingerprint, new: &SshPublicKey) -> Result<Vec<u8>, EditError> {
        if &new.fingerprint == old {
            return Err(EditError::SameKey);
        }
        if new
            .comment
            .as_deref()
            .is_some_and(|c| c.chars().any(char::is_control))
        {
            return Err(EditError::BadComment);
        }
        if !self.lines.iter().any(|l| matches(l, old)) {
            return Err(EditError::OldKeyMissing);
        }
        let default_ending = self
            .lines
            .iter()
            .map(|l| l.ending)
            .find(|e| !e.is_empty())
            .unwrap_or(b"\n");
        let mut present: Vec<Option<String>> = self
            .lines
            .iter()
            .filter(|l| matches(l, &new.fingerprint))
            .filter_map(|l| l.key.as_ref().map(|k| k.options.clone()))
            .collect();
        let mut out = Vec::new();
        for l in &self.lines {
            out.extend_from_slice(&l.text);
            let options = match &l.key {
                Some(k) if matches(l, old) && !present.contains(&k.options) => k.options.clone(),
                _ => {
                    out.extend_from_slice(l.ending);
                    continue;
                }
            };
            out.extend_from_slice(if l.ending.is_empty() {
                default_ending
            } else {
                l.ending
            });
            if let Some(o) = &options {
                out.extend_from_slice(o.as_bytes());
                out.push(b' ');
            }
            out.extend_from_slice(new.encoded.as_bytes());
            if let Some(c) = &new.comment {
                out.push(b' ');
                out.extend_from_slice(c.as_bytes());
            }
            out.extend_from_slice(l.ending);
            present.push(options);
        }
        cap(out)
    }

    /// Drops every line with `old`. Refuses if no line with `keep` stays.
    /// If `old` is not there, the file stays as it is.
    pub fn remove(&self, old: &Fingerprint, keep: &Fingerprint) -> Result<Vec<u8>, EditError> {
        if old == keep {
            return Err(EditError::SameKey);
        }
        if !self.lines.iter().any(|l| matches(l, keep)) {
            return Err(EditError::NewKeyMissing);
        }
        let mut out = Vec::new();
        for l in self.lines.iter().filter(|l| !matches(l, old)) {
            out.extend_from_slice(&l.text);
            out.extend_from_slice(l.ending);
        }
        cap(out)
    }
}

fn cap(out: Vec<u8>) -> Result<Vec<u8>, EditError> {
    if out.len() > MAX_FILE {
        Err(EditError::TooLarge)
    } else {
        Ok(out)
    }
}

/// A login key line (not a CA line) with this fingerprint.
fn matches(line: &Line, fpr: &Fingerprint) -> bool {
    line.key
        .as_ref()
        .is_some_and(|k| !k.cert_authority && &k.key.fingerprint == fpr)
}

/// Like sshd: first try the line as a bare key, then as options and a key.
fn parse_key_line(text: &[u8], line: usize) -> Option<KeyLine> {
    let text = std::str::from_utf8(text).ok()?;
    if text.starts_with('\u{feff}') {
        return None;
    }
    let text = text.trim_start_matches([' ', '\t']);
    if text.is_empty() || text.starts_with('#') {
        return None;
    }
    if let Some(key) = parse_key(text) {
        return Some(KeyLine {
            line,
            options: None,
            key,
            cert_authority: false,
        });
    }
    let end = options_end(text)?;
    let (options, rest) = text.split_at(end);
    let key = parse_key(rest.trim_start_matches([' ', '\t']))?;
    Some(KeyLine {
        line,
        cert_authority: split_options(options)
            .iter()
            .any(|o| option_name(o).eq_ignore_ascii_case("cert-authority")),
        options: Some(options.to_string()),
        key,
    })
}

fn parse_key(text: &str) -> Option<SshPublicKey> {
    match parse_public_keys(text.as_bytes()).ok()?.as_slice() {
        [one] => match &one.key {
            Ok(PublicKey::Ssh(k)) => Some(k.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Byte index where the options end (first space or tab outside quotes).
/// `None` for an unclosed quote or a line with nothing after the options.
fn options_end(text: &str) -> Option<usize> {
    let b = text.as_bytes();
    let mut quoted = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if b.get(i + 1) == Some(&b'"') => i += 1,
            b'"' => quoted = !quoted,
            b' ' | b'\t' if !quoted => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Splits options at commas outside quotes.
fn split_options(options: &str) -> Vec<&str> {
    let b = options.as_bytes();
    let mut out = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if b.get(i + 1) == Some(&b'"') => i += 1,
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                out.push(&options[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(&options[start..]);
    out
}

fn option_name(option: &str) -> &str {
    option.split('=').next().unwrap_or(option)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOP3xJfcaGYrwTcdoje/Ka7JhNrATYv7RJIjLUBvVJAq";

    #[test]
    fn options_end_at_unquoted_space() {
        assert_eq!(options_end(r#"a="x y",b z"#), Some(9));
        assert_eq!(options_end(r#"a="x \" y" z"#), Some(10));
        assert_eq!(options_end(r#"a="x y"#), None);
        assert_eq!(options_end("restrict"), None);
    }

    #[test]
    fn split_options_keeps_quoted_commas() {
        assert_eq!(
            split_options(r#"from="a,b",cert-authority,x="\",""#),
            vec![r#"from="a,b""#, "cert-authority", r#"x="\",""#]
        );
    }

    #[test]
    fn lines_with_bad_options_are_not_keys() {
        for line in [
            format!("command=\"open {KEY} c"),
            format!("{KEY}x"),
            format!("\u{feff}{KEY}"),
            "restrict".to_string(),
        ] {
            assert!(parse_key_line(line.as_bytes(), 1).is_none(), "{line}");
        }
        let k = parse_key_line(format!("Cert-Authority,x=\"a b\" {KEY} c").as_bytes(), 1).unwrap();
        assert!(k.cert_authority);
        assert_eq!(k.options.as_deref(), Some("Cert-Authority,x=\"a b\""));
    }

    #[test]
    fn too_large_is_refused() {
        let big = vec![b'#'; MAX_FILE + 1];
        assert_eq!(
            AuthorizedKeys::parse(&big).unwrap_err(),
            EditError::TooLarge
        );
        assert!(AuthorizedKeys::parse(&big[1..]).is_ok());
    }

    #[test]
    fn to_bytes_round_trips() {
        for input in [&b""[..], b"\n", b"a\r\nb\nc", b"\r\r\n\xff\xfe\n"] {
            assert_eq!(AuthorizedKeys::parse(input).unwrap().to_bytes(), input);
        }
    }
}
