//! `authorized_keys` parser and editor, pure (FR-6, SPEC 9.1).
//!
//! The file comes from a server, so it is treated as hostile: at most
//! [`MAX_FILE`] bytes, and a line we do not understand is kept as it is.
//! Every line keeps its raw bytes and its line ending (LF, CRLF, or none
//! for a last line without newline). An edit only adds or drops whole
//! lines; all other bytes stay the same.
//!
//! # How sshd reads a line (OpenSSH portable 10.2p1, same on master)
//!
//! A line must be read as sshd reads it, or a line sshd accepts as the
//! old key could stay behind after `remove`.
//!
//! 1. `auth_check_authkeys_file` (auth2-pubkeyfile.c): `getline`, then the
//!    line is a C string, so it ends at the first NUL byte. `skip_space`
//!    (misc.c) skips spaces and tabs only. Empty lines, a lone `\n` and
//!    lines starting with `#` are skipped.
//! 2. `auth_check_authkey_line` (auth2-pubkeyfile.c): first `sshkey_read`
//!    on the whole line. If that fails, the options run to the end of
//!    `sshkey_advance_past_options` (authfile.c): up to the first space or
//!    tab outside double quotes, `\"` skipped as a pair, an unclosed quote
//!    is an error. Then spaces and tabs, then `sshkey_read` again.
//! 3. `sshkey_read` (sshkey.c): the type is the bytes up to the first
//!    space or tab and must be followed by one; it must equal a key type
//!    name exactly (`peek_type_nid`). Spaces and tabs, then the base64
//!    field up to the next space or tab. Everything after is the comment.
//! 4. The base64 field goes to `b64_pton` (openbsd-compat/base64.c) via
//!    `sshbuf_b64tod` (sshbuf-misc.c), which skips every C `isspace` byte
//!    anywhere (`\r`, `\v`, `\f`; space, tab and `\n` cannot be inside).
//!    Padding must be right and unused bits zero. `sshkey_fromb` refuses
//!    extra bytes after the key.
//! 5. `sshauthopt_parse` (auth-options.c) and `opt_flag` (misc.c): options
//!    match case-insensitively. A line with bad options is ignored by
//!    sshd; this module still treats it as a key line (removing it is
//!    harmless; a `keep` line like that is caught by the removal login).
//! 6. A plain key never matches a `cert-authority` line, but a user
//!    certificate signed by that key does. Such lines are kept and listed
//!    by [`AuthorizedKeys::remove`].
//!
//! Here: line endings (`\n`, and a `\r` before it) are split off and
//! kept, each line is cut at its first NUL before parsing, fields split on
//! spaces and tabs only, and `\r`, `\v`, `\f` are dropped from the base64
//! field before it is decoded.

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
    #[error("a line the editor does not understand holds the old key; edit the file by hand")]
    OldKeyInUnknownLine,
}

/// The result of [`AuthorizedKeys::remove`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed {
    /// The new file.
    pub bytes: Vec<u8>,
    /// Line numbers (from 1) of `cert-authority` lines that hold the old
    /// key. They are kept, but the old private key can still sign a user
    /// certificate that logs in here: tell the user.
    pub ca_lines_with_old_key: Vec<usize>,
}

/// One login key line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLine {
    /// Line number, from 1.
    pub line: usize,
    /// The options exactly as written, if any (raw bytes).
    pub options: Option<Vec<u8>>,
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
        let mut present: Vec<Option<Vec<u8>>> = self
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
                out.extend_from_slice(o);
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

    /// Drops every login key line with `old`. Refuses if no login key line
    /// (any options, CA lines not counted) has `keep`; whether that line
    /// really lets the new key log in is not checked here. Refuses if a
    /// line it does not understand still holds `old`, since sshd might
    /// accept that line. If `old` is not there, the file stays as it is.
    /// CA lines with `old` are kept and listed in the result.
    pub fn remove(&self, old: &Fingerprint, keep: &Fingerprint) -> Result<Removed, EditError> {
        if old == keep {
            return Err(EditError::SameKey);
        }
        if !self.lines.iter().any(|l| matches(l, keep)) {
            return Err(EditError::NewKeyMissing);
        }
        if self
            .lines
            .iter()
            .any(|l| l.key.is_none() && mentions(&l.text, old))
        {
            return Err(EditError::OldKeyInUnknownLine);
        }
        let mut out = Vec::new();
        for l in self.lines.iter().filter(|l| !matches(l, old)) {
            out.extend_from_slice(&l.text);
            out.extend_from_slice(l.ending);
        }
        let ca_lines_with_old_key = self
            .keys()
            .filter(|k| k.cert_authority && &k.key.fingerprint == old)
            .map(|k| k.line)
            .collect();
        Ok(Removed {
            bytes: cap(out)?,
            ca_lines_with_old_key,
        })
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
/// Works on bytes: only the key type and the base64 field must be ASCII;
/// options and comment may hold any bytes.
fn parse_key_line(text: &[u8], line: usize) -> Option<KeyLine> {
    let text = until_nul(text);
    if text.starts_with("\u{feff}".as_bytes()) {
        return None;
    }
    let text = trim_ws(text);
    if text.is_empty() || text[0] == b'#' {
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
    let key = parse_key(trim_ws(rest))?;
    Some(KeyLine {
        line,
        cert_authority: split_options(options)
            .iter()
            .any(|o| option_name(o).eq_ignore_ascii_case(b"cert-authority")),
        options: Some(options.to_vec()),
        key,
    })
}

/// `<type> <base64> [comment]`, fields split by spaces or tabs as sshd
/// does. The comment is kept as text with bad UTF-8 replaced.
fn parse_key(text: &[u8]) -> Option<SshPublicKey> {
    let (key_type, rest) = split_field(text);
    let (blob, comment) = split_field(rest);
    let key_type = std::str::from_utf8(key_type).ok()?;
    let blob: Vec<u8> = blob
        .iter()
        .copied()
        .filter(|b| !matches!(b, b'\r' | b'\n' | 0x0b | 0x0c))
        .collect();
    let blob = std::str::from_utf8(&blob).ok()?;
    if key_type.is_empty() || blob.is_empty() || !key_type.is_ascii() || !blob.is_ascii() {
        return None;
    }
    let mut key = match parse_public_keys(format!("{key_type} {blob}").as_bytes())
        .ok()?
        .as_slice()
    {
        [one] => match &one.key {
            Ok(PublicKey::Ssh(k)) => k.clone(),
            _ => return None,
        },
        _ => return None,
    };
    let comment = String::from_utf8_lossy(comment);
    key.comment = Some(comment.trim_end().to_string()).filter(|c| !c.is_empty());
    Some(key)
}

/// Whether a line that is neither a comment nor a parsed key holds a key
/// with this fingerprint anywhere, as two neighbouring fields.
fn mentions(text: &[u8], fpr: &Fingerprint) -> bool {
    let text = trim_ws(until_nul(text));
    if text.is_empty() || text[0] == b'#' {
        return false;
    }
    let fields: Vec<&[u8]> = text
        .split(|&b| b == b' ' || b == b'\t')
        .filter(|f| !f.is_empty())
        .collect();
    // The type may be glued to options or a BOM, so look at field ends.
    fields.windows(2).any(|w| {
        KEY_TYPES.iter().any(|t| {
            w[0].ends_with(t.as_bytes())
                && parse_key(&[t.as_bytes(), b" ", w[1]].concat())
                    .is_some_and(|k| &k.fingerprint == fpr)
        })
    })
}

/// Key types `identity_core` parses.
const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// The line as sshd sees it: a C string ends at the first NUL.
fn until_nul(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

fn trim_ws(b: &[u8]) -> &[u8] {
    let i = b
        .iter()
        .position(|&c| c != b' ' && c != b'\t')
        .unwrap_or(b.len());
    &b[i..]
}

/// The first field, and the rest without its leading spaces and tabs.
fn split_field(b: &[u8]) -> (&[u8], &[u8]) {
    match b.iter().position(|&c| c == b' ' || c == b'\t') {
        Some(i) => (&b[..i], trim_ws(&b[i..])),
        None => (b, &[]),
    }
}

/// Byte index where the options end (first space or tab outside quotes).
/// `None` for an unclosed quote or a line with nothing after the options.
fn options_end(b: &[u8]) -> Option<usize> {
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
fn split_options(b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if b.get(i + 1) == Some(&b'"') => i += 1,
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                out.push(&b[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(&b[start..]);
    out
}

fn option_name(option: &[u8]) -> &[u8] {
    option.split(|&b| b == b'=').next().unwrap_or(option)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOP3xJfcaGYrwTcdoje/Ka7JhNrATYv7RJIjLUBvVJAq";

    #[test]
    fn options_end_at_unquoted_space() {
        assert_eq!(options_end(br#"a="x y",b z"#), Some(9));
        assert_eq!(options_end(br#"a="x \" y" z"#), Some(10));
        assert_eq!(options_end(br#"a="x y"#), None);
        assert_eq!(options_end(b"restrict"), None);
    }

    #[test]
    fn split_options_keeps_quoted_commas() {
        assert_eq!(
            split_options(br#"from="a,b",cert-authority,x="\",""#),
            vec![&br#"from="a,b""#[..], b"cert-authority", br#"x="\",""#]
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
        assert_eq!(k.options.as_deref(), Some(&b"Cert-Authority,x=\"a b\""[..]));
    }

    #[test]
    fn sshd_variants_of_a_key_are_seen() {
        let (t, b) = KEY.split_once(' ').unwrap();
        let fpr = parse_key(KEY.as_bytes()).unwrap().fingerprint;
        let (b1, b2) = b.split_at(10);
        let variants: Vec<Vec<u8>> = vec![
            format!("{t} {b1}\r{b2}").into_bytes(),
            format!("{t} {b1}\x0b{b2}").into_bytes(),
            format!("{t} {b1}\x0c{b2} c").into_bytes(),
            format!("restrict {t} {b1}\x0b{b2}").into_bytes(),
            format!("{KEY}\0junk").into_bytes(),
            format!("{KEY}\0").into_bytes(),
        ];
        for v in &variants {
            let k = parse_key_line(v, 1).unwrap_or_else(|| panic!("{v:?}"));
            assert_eq!(k.key.fingerprint, fpr, "{v:?}");
            // The guard sees the same key inside a line it cannot parse.
            let unknown = [&b"command=\"unclosed "[..], v].concat();
            assert!(parse_key_line(&unknown, 1).is_none(), "{unknown:?}");
            assert!(mentions(&unknown, &fpr), "{unknown:?}");
        }
        // sshd stops at NUL, so a key after it is not there.
        let hidden = format!("\0{KEY}").into_bytes();
        assert!(parse_key_line(&hidden, 1).is_none());
        assert!(!mentions(&hidden, &fpr));
        // A space inside the base64 field ends it, as in sshd.
        assert!(parse_key_line(format!("{t} {b1} {b2}").as_bytes(), 1).is_none());
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
