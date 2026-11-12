//! Remote scripts for `authorized_keys` and how to run them (SPEC 9.1, S-6).
//!
//! The scripts are static files in `key-steward/remote-scripts/`. The
//! remote command is a fixed bootstrap that reads exactly the script from
//! stdin with `dd bs=1`, so the data after the script stays in the pipe
//! (`sh -s` loses it to read-ahead in dash and BusyBox). User data goes
//! only on stdin, never into the command.
//!
//! Script output comes from the server and is treated as hostile: capped
//! at [`MAX_FILE`] plus a short header, and the content must match the
//! checksum line.

use std::fmt;

use super::authorized_keys::MAX_FILE;

/// A static remote script.
#[derive(Debug, Clone, Copy)]
pub struct Script {
    pub name: &'static str,
    pub body: &'static str,
}

pub const READ: Script = Script {
    name: "authorized_keys_read.sh",
    body: include_str!("../../../../remote-scripts/authorized_keys_read.sh"),
};

pub const APPLY: Script = Script {
    name: "authorized_keys_apply.sh",
    body: include_str!("../../../../remote-scripts/authorized_keys_apply.sh"),
};

const READ_MARKER: &[u8] = b"key-steward-read v1";
const APPLY_MARKER: &[u8] = b"key-steward-apply v1";
/// Room for the marker and status lines on top of the file.
const MAX_HEADER: usize = 256;

impl Script {
    /// The remote command: no user data, and no `'`, `\` or `!` inside the
    /// quotes, so common login shells pass it to `sh` unchanged.
    pub fn command(&self) -> String {
        format!(
            "sh -c 'eval \"$(dd bs=1 count={} 2>/dev/null)\"'",
            self.body.len()
        )
    }
}

/// POSIX `cksum` output: CRC and byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cksum {
    pub crc: u32,
    pub size: u64,
}

impl fmt::Display for Cksum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.crc, self.size)
    }
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u32) << 24;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 0x8000_0000 != 0 {
                (c << 1) ^ 0x04c1_1db7
            } else {
                c << 1
            };
            bit += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// The checksum POSIX `cksum` prints for `data`.
pub fn cksum(data: &[u8]) -> Cksum {
    let step = |crc: u32, b: u8| (crc << 8) ^ CRC_TABLE[((crc >> 24) as u8 ^ b) as usize];
    let mut crc = data.iter().fold(0, |c, &b| step(c, b));
    let mut n = data.len() as u64;
    while n != 0 {
        crc = step(crc, n as u8);
        n >>= 8;
    }
    Cksum {
        crc: !crc,
        size: data.len() as u64,
    }
}

/// Stdin for the read script.
pub fn read_stdin() -> Vec<u8> {
    READ.body.as_bytes().to_vec()
}

/// Stdin for the apply script: the script, the header with the checksum
/// of the file as read and of the new content, then the new content.
pub fn apply_stdin(old: Cksum, new: &[u8]) -> Vec<u8> {
    let mut out = APPLY.body.as_bytes().to_vec();
    out.extend_from_slice(format!("{old} {}\n", cksum(new)).as_bytes());
    out.extend_from_slice(new);
    out
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    /// The first line is not the marker: a forced command (`command=`) or
    /// a login shell that prints text ran instead of the script.
    #[error("the server did not run the script (a forced command or shell output?)")]
    NoMarker,
    #[error("the script's answer is not understood")]
    Malformed,
    #[error("the script's answer is too large")]
    TooLarge,
    #[error("the file did not arrive whole (checksum differs)")]
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadReply {
    Present {
        content: Vec<u8>,
        sum: Cksum,
    },
    Absent,
    Symlink,
    NotFile,
    TooLarge,
    /// The script failed; the word is from a fixed list in the script.
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyReply {
    Done(Cksum),
    /// The file changed since it was read. Nothing written.
    Changed,
    Symlink,
    Absent,
    NotFile,
    /// The new content did not arrive whole. Nothing written.
    Short,
    BadInput,
    NoTemp,
    Failed(String),
}

/// Parses the read script's stdout.
pub fn parse_read(out: &[u8]) -> Result<ReadReply, ProtocolError> {
    if out.len() > MAX_FILE + MAX_HEADER {
        return Err(ProtocolError::TooLarge);
    }
    let rest = marker(out, READ_MARKER)?;
    let (status, content) = split_line(rest).ok_or(ProtocolError::Malformed)?;
    let words: Vec<&[u8]> = status.split(|&b| b == b' ').collect();
    let reply = match words.as_slice() {
        [b"ok", crc, size] => {
            let sum = parse_sum(crc, size)?;
            if sum != cksum(content) {
                return Err(ProtocolError::Mismatch);
            }
            return Ok(ReadReply::Present {
                content: content.to_vec(),
                sum,
            });
        }
        [b"absent"] => ReadReply::Absent,
        [b"symlink"] => ReadReply::Symlink,
        [b"notfile"] => ReadReply::NotFile,
        [b"toolarge"] => ReadReply::TooLarge,
        [b"error", what] => ReadReply::Failed(word(what)?),
        _ => return Err(ProtocolError::Malformed),
    };
    if content.is_empty() {
        Ok(reply)
    } else {
        Err(ProtocolError::Malformed)
    }
}

/// Parses the apply script's stdout.
pub fn parse_apply(out: &[u8]) -> Result<ApplyReply, ProtocolError> {
    if out.len() > MAX_HEADER {
        return Err(ProtocolError::TooLarge);
    }
    let rest = marker(out, APPLY_MARKER)?;
    let (status, tail) = split_line(rest).ok_or(ProtocolError::Malformed)?;
    if !tail.is_empty() {
        return Err(ProtocolError::Malformed);
    }
    let words: Vec<&[u8]> = status.split(|&b| b == b' ').collect();
    Ok(match words.as_slice() {
        [b"done", crc, size] => ApplyReply::Done(parse_sum(crc, size)?),
        [b"changed"] => ApplyReply::Changed,
        [b"symlink"] => ApplyReply::Symlink,
        [b"absent"] => ApplyReply::Absent,
        [b"notfile"] => ApplyReply::NotFile,
        [b"short"] => ApplyReply::Short,
        [b"badinput"] => ApplyReply::BadInput,
        [b"notmp"] => ApplyReply::NoTemp,
        [b"error", what] => ApplyReply::Failed(word(what)?),
        _ => return Err(ProtocolError::Malformed),
    })
}

fn marker<'a>(out: &'a [u8], marker: &[u8]) -> Result<&'a [u8], ProtocolError> {
    match split_line(out) {
        Some((first, rest)) if first == marker => Ok(rest),
        _ => Err(ProtocolError::NoMarker),
    }
}

/// The first line without its `\n`, and the rest.
fn split_line(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let i = b.iter().position(|&c| c == b'\n')?;
    Some((&b[..i], &b[i + 1..]))
}

fn parse_sum(crc: &[u8], size: &[u8]) -> Result<Cksum, ProtocolError> {
    let num = |b: &[u8]| {
        std::str::from_utf8(b)
            .ok()
            .filter(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok())
    };
    let crc = num(crc)
        .and_then(|c| u32::try_from(c).ok())
        .ok_or(ProtocolError::Malformed)?;
    let size = num(size).ok_or(ProtocolError::Malformed)?;
    Ok(Cksum { crc, size })
}

/// A short lower case word from the script, or `Malformed`.
fn word(b: &[u8]) -> Result<String, ProtocolError> {
    if !b.is_empty() && b.len() <= 16 && b.iter().all(u8::is_ascii_lowercase) {
        Ok(String::from_utf8_lossy(b).into_owned())
    } else {
        Err(ProtocolError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cksum_known_values() {
        // From GNU coreutils `cksum`.
        assert_eq!(cksum(b"").to_string(), "4294967295 0");
        assert_eq!(cksum(b"a").to_string(), "1220704766 1");
        assert_eq!(cksum(b"123456789").to_string(), "930766865 9");
    }

    #[test]
    fn read_reply_needs_marker_and_matching_sum() {
        let body = b"k1\r\nk2";
        let ok = [
            &b"key-steward-read v1\nok "[..],
            cksum(body).to_string().as_bytes(),
            b"\n",
            body,
        ]
        .concat();
        assert_eq!(
            parse_read(&ok).unwrap(),
            ReadReply::Present {
                content: body.to_vec(),
                sum: cksum(body)
            }
        );
        let cut = &ok[..ok.len() - 1];
        assert_eq!(parse_read(cut), Err(ProtocolError::Mismatch));
        assert_eq!(parse_read(b"hi\n"), Err(ProtocolError::NoMarker));
        assert_eq!(
            parse_read(b"motd\nkey-steward-read v1\nabsent\n"),
            Err(ProtocolError::NoMarker)
        );
        assert_eq!(
            parse_read(b"key-steward-read v1\nabsent\n").unwrap(),
            ReadReply::Absent
        );
        assert_eq!(
            parse_read(b"key-steward-read v1\nabsent\nmore"),
            Err(ProtocolError::Malformed)
        );
        assert_eq!(
            parse_read(b"key-steward-read v1\nerror Bad!\n"),
            Err(ProtocolError::Malformed)
        );
        let big = vec![b'x'; MAX_FILE + MAX_HEADER + 1];
        assert_eq!(parse_read(&big), Err(ProtocolError::TooLarge));
    }

    #[test]
    fn apply_reply_words() {
        assert_eq!(
            parse_apply(b"key-steward-apply v1\ndone 1 2\n").unwrap(),
            ApplyReply::Done(Cksum { crc: 1, size: 2 })
        );
        assert_eq!(
            parse_apply(b"key-steward-apply v1\nchanged\n").unwrap(),
            ApplyReply::Changed
        );
        for bad in [
            &b"key-steward-apply v1\ndone 1\n"[..],
            b"key-steward-apply v1\ndone 99999999999 2\n",
            b"key-steward-apply v1\ndone -1 2\n",
            b"key-steward-apply v1\nchanged",
            b"key-steward-apply v1\nchanged\nx",
        ] {
            assert_eq!(parse_apply(bad), Err(ProtocolError::Malformed));
        }
    }
}
