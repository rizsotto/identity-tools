//! Is a private key file encrypted? Looks at the header only (Key Steward
//! S-1): it reads the file without a buffer, a few bytes at a time, and
//! stops as soon as it knows. It never reads the private key itself.

use std::io::Read;
use std::path::Path;

use base64ct::{Base64Unpadded, Encoding};

use crate::error::KeyError;

/// Whether a private key file is protected by a passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrivateKeyProtection {
    Encrypted,
    Unencrypted,
    /// Not a format we know. Never treat this as unencrypted.
    Unknown,
}

const OPENSSH_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";
/// Base64 characters to decode from an OpenSSH key: 60 bytes. That covers
/// the magic, the cipher name (up to 29 bytes, `chacha20-poly1305@openssh.com`)
/// and the KDF name, and stays inside the public part of the file.
const OPENSSH_HEADER_B64: usize = 80;
/// Most bytes to read after the BEGIN line while collecting those base64
/// characters. Leaves room for a few line breaks (also CRLF).
const OPENSSH_HEADER_MAX_READ: usize = OPENSSH_HEADER_B64 + 16;
const PEM_BEGIN: &[&str] = &[
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
];
const PKCS8_PLAIN: &str = "-----BEGIN PRIVATE KEY-----";
const PKCS8_ENCRYPTED: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
const MAX_FIRST_LINE: usize = 64;

/// Check whether the private key at `path` is encrypted.
pub fn private_key_protection(path: &Path) -> Result<PrivateKeyProtection, KeyError> {
    // No BufReader: it would pull the whole key into memory.
    check(std::fs::File::open(path)?)
}

pub(crate) fn check(mut r: impl Read) -> Result<PrivateKeyProtection, KeyError> {
    let Some(first) = read_line(&mut r, MAX_FIRST_LINE)? else {
        return Ok(PrivateKeyProtection::Unknown);
    };
    let first = first.trim_end_matches('\r');
    Ok(match first {
        OPENSSH_BEGIN => openssh(&mut r)?,
        PKCS8_ENCRYPTED => PrivateKeyProtection::Encrypted,
        PKCS8_PLAIN => PrivateKeyProtection::Unencrypted,
        l if PEM_BEGIN.contains(&l) => pem(&mut r)?,
        _ => PrivateKeyProtection::Unknown,
    })
}

/// Read up to and including `\n`, one byte at a time. `None` if the line is
/// longer than `max` bytes or not UTF-8.
fn read_line(r: &mut impl Read, max: usize) -> Result<Option<String>, KeyError> {
    let mut line = Vec::new();
    let mut byte = [0u8];
    while line.len() <= max {
        if r.read(&mut byte)? == 0 || byte[0] == b'\n' {
            return Ok(String::from_utf8(line).ok());
        }
        line.push(byte[0]);
    }
    Ok(None)
}

/// Old PEM format: a `Proc-Type: 4,ENCRYPTED` header follows the BEGIN
/// line. `-` is not a base64 character, so five bytes tell a header from key
/// data.
fn pem(r: &mut impl Read) -> Result<PrivateKeyProtection, KeyError> {
    let mut start = [0u8; 5];
    if r.read_exact(&mut start).is_err() {
        return Ok(PrivateKeyProtection::Unknown);
    }
    if &start != b"Proc-" {
        return Ok(PrivateKeyProtection::Unencrypted);
    }
    let mut rest = [0u8; 17];
    if r.read_exact(&mut rest).is_err() {
        return Ok(PrivateKeyProtection::Unknown);
    }
    Ok(if &rest == b"Type: 4,ENCRYPTED" {
        PrivateKeyProtection::Encrypted
    } else {
        PrivateKeyProtection::Unknown
    })
}

/// OpenSSH format: `openssh-key-v1\0`, then cipher name and KDF name as SSH
/// strings. `none`/`none` is unencrypted.
fn openssh(r: &mut impl Read) -> Result<PrivateKeyProtection, KeyError> {
    let mut b64 = Vec::with_capacity(OPENSSH_HEADER_B64);
    let mut byte = [0u8];
    let mut taken = 0;
    while b64.len() < OPENSSH_HEADER_B64 {
        if taken == OPENSSH_HEADER_MAX_READ {
            return Ok(PrivateKeyProtection::Unknown);
        }
        if r.read(&mut byte)? == 0 {
            break;
        }
        taken += 1;
        match byte[0] {
            b'\n' | b'\r' => {}
            b'-' => break,
            b => b64.push(b),
        }
    }
    let Ok(bin) = Base64Unpadded::decode_vec(&String::from_utf8_lossy(&b64)) else {
        return Ok(PrivateKeyProtection::Unknown);
    };
    let Some(rest) = bin.strip_prefix(OPENSSH_MAGIC) else {
        return Ok(PrivateKeyProtection::Unknown);
    };
    let Some((cipher, rest)) = ssh_string(rest) else {
        return Ok(PrivateKeyProtection::Unknown);
    };
    let Some((kdf, _)) = ssh_string(rest) else {
        return Ok(PrivateKeyProtection::Unknown);
    };
    Ok(match (cipher, kdf) {
        (b"none", b"none") => PrivateKeyProtection::Unencrypted,
        (c, b"bcrypt") if c != b"none" => PrivateKeyProtection::Encrypted,
        _ => PrivateKeyProtection::Unknown,
    })
}

fn ssh_string(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) as usize;
    let rest = &b[4..];
    (rest.len() >= len).then(|| rest.split_at(len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Counts the bytes taken from the inner reader.
    struct Counting<R> {
        inner: R,
        taken: usize,
    }

    impl<R: Read> Read for Counting<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.taken += n;
            Ok(n)
        }
    }

    fn keygen(dir: &Path, name: &str, args: &[&str]) -> std::path::PathBuf {
        let path = dir.join(name);
        let ok = Command::new("ssh-keygen")
            .args(["-q", "-C", "test@example.org", "-f"])
            .arg(&path)
            .args(args)
            .status()
            .unwrap()
            .success();
        assert!(ok, "ssh-keygen {args:?}");
        path
    }

    #[test]
    fn stops_reading_after_the_header() {
        let dir = tempfile::tempdir().unwrap();
        // (key, most bytes the check may take)
        let cases = [
            (
                keygen(dir.path(), "openssh", &["-t", "ed25519", "-N", ""]),
                OPENSSH_BEGIN.len() + 1 + OPENSSH_HEADER_MAX_READ,
            ),
            (
                keygen(dir.path(), "pem", &["-t", "ecdsa", "-m", "PEM", "-N", ""]),
                "-----BEGIN EC PRIVATE KEY-----\n".len() + 5,
            ),
            (
                keygen(dir.path(), "pkcs8", &["-t", "rsa", "-m", "PKCS8", "-N", ""]),
                PKCS8_PLAIN.len() + 1,
            ),
        ];
        for (path, limit) in cases {
            let size = std::fs::metadata(&path).unwrap().len() as usize;
            let mut r = Counting {
                inner: std::fs::File::open(&path).unwrap(),
                taken: 0,
            };
            assert_eq!(check(&mut r).unwrap(), PrivateKeyProtection::Unencrypted);
            assert!(r.taken <= limit, "{path:?}: read {} > {limit}", r.taken);
            assert!(r.taken < size);
        }
    }
}
