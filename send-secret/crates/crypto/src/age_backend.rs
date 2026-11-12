//! age backend: x25519 and SSH (Ed25519, RSA 2048 to 4096 bits) recipients,
//! armored and binary, streaming. Only calls the `age` crate (section 14).

use std::cell::Cell;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::rc::Rc;
use std::str::FromStr;

use age::armor::{ArmoredReader, ArmoredWriter, Format as ArmorFormat};
use identity_core::{Fingerprint, KeyAlgo, PublicKey};
use zeroize::Zeroizing;

use crate::detect::{DETECT_LEN, Detected, detect_format};
use crate::{Error, Result};

/// Size of our plaintext copy buffer. Same as the age chunk size.
const COPY_BUF: usize = 64 * 1024;

const AGE_END_MARKER: &[u8] = b"-----END AGE ENCRYPTED FILE-----";

/// Largest age header we read. The `age` crate parses the header again
/// after every read, so a huge hostile header takes minutes (SPEC 15
/// item 1). A real header with eight SSH RSA keys is about 5 KiB.
const MAX_HEADER: usize = 16 * 1024;

/// How an age header ends: the MAC line starts with `---`.
const HEADER_END: &[u8] = b"\n---";

/// An age recipient: a native X25519 key or an SSH key.
#[derive(Clone)]
pub enum AgeKey {
    X25519(age::x25519::Recipient),
    Ssh(age::ssh::Recipient),
}

impl AgeKey {
    fn as_recipient(&self) -> &dyn age::Recipient {
        match self {
            AgeKey::X25519(r) => r,
            AgeKey::Ssh(r) => r,
        }
    }
}

impl fmt::Debug for AgeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgeKey::X25519(r) => write!(f, "X25519({r})"),
            AgeKey::Ssh(r) => write!(f, "Ssh({r})"),
        }
    }
}

/// A key that the age format can not encrypt to, and why. Shown as a note;
/// the other keys of that person are still used (FR-4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub fingerprint: Fingerprint,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
    /// ECDSA, `sk-` and other SSH key types age does not support.
    UnsupportedType(KeyAlgo),
    /// SSH RSA under 2048 bits.
    RsaTooSmall(u32),
    /// SSH RSA over 4096 bits (the `age` crate limit, SPEC 15 item 1).
    RsaTooLarge(u32),
    /// Not an age or SSH key (for example OpenPGP).
    NotAgeKey,
    /// The `age` crate could not read the key.
    Invalid,
}

impl fmt::Display for Skipped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "skipped key {}: {}", self.fingerprint, self.reason)
    }
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SkipReason::UnsupportedType(algo) => {
                write!(f, "{} keys are not age recipients", algo_name(algo))
            }
            SkipReason::RsaTooSmall(bits) => {
                write!(f, "RSA {bits} is too small for age (minimum 2048 bits)")
            }
            SkipReason::RsaTooLarge(bits) => {
                write!(f, "RSA {bits} is too large for age (maximum 4096 bits)")
            }
            SkipReason::NotAgeKey => f.write_str("not an age or SSH key"),
            SkipReason::Invalid => f.write_str("age can not read this key"),
        }
    }
}

fn algo_name(algo: &KeyAlgo) -> String {
    match algo {
        KeyAlgo::Ed25519 => "Ed25519".into(),
        KeyAlgo::Ecdsa(curve) => format!("ECDSA {curve}"),
        KeyAlgo::Rsa(bits) => format!("RSA {bits}"),
        KeyAlgo::Dsa(bits) => format!("DSA {bits}"),
        KeyAlgo::SkEd25519 => "sk-ssh-ed25519".into(),
        KeyAlgo::SkEcdsa(curve) => format!("sk-ecdsa {curve}"),
        KeyAlgo::Cv25519 => "Cv25519".into(),
        KeyAlgo::X25519 => "X25519".into(),
        KeyAlgo::Other(name) => name.clone(),
    }
}

/// Turns a parsed public key into an age recipient. The `age` crate has the
/// last word, so an SSH RSA key outside 2048 to 4096 bits is skipped here
/// even if the key type looks fine.
pub fn age_key(key: &PublicKey) -> Result<AgeKey, Skipped> {
    let skip = |reason| Skipped {
        fingerprint: key.fingerprint(),
        reason,
    };
    match key {
        PublicKey::Age(r) => age::x25519::Recipient::from_str(r.as_str())
            .map(AgeKey::X25519)
            .map_err(|_| skip(SkipReason::Invalid)),
        PublicKey::Ssh(k) => {
            use age::ssh::ParseRecipientKeyError as E;
            age::ssh::Recipient::from_str(&k.encoded)
                .map(AgeKey::Ssh)
                .map_err(|e| {
                    let bits = match k.algo {
                        KeyAlgo::Rsa(bits) => bits,
                        _ => 0,
                    };
                    skip(match e {
                        E::Unsupported(_) => SkipReason::UnsupportedType(k.algo.clone()),
                        E::RsaModulusTooSmall => SkipReason::RsaTooSmall(bits),
                        E::RsaModulusTooLarge => SkipReason::RsaTooLarge(bits),
                        _ => SkipReason::Invalid,
                    })
                })
        }
        PublicKey::OpenPgp(_) => Err(skip(SkipReason::NotAgeKey)),
    }
}

/// Encrypts `input` to all `keys` in one age message (one person's devices,
/// FR-4) and writes it to `output`. Streams; the plaintext buffer is zeroed.
pub(crate) fn encrypt(
    mut input: impl Read,
    output: impl Write,
    keys: &[AgeKey],
    armor: bool,
) -> Result<()> {
    let encryptor = age::Encryptor::with_recipients(keys.iter().map(AgeKey::as_recipient))
        .map_err(|e| Error::Age(e.to_string()))?;
    let format = if armor {
        ArmorFormat::AsciiArmor
    } else {
        ArmorFormat::Binary
    };
    let armored = ArmoredWriter::wrap_output(output, format)?;
    let mut writer = encryptor.wrap_output(armored)?;
    copy_plaintext(&mut input, &mut writer).map_err(|e| Error::Io(e.into_inner()))?;
    let mut output = writer.finish()?.finish()?;
    output.flush()?;
    Ok(())
}

/// Decrypts an age message that starts at the first byte of `input`.
/// For armor, reading stops after the END line, so trailing text (closing
/// backticks) is ignored. Returns true if another message follows the END
/// line; it is not decrypted.
///
/// Plaintext is written as it is authenticated, chunk by chunk. On an error
/// the caller must throw away what was written.
pub(crate) fn decrypt(
    input: impl BufRead,
    output: impl Write,
    armored: bool,
    identities: &[Box<dyn age::Identity>],
) -> Result<bool> {
    if armored {
        let more = Rc::new(Cell::new(false));
        let until_end = UntilArmorEnd::new(input, Rc::clone(&more));
        decrypt_stream(ArmoredReader::new(until_end), output, identities)?;
        Ok(more.get())
    } else {
        decrypt_stream(input, output, identities)?;
        Ok(false)
    }
}

fn decrypt_stream(
    input: impl Read,
    mut output: impl Write,
    identities: &[Box<dyn age::Identity>],
) -> Result<()> {
    let input = BufReader::new(HeaderCap::new(input));
    let decryptor = age::Decryptor::new_buffered(input).map_err(map_decrypt_error)?;
    let mut reader = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref()))
        .map_err(map_decrypt_error)?;
    copy_plaintext(&mut reader, &mut output).map_err(|e| match e {
        CopyError::Read(e) if is_corrupt(&e) => Error::Corrupt,
        e => Error::Io(e.into_inner()),
    })?;
    output.flush()?;
    Ok(())
}

fn map_decrypt_error(e: age::DecryptError) -> Error {
    use age::DecryptError as D;
    match e {
        D::NoMatchingKeys => Error::NoMatchingKey,
        D::KeyDecryptionFailed => Error::KeyLocked,
        D::DecryptionFailed | D::InvalidHeader | D::InvalidMac | D::UnknownFormat => Error::Corrupt,
        D::Io(e) if is_corrupt(&e) => Error::Corrupt,
        D::Io(e) => Error::Io(e),
        e => Error::Age(e.to_string()),
    }
}

fn is_corrupt(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
    )
}

enum CopyError {
    Read(io::Error),
    Write(io::Error),
}

impl CopyError {
    fn into_inner(self) -> io::Error {
        match self {
            CopyError::Read(e) | CopyError::Write(e) => e,
        }
    }
}

/// Like `io::copy`, but the buffer is zeroed when done (S-5).
fn copy_plaintext(
    input: &mut impl Read,
    output: &mut impl Write,
) -> std::result::Result<(), CopyError> {
    let mut buf = Zeroizing::new(vec![0u8; COPY_BUF]);
    loop {
        let n = match input.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CopyError::Read(e)),
        };
        output.write_all(&buf[..n]).map_err(CopyError::Write)?;
    }
}

/// Fails with `InvalidData` if the age header does not end within
/// [`MAX_HEADER`] bytes. After the header, bytes pass through unchanged.
struct HeaderCap<R> {
    inner: R,
    seen: usize,
    /// How many bytes of [`HEADER_END`] the last bytes matched.
    matched: usize,
    header_done: bool,
}

impl<R> HeaderCap<R> {
    fn new(inner: R) -> Self {
        HeaderCap {
            inner,
            seen: 0,
            matched: 0,
            header_done: false,
        }
    }
}

impl<R: Read> Read for HeaderCap<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.header_done {
            return self.inner.read(out);
        }
        let room = MAX_HEADER - self.seen;
        if room == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "age header is too large",
            ));
        }
        let take = out.len().min(room);
        let n = self.inner.read(&mut out[..take])?;
        self.seen += n;
        for &b in &out[..n] {
            self.matched = if b == HEADER_END[self.matched] {
                self.matched + 1
            } else if b == HEADER_END[0] {
                1
            } else {
                0
            };
            if self.matched == HEADER_END.len() {
                self.header_done = true;
                break;
            }
        }
        Ok(n)
    }
}

/// Passes bytes through up to and including the age END line, then reports
/// end of input. The `age` crate rejects anything but whitespace after the
/// END line, and pasted text often has closing backticks there. Sets `more`
/// if another message starts after the END line.
struct UntilArmorEnd<R> {
    inner: R,
    /// The current line, cut off once it is too long to be the END line.
    line: Vec<u8>,
    done: bool,
    checked_rest: bool,
    more: Rc<Cell<bool>>,
}

impl<R> UntilArmorEnd<R> {
    fn new(inner: R, more: Rc<Cell<bool>>) -> Self {
        UntilArmorEnd {
            inner,
            line: Vec::with_capacity(AGE_END_MARKER.len() + 2),
            done: false,
            checked_rest: false,
            more,
        }
    }
}

impl<R: BufRead> UntilArmorEnd<R> {
    /// Looks at the text after the END line, once, for another message.
    fn check_rest(&mut self) -> io::Result<()> {
        if self.checked_rest {
            return Ok(());
        }
        self.checked_rest = true;
        let mut rest = Vec::with_capacity(DETECT_LEN);
        (&mut self.inner)
            .take(DETECT_LEN as u64)
            .read_to_end(&mut rest)?;
        self.more
            .set(detect_format(&rest).format != Detected::Unknown);
        Ok(())
    }
}

fn is_end_line(line: &[u8]) -> bool {
    line.strip_suffix(b"\r").unwrap_or(line) == AGE_END_MARKER
}

impl<R: BufRead> Read for UntilArmorEnd<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.done {
            self.check_rest()?;
            return Ok(0);
        }
        if out.is_empty() {
            return Ok(0);
        }
        let buf = self.inner.fill_buf()?;
        if buf.is_empty() {
            return Ok(0);
        }
        let mut n = 0;
        while n < buf.len() && n < out.len() {
            let b = buf[n];
            n += 1;
            if b == b'\n' {
                if is_end_line(&self.line) {
                    self.done = true;
                    break;
                }
                self.line.clear();
            } else if self.line.len() < AGE_END_MARKER.len() + 2 {
                self.line.push(b);
            }
        }
        out[..n].copy_from_slice(&buf[..n]);
        self.inner.consume(n);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture(rel: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(rel);
        std::fs::read(&path).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    fn public_key(rel: &str) -> PublicKey {
        let mut lines = identity_core::parse_public_keys(&fixture(rel)).unwrap();
        assert_eq!(lines.len(), 1, "{rel}");
        lines.remove(0).key.unwrap()
    }

    fn key(rel: &str) -> AgeKey {
        age_key(&public_key(rel)).unwrap()
    }

    fn x25519_identity(rel: &str) -> Box<dyn age::Identity> {
        let text = String::from_utf8(fixture(rel)).unwrap();
        let line = text
            .lines()
            .find(|l| l.starts_with("AGE-SECRET-KEY-"))
            .unwrap();
        Box::new(age::x25519::Identity::from_str(line).unwrap())
    }

    fn ssh_identity(rel: &str) -> Box<dyn age::Identity> {
        let id = age::ssh::Identity::from_buffer(&fixture(rel)[..], None).unwrap();
        Box::new(id)
    }

    fn encrypt_to(keys: &[AgeKey], armor: bool, msg: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encrypt(msg, &mut out, keys, armor).unwrap();
        out
    }

    fn decrypt_with(ct: &[u8], armored: bool, ids: &[Box<dyn age::Identity>]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        decrypt(ct, &mut out, armored, ids)?;
        Ok(out)
    }

    const MSG: &[u8] = b"a secret for one person";

    #[test]
    fn round_trip_x25519_ed25519_rsa() {
        for (public, secret, x25519) in [
            ("age/dave.pub", "age/dave.txt", true),
            ("ssh/erin_ed25519.pub", "ssh/erin_ed25519", false),
            ("ssh/frank_rsa.pub", "ssh/frank_rsa", false),
        ] {
            let id = if x25519 {
                x25519_identity(secret)
            } else {
                ssh_identity(secret)
            };
            for armor in [true, false] {
                let ct = encrypt_to(&[key(public)], armor, MSG);
                assert_eq!(ct.starts_with(b"-----BEGIN AGE"), armor, "{public}");
                assert_eq!(
                    decrypt_with(&ct, armor, std::slice::from_ref(&id)).unwrap(),
                    MSG,
                    "{public} armor={armor}"
                );
            }
        }
    }

    #[test]
    fn two_keys_in_one_message_each_decrypt_alone() {
        let ct = encrypt_to(
            &[key("ssh/erin_ed25519.pub"), key("ssh/frank_rsa.pub")],
            true,
            MSG,
        );
        for secret in ["ssh/erin_ed25519", "ssh/frank_rsa"] {
            let out = decrypt_with(&ct, true, &[ssh_identity(secret)]).unwrap();
            assert_eq!(out, MSG, "{secret}");
        }
        let err = decrypt_with(&ct, true, &[x25519_identity("age/dave.txt")]).unwrap_err();
        assert!(matches!(err, Error::NoMatchingKey), "{err:?}");
    }

    #[test]
    fn multi_keys_file_uses_supported_keys_and_skips_the_rest() {
        let lines = identity_core::parse_public_keys(&fixture("ssh/multi.keys")).unwrap();
        let (keys, skipped): (Vec<_>, Vec<_>) = lines
            .iter()
            .map(|l| age_key(l.key.as_ref().unwrap()))
            .partition(|r| r.is_ok());
        assert_eq!(keys.len(), 2);
        let reasons: Vec<_> = skipped.into_iter().map(|s| s.unwrap_err().reason).collect();
        assert_eq!(
            reasons,
            vec![
                SkipReason::UnsupportedType(KeyAlgo::Ecdsa("nistp256".into())),
                SkipReason::UnsupportedType(KeyAlgo::SkEd25519),
                SkipReason::RsaTooLarge(8192),
                SkipReason::RsaTooSmall(1024),
            ]
        );
    }

    #[test]
    fn ssh_rsa_outside_2048_4096_skipped_with_note() {
        let small = age_key(&public_key("ssh/kim_rsa1024.pub")).unwrap_err();
        assert_eq!(small.reason, SkipReason::RsaTooSmall(1024));
        assert!(
            small.to_string().contains("RSA 1024 is too small"),
            "{small}"
        );
        assert!(small.to_string().contains("SHA256:"), "{small}");
        let large = age_key(&public_key("ssh/ivan_rsa8192.pub")).unwrap_err();
        assert_eq!(large.reason, SkipReason::RsaTooLarge(8192));
        assert!(
            large.to_string().contains("RSA 8192 is too large"),
            "{large}"
        );
    }

    #[test]
    fn ecdsa_and_sk_keys_skipped_with_note() {
        let ecdsa = age_key(&public_key("ssh/heidi_ecdsa.pub")).unwrap_err();
        assert_eq!(
            ecdsa.to_string(),
            format!(
                "skipped key {}: ECDSA nistp256 keys are not age recipients",
                ecdsa.fingerprint
            )
        );
        let sk = age_key(&public_key("ssh/judy_sk.pub")).unwrap_err();
        assert_eq!(sk.reason, SkipReason::UnsupportedType(KeyAlgo::SkEd25519));
    }

    #[test]
    fn no_keys_is_an_error() {
        let err = encrypt(MSG, Vec::new(), &[], false).unwrap_err();
        assert!(matches!(err, Error::Age(_)), "{err:?}");
    }

    #[test]
    fn decrypts_go_age_fixtures() {
        let id = x25519_identity("age/dave.txt");
        let want = b"Send Secret fixture message";
        for (rel, armored) in [
            ("ciphertext/age-armored.age", true),
            ("ciphertext/age-binary.age", false),
        ] {
            let out = decrypt_with(&fixture(rel), armored, std::slice::from_ref(&id)).unwrap();
            assert_eq!(out, want, "{rel}");
        }
    }

    #[test]
    fn trailing_text_after_end_line_is_ignored() {
        let id = x25519_identity("age/dave.txt");
        let mut ct = encrypt_to(&[key("age/dave.pub")], true, MSG);
        ct.extend(b"```\nsent with Send Secret\n");
        let out = decrypt_with(&ct, true, std::slice::from_ref(&id)).unwrap();
        assert_eq!(out, MSG);
    }

    #[test]
    fn crlf_armor_with_trailing_text() {
        let id = x25519_identity("age/dave.txt");
        let ct = encrypt_to(&[key("age/dave.pub")], true, MSG);
        let mut crlf: Vec<u8> = String::from_utf8(ct)
            .unwrap()
            .replace('\n', "\r\n")
            .into_bytes();
        crlf.extend(b"```\r\n");
        let out = decrypt_with(&crlf, true, std::slice::from_ref(&id)).unwrap();
        assert_eq!(out, MSG);
    }

    #[test]
    fn until_armor_end_cuts_after_end_line_only() {
        let input =
            b"a\n-----END AGE ENCRYPTED FILE----- \nb\n-----END AGE ENCRYPTED FILE-----\nrest";
        let mut out = Vec::new();
        UntilArmorEnd::new(&input[..], Rc::default())
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, &input[..input.len() - 4]);
    }

    #[test]
    fn until_armor_end_handles_long_lines_and_tiny_reads() {
        let mut input = vec![b'x'; 10_000];
        input.extend(b"\n-----END AGE ENCRYPTED FILE-----\r\nmore");
        let mut reader = UntilArmorEnd::new(&input[..], Rc::default());
        let mut out = Vec::new();
        let mut byte = [0u8; 1];
        while reader.read(&mut byte).unwrap() == 1 {
            out.push(byte[0]);
        }
        assert_eq!(out, &input[..input.len() - 4]);
    }

    #[test]
    fn huge_header_is_refused_fast() {
        let id = x25519_identity("age/dave.txt");
        let stanza = format!("-> X25519 {}\n{}\n", "A".repeat(43), "A".repeat(43));
        let mut ct = b"age-encryption.org/v1\n".to_vec();
        while ct.len() < 1024 * 1024 {
            ct.extend(stanza.as_bytes());
        }
        ct.extend(b"--- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
        let start = std::time::Instant::now();
        let err = decrypt_with(&ct, false, std::slice::from_ref(&id)).unwrap_err();
        assert!(matches!(err, Error::Corrupt), "{err:?}");
        assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
    }

    #[test]
    fn header_cap_lets_a_normal_header_through() {
        let keys: Vec<_> = (0..8).map(|_| key("ssh/frank_rsa.pub")).collect();
        let ct = encrypt_to(&keys, false, MSG);
        assert!(ct.len() > 4 * 1024, "{}", ct.len());
        let out = decrypt_with(&ct, false, &[ssh_identity("ssh/frank_rsa")]).unwrap();
        assert_eq!(out, MSG);
    }

    #[test]
    fn header_cap_counts_only_the_header() {
        let mut header = b"age-encryption.org/v1\n".to_vec();
        header.resize(MAX_HEADER - 10, b'a');
        header.extend(b"\n--- mac\n");
        let mut input = header.clone();
        input.extend(vec![b'z'; 3 * MAX_HEADER]);
        let mut out = Vec::new();
        HeaderCap::new(&input[..]).read_to_end(&mut out).unwrap();
        assert_eq!(out, input);
        let mut out = Vec::new();
        let err = HeaderCap::new(&vec![b'a'; MAX_HEADER + 1][..])
            .read_to_end(&mut out)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn second_pasted_message_is_reported() {
        let id = x25519_identity("age/dave.txt");
        let first = encrypt_to(&[key("age/dave.pub")], true, MSG);
        let second = encrypt_to(&[key("age/dave.pub")], true, b"other");
        let mut input = first.clone();
        input.extend(b"\n```\n\n```\n");
        input.extend(&second);
        let mut out = Vec::new();
        let more = decrypt(&input[..], &mut out, true, std::slice::from_ref(&id)).unwrap();
        assert_eq!((out.as_slice(), more), (MSG, true));
        let mut alone = first;
        alone.extend(b"```\nthanks\n");
        let mut out = Vec::new();
        let more = decrypt(&alone[..], &mut out, true, &[id]).unwrap();
        assert_eq!((out.as_slice(), more), (MSG, false));
    }

    #[test]
    fn age_key_agrees_with_is_age_recipient_for_all_fixtures() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        let mut checked = 0;
        for sub in ["age", "ssh"] {
            for entry in std::fs::read_dir(dir.join(sub)).unwrap() {
                let path = entry.unwrap().path();
                let Ok(lines) = identity_core::parse_public_keys(&std::fs::read(&path).unwrap())
                else {
                    continue; // private keys
                };
                for line in lines {
                    let k = line.key.unwrap();
                    assert_eq!(age_key(&k).is_ok(), k.is_age_recipient(), "{path:?}");
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 14);
    }

    #[test]
    fn tampered_message_is_corrupt() {
        let id = x25519_identity("age/dave.txt");
        let mut ct = encrypt_to(&[key("age/dave.pub")], false, MSG);
        let last = ct.len() - 1;
        ct[last] ^= 1;
        let err = decrypt_with(&ct, false, std::slice::from_ref(&id)).unwrap_err();
        assert!(matches!(err, Error::Corrupt), "{err:?}");
        let err = decrypt_with(b"age-encryption.org/v1\n-> junk\n", false, &[id]).unwrap_err();
        assert!(matches!(err, Error::Corrupt), "{err:?}");
    }

    fn tool(cmd: &mut std::process::Command, input: &[u8]) -> Vec<u8> {
        use std::process::Stdio;
        let mut child = cmd
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run age (it must be installed)");
        child.stdin.take().unwrap().write_all(input).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    fn private_copy(dir: &Path, rel: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(Path::new(rel).file_name().unwrap());
        std::fs::write(&path, fixture(rel)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    const PAIRS: [(&str, &str); 3] = [
        ("age/dave.pub", "age/dave.txt"),
        ("ssh/erin_ed25519.pub", "ssh/erin_ed25519"),
        ("ssh/frank_rsa.pub", "ssh/frank_rsa"),
    ];

    #[test]
    fn go_age_decrypts_our_output() {
        let tmp = tempfile::tempdir().unwrap();
        for (public, secret) in PAIRS {
            let id = private_copy(tmp.path(), secret);
            for armor in [true, false] {
                let ct = encrypt_to(&[key(public)], armor, MSG);
                let out = tool(
                    std::process::Command::new("age")
                        .arg("-d")
                        .arg("-i")
                        .arg(&id),
                    &ct,
                );
                assert_eq!(out, MSG, "{public} armor={armor}");
            }
        }
    }

    #[test]
    fn we_decrypt_go_age_output() {
        let tmp = tempfile::tempdir().unwrap();
        for (public, secret) in PAIRS {
            let pubfile = tmp.path().join("recipient");
            std::fs::write(&pubfile, fixture(public)).unwrap();
            let id = if secret.starts_with("age/") {
                x25519_identity(secret)
            } else {
                ssh_identity(secret)
            };
            for armor in [true, false] {
                let mut cmd = std::process::Command::new("age");
                cmd.arg("-e").arg("-R").arg(&pubfile);
                if armor {
                    cmd.arg("-a");
                }
                let ct = tool(&mut cmd, MSG);
                let out = decrypt_with(&ct, armor, std::slice::from_ref(&id)).unwrap();
                assert_eq!(out, MSG, "{public} armor={armor}");
            }
        }
    }

    #[test]
    fn large_input_streams() {
        let msg = vec![7u8; 3 * COPY_BUF + 123];
        let id = ssh_identity("ssh/erin_ed25519");
        let ct = encrypt_to(&[key("ssh/erin_ed25519.pub")], false, &msg);
        assert_eq!(decrypt_with(&ct, false, &[id]).unwrap(), msg);
    }
}
