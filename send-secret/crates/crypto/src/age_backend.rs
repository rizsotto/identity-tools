//! age backend: x25519 and SSH (Ed25519, RSA 2048 to 4096 bits) recipients,
//! armored and binary, streaming. Only calls the `age` crate (section 14).

use std::fmt;
use std::io::{self, BufRead, Read, Write};
use std::str::FromStr;

use age::armor::{ArmoredReader, ArmoredWriter, Format as ArmorFormat};
use identity_core::{Fingerprint, KeyAlgo, PublicKey};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Size of our plaintext copy buffer. Same as the age chunk size.
const COPY_BUF: usize = 64 * 1024;

const AGE_END_MARKER: &[u8] = b"-----END AGE ENCRYPTED FILE-----";

/// An age recipient: a native X25519 key or an SSH key.
#[derive(Clone)]
pub enum AgeKey {
    X25519(age::x25519::Recipient),
    Ssh(age::ssh::Recipient),
}

// Used by the encrypt facade (M1 T09).
#[allow(dead_code)]
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
#[allow(dead_code)]
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
/// backticks) is ignored.
///
/// Plaintext is written as it is authenticated, chunk by chunk. On an error
/// the caller must throw away what was written.
pub(crate) fn decrypt(
    input: impl BufRead,
    output: impl Write,
    armored: bool,
    identities: &[Box<dyn age::Identity>],
) -> Result<()> {
    if armored {
        decrypt_stream(
            ArmoredReader::new(UntilArmorEnd::new(input)),
            output,
            identities,
        )
    } else {
        decrypt_stream(input, output, identities)
    }
}

fn decrypt_stream(
    input: impl Read,
    mut output: impl Write,
    identities: &[Box<dyn age::Identity>],
) -> Result<()> {
    let decryptor = age::Decryptor::new(input).map_err(map_decrypt_error)?;
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

/// Passes bytes through up to and including the age END line, then reports
/// end of input. The `age` crate rejects anything but whitespace after the
/// END line, and pasted text often has closing backticks there.
struct UntilArmorEnd<R> {
    inner: R,
    /// The current line, cut off once it is too long to be the END line.
    line: Vec<u8>,
    done: bool,
}

impl<R> UntilArmorEnd<R> {
    fn new(inner: R) -> Self {
        UntilArmorEnd {
            inner,
            line: Vec::with_capacity(AGE_END_MARKER.len() + 2),
            done: false,
        }
    }
}

fn is_end_line(line: &[u8]) -> bool {
    line.strip_suffix(b"\r").unwrap_or(line) == AGE_END_MARKER
}

impl<R: BufRead> Read for UntilArmorEnd<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.done || out.is_empty() {
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
        UntilArmorEnd::new(&input[..])
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, &input[..input.len() - 4]);
    }

    #[test]
    fn until_armor_end_handles_long_lines_and_tiny_reads() {
        let mut input = vec![b'x'; 10_000];
        input.extend(b"\n-----END AGE ENCRYPTED FILE-----\r\nmore");
        let mut reader = UntilArmorEnd::new(&input[..]);
        let mut out = Vec::new();
        let mut byte = [0u8; 1];
        while reader.read(&mut byte).unwrap() == 1 {
            out.push(byte[0]);
        }
        assert_eq!(out, &input[..input.len() - 4]);
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
