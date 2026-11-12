//! The public encrypt and decrypt calls (SPEC section 7, plan.md).

use std::io::{BufReader, Read, Write};

use crate::detect::{Detected, open_message};
use crate::self_identity::SelfIdentity;
use crate::{Error, Format, Result, age_backend};

/// The private keys decrypt may try.
#[derive(Default)]
pub struct DecryptCtx {
    age: Vec<Box<dyn age::Identity>>,
}

impl DecryptCtx {
    pub fn new() -> Self {
        Self::default()
    }

    /// The sender's own identity, to open self copies.
    pub fn add_self_identity(&mut self, identity: SelfIdentity) {
        self.age.push(identity.into_identity());
    }

    /// An age identity file (`age-keygen` output). The caller reads the
    /// file and should zero `bytes` after this call.
    pub fn add_age_identity_file(&mut self, bytes: &[u8]) -> Result<()> {
        let file = age::IdentityFile::from_buffer(bytes)
            .map_err(|_| Error::Identity("not an age identity file"))?;
        let identities = file
            .into_identities()
            .map_err(|_| Error::Identity("unusable age identity file"))?;
        if identities.is_empty() {
            return Err(Error::Identity("no identity in the age identity file"));
        }
        for identity in identities {
            self.age.push(identity);
        }
        Ok(())
    }

    /// An OpenSSH private key (Ed25519 or RSA). For a protected key,
    /// `callbacks` asks for the passphrase when a message needs this key.
    pub fn add_ssh_identity<C: age::Callbacks>(
        &mut self,
        bytes: &[u8],
        callbacks: C,
    ) -> Result<()> {
        let identity = age::ssh::Identity::from_buffer(bytes, None)
            .map_err(|_| Error::Identity("not an SSH private key"))?;
        if let age::ssh::Identity::Unsupported(_) = identity {
            return Err(Error::Identity(
                "this SSH key type can not decrypt age messages",
            ));
        }
        self.age.push(Box::new(identity.with_callbacks(callbacks)));
        Ok(())
    }
}

/// What decrypt found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Decrypted {
    pub format: Format,
}

/// Decrypts one message. Text before the armor (BOM, backticks, a header
/// line) and after an age END line is ignored (FR-7).
///
/// Plaintext is written as it is authenticated. On an error the caller must
/// throw away what was written to `output`.
pub fn decrypt(input: impl Read, output: impl Write, ctx: &DecryptCtx) -> Result<Decrypted> {
    let (detection, reader) = open_message(input)?;
    let armored = match detection.format {
        Detected::AgeArmor => true,
        Detected::AgeBinary => false,
        Detected::OpenPgpArmor | Detected::OpenPgpBinary => {
            return Err(Error::NotYet(Format::OpenPgp));
        }
        Detected::Unknown => return Err(Error::UnknownFormat),
    };
    age_backend::decrypt(BufReader::new(reader), output, armored, &ctx.age)?;
    Ok(Decrypted {
        format: Format::Age,
    })
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

    fn dave() -> DecryptCtx {
        let mut ctx = DecryptCtx::new();
        ctx.add_age_identity_file(&fixture("age/dave.txt")).unwrap();
        ctx
    }

    const WANT: &[u8] = b"Send Secret fixture message";

    fn open(input: &[u8], ctx: &DecryptCtx) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let found = decrypt(input, &mut out, ctx)?;
        assert_eq!(found.format, Format::Age);
        Ok(out)
    }

    #[test]
    fn decrypt_armor_in_backticks_with_bom() {
        let mut input = b"\xef\xbb\xbf```\n".to_vec();
        input.extend(fixture("ciphertext/age-armored.age"));
        input.extend(b"```\n");
        assert_eq!(open(&input, &dave()).unwrap(), WANT);
    }

    #[test]
    fn decrypt_after_header_line_and_blank_lines() {
        let mut input = b"Encrypted for Dave with age.\n\n".to_vec();
        input.extend(fixture("ciphertext/age-armored.age"));
        input.extend(b"\nthanks\n");
        assert_eq!(open(&input, &dave()).unwrap(), WANT);
    }

    #[test]
    fn decrypt_binary_fixture() {
        assert_eq!(
            open(&fixture("ciphertext/age-binary.age"), &dave()).unwrap(),
            WANT
        );
    }

    #[test]
    fn decrypt_with_ssh_identity_files() {
        let mut ctx = DecryptCtx::new();
        ctx.add_ssh_identity(&fixture("ssh/erin_ed25519"), age::NoCallbacks)
            .unwrap();
        let mut keys = identity_core::parse_public_keys(&fixture("ssh/erin_ed25519.pub")).unwrap();
        let key = age_backend::age_key(keys.remove(0).key.as_ref().unwrap()).unwrap();
        let mut ct = Vec::new();
        age_backend::encrypt(&b"hi"[..], &mut ct, &[key], true).unwrap();
        assert_eq!(open(&ct, &ctx).unwrap(), b"hi");
    }

    #[test]
    fn protected_ssh_key_without_passphrase_cannot_decrypt() {
        let mut ctx = DecryptCtx::new();
        ctx.add_ssh_identity(&fixture("ssh/grace_ed25519_pw"), age::NoCallbacks)
            .unwrap();
        let mut keys =
            identity_core::parse_public_keys(&fixture("ssh/grace_ed25519_pw.pub")).unwrap();
        let key = age_backend::age_key(keys.remove(0).key.as_ref().unwrap()).unwrap();
        let mut ct = Vec::new();
        age_backend::encrypt(&b"hi"[..], &mut ct, &[key], false).unwrap();
        let err = open(&ct, &ctx).unwrap_err();
        assert!(matches!(err, Error::NoMatchingKey), "{err:?}");
    }

    #[test]
    fn protected_ssh_key_with_passphrase_decrypts() {
        #[derive(Clone)]
        struct Pass;
        impl age::Callbacks for Pass {
            fn display_message(&self, _: &str) {}
            fn confirm(&self, _: &str, _: &str, _: Option<&str>) -> Option<bool> {
                None
            }
            fn request_public_string(&self, _: &str) -> Option<String> {
                None
            }
            fn request_passphrase(&self, _: &str) -> Option<age::secrecy::SecretString> {
                Some("fixture-passphrase".to_owned().into())
            }
        }
        let mut ctx = DecryptCtx::new();
        ctx.add_ssh_identity(&fixture("ssh/grace_ed25519_pw"), Pass)
            .unwrap();
        let mut keys =
            identity_core::parse_public_keys(&fixture("ssh/grace_ed25519_pw.pub")).unwrap();
        let key = age_backend::age_key(keys.remove(0).key.as_ref().unwrap()).unwrap();
        let mut ct = Vec::new();
        age_backend::encrypt(&b"hi"[..], &mut ct, &[key], false).unwrap();
        assert_eq!(open(&ct, &ctx).unwrap(), b"hi");
    }

    #[test]
    fn ecdsa_identity_is_refused() {
        let err = DecryptCtx::new()
            .add_ssh_identity(&fixture("ssh/heidi_ecdsa"), age::NoCallbacks)
            .unwrap_err();
        assert!(matches!(err, Error::Identity(_)), "{err:?}");
    }

    #[test]
    fn openpgp_is_not_yet_and_junk_is_unknown() {
        let err = open(&fixture("ciphertext/openpgp-armored.asc"), &dave()).unwrap_err();
        assert!(matches!(err, Error::NotYet(Format::OpenPgp)), "{err:?}");
        let err = open(b"hello", &dave()).unwrap_err();
        assert!(matches!(err, Error::UnknownFormat), "{err:?}");
    }

    #[test]
    fn wrong_identity_is_no_matching_key() {
        let mut ctx = DecryptCtx::new();
        ctx.add_ssh_identity(&fixture("ssh/frank_rsa"), age::NoCallbacks)
            .unwrap();
        let err = open(&fixture("ciphertext/age-armored.age"), &ctx).unwrap_err();
        assert!(matches!(err, Error::NoMatchingKey), "{err:?}");
    }
}
