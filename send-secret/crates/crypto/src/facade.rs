//! The public encrypt and decrypt calls (SPEC section 7, plan.md).

use std::io::{self, BufReader, Read, Write};

use crate::age_backend::AgeKey;
use crate::detect::{Detected, open_message};
use crate::plan::{MessagePlan, Recipient};
use crate::self_identity::SelfIdentity;
use crate::{Error, Format, Result, age_backend};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptOpts {
    pub armor: bool,
    /// Sign OpenPGP messages. age messages are never signed (section 4).
    pub sign: bool,
}

/// One message, to `plan.keys` only. Never adds any other key (S-8).
pub fn encrypt(
    input: impl Read,
    output: impl Write,
    plan: &MessagePlan,
    opts: &EncryptOpts,
) -> Result<()> {
    let keys = checked_keys(plan)?;
    age_backend::encrypt(input, output, &keys, opts.armor)
}

/// The result of one message from [`encrypt_each`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    pub label: String,
    pub format: Format,
}

/// Runs [`encrypt`] once per plan, in order (recipients, then the self copy
/// if the caller added it). Opens the input again for every message, so no
/// plaintext is buffered (S-4). A plan is checked before its input and
/// output are opened. One result per plan; a failure does not stop the rest.
pub fn encrypt_each<R: Read, W: Write>(
    mut open_input: impl FnMut() -> io::Result<R>,
    mut open_output: impl FnMut(&MessagePlan) -> io::Result<W>,
    plans: &[MessagePlan],
    opts: &EncryptOpts,
) -> Vec<Result<Sent>> {
    plans
        .iter()
        .map(|plan| {
            let keys = checked_keys(plan)?;
            let input = open_input()?;
            let output = open_output(plan)?;
            age_backend::encrypt(input, output, &keys, opts.armor)?;
            Ok(Sent {
                label: plan.label.clone(),
                format: plan.format,
            })
        })
        .collect()
}

/// The plan's age keys, after checking every key matches the format.
/// OpenPGP is not built yet (M1 T08b).
fn checked_keys(plan: &MessagePlan) -> Result<Vec<AgeKey>> {
    if plan.keys.is_empty() {
        return Err(Error::NoKeys {
            label: plan.label.clone(),
        });
    }
    if plan.keys.iter().any(|k| k.format() != plan.format) {
        return Err(Error::WrongFormat {
            label: plan.label.clone(),
            format: plan.format,
        });
    }
    match plan.format {
        Format::OpenPgp => Err(Error::NotYet(Format::OpenPgp)),
        Format::Age => Ok(plan
            .keys
            .iter()
            .filter_map(|k| match k {
                Recipient::Age(key) => Some(key.clone()),
                Recipient::OpenPgp(_) => None,
            })
            .collect()),
    }
}

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

    use crate::plan::{OpenPgpCert, OpenPgpSelf, Person, Sender, plan, self_plan};
    use std::cell::RefCell;

    const OPTS: EncryptOpts = EncryptOpts {
        armor: false,
        sign: true,
    };

    fn ssh_person(label: &str, rel: &str) -> Person {
        let lines = identity_core::parse_public_keys(&fixture(rel)).unwrap();
        let keys = lines
            .iter()
            .filter_map(|l| age_backend::age_key(l.key.as_ref().unwrap()).ok())
            .map(Recipient::Age)
            .collect();
        Person {
            label: label.into(),
            keys,
        }
    }

    fn ssh_ctx(rel: &str) -> DecryptCtx {
        let mut ctx = DecryptCtx::new();
        ctx.add_ssh_identity(&fixture(rel), age::NoCallbacks)
            .unwrap();
        ctx
    }

    /// Runs `encrypt_each` with in-memory outputs, one per plan.
    fn run(plans: &[MessagePlan], msg: &[u8]) -> (Vec<Result<Sent>>, Vec<Vec<u8>>) {
        let outputs = RefCell::new(Vec::new());
        let results = encrypt_each(
            || Ok(msg),
            |_| {
                outputs.borrow_mut().push(Vec::new());
                Ok(Out(&outputs))
            },
            plans,
            &OPTS,
        );
        (results, outputs.into_inner())
    }

    /// Writes into the last buffer of the list.
    struct Out<'a>(&'a RefCell<Vec<Vec<u8>>>);
    impl Write for Out<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .borrow_mut()
                .last_mut()
                .unwrap()
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Stanza types of a binary age header, like `X25519`. The crate adds
    /// a random `*-grease` stanza that holds no key; it is left out.
    fn stanzas(ct: &[u8]) -> Vec<String> {
        let end = ct.windows(4).position(|w| w == b"\n---").unwrap();
        String::from_utf8_lossy(&ct[..end])
            .lines()
            .filter(|l| l.starts_with("-> "))
            .map(|l| l.split(' ').nth(1).unwrap().to_owned())
            .filter(|t| !t.ends_with("-grease"))
            .collect()
    }

    #[test]
    fn encrypt_rejects_wrong_format_keys() {
        let erin = ssh_person("erin", "ssh/erin_ed25519.pub");
        let wrong = MessagePlan {
            label: "erin".into(),
            format: Format::OpenPgp,
            keys: erin.keys.clone(),
        };
        let err = encrypt(&b"x"[..], Vec::new(), &wrong, &OPTS).unwrap_err();
        assert!(matches!(err, Error::WrongFormat { .. }), "{err:?}");
        let mixed = MessagePlan {
            label: "erin".into(),
            format: Format::Age,
            keys: vec![
                erin.keys[0].clone(),
                Recipient::OpenPgp(OpenPgpCert::new(b"k".to_vec()).unwrap()),
            ],
        };
        let err = encrypt(&b"x"[..], Vec::new(), &mixed, &OPTS).unwrap_err();
        assert!(matches!(err, Error::WrongFormat { .. }), "{err:?}");
        let empty = MessagePlan {
            keys: vec![],
            ..mixed
        };
        let err = encrypt(&b"x"[..], Vec::new(), &empty, &OPTS).unwrap_err();
        assert!(matches!(err, Error::NoKeys { .. }), "{err:?}");
    }

    #[test]
    fn encrypt_each_one_result_per_recipient() {
        let people = [
            ssh_person("erin", "ssh/erin_ed25519.pub"),
            Person {
                label: "alice".into(),
                keys: vec![Recipient::OpenPgp(OpenPgpCert::new(b"k".to_vec()).unwrap())],
            },
            ssh_person("frank", "ssh/frank_rsa.pub"),
        ];
        let plans = plan(&people, None).unwrap();
        let (results, outputs) = run(&plans, b"hello");
        assert_eq!(results.len(), 3);
        assert_eq!(
            results[0].as_ref().unwrap(),
            &Sent {
                label: "erin".into(),
                format: Format::Age
            }
        );
        // OpenPGP waits for T08b; its output is never opened.
        assert!(matches!(results[1], Err(Error::NotYet(Format::OpenPgp))));
        assert_eq!(results[2].as_ref().unwrap().label, "frank");
        assert_eq!(outputs.len(), 2);
    }

    #[test]
    fn recipient_cannot_open_others_message() {
        let people = [
            ssh_person("erin", "ssh/erin_ed25519.pub"),
            ssh_person("frank", "ssh/frank_rsa.pub"),
        ];
        let (results, outputs) = run(&plan(&people, None).unwrap(), b"hello");
        assert!(results.iter().all(Result::is_ok));
        let (erin, frank) = (ssh_ctx("ssh/erin_ed25519"), ssh_ctx("ssh/frank_rsa"));
        assert_eq!(open(&outputs[0], &erin).unwrap(), b"hello");
        assert_eq!(open(&outputs[1], &frank).unwrap(), b"hello");
        assert!(matches!(
            open(&outputs[0], &frank),
            Err(Error::NoMatchingKey)
        ));
        assert!(matches!(
            open(&outputs[1], &erin),
            Err(Error::NoMatchingKey)
        ));
        assert_eq!(stanzas(&outputs[0]), ["ssh-ed25519"]);
        assert_eq!(stanzas(&outputs[1]), ["ssh-rsa"]);
    }

    #[test]
    fn age_self_copy_and_recipient_message_keep_keys_apart() {
        let tmp = tempfile::tempdir().unwrap();
        let path = crate::self_identity_path(tmp.path());
        let me = SelfIdentity::load_or_create(&path).unwrap();
        let sender = Sender {
            openpgp: OpenPgpSelf::NoSecretKey,
            age: me.recipient(),
        };
        let mut plans = plan(&[ssh_person("erin", "ssh/erin_ed25519.pub")], None).unwrap();
        let (self_copy, note) = self_plan(&sender, None).unwrap();
        assert!(note.is_some());
        plans.push(self_copy);
        let (results, outputs) = run(&plans, b"hello");
        assert_eq!(results[1].as_ref().unwrap().label, "self");

        let mut mine = DecryptCtx::new();
        mine.add_self_identity(SelfIdentity::load(&path).unwrap().unwrap());
        // self_copy_opens_with_sender_key
        assert_eq!(open(&outputs[1], &mine).unwrap(), b"hello");
        assert_eq!(stanzas(&outputs[1]), ["X25519"]);
        assert!(matches!(
            open(&outputs[1], &ssh_ctx("ssh/erin_ed25519")),
            Err(Error::NoMatchingKey)
        ));
        // recipient_message_has_no_sender_key
        assert!(matches!(
            open(&outputs[0], &mine),
            Err(Error::NoMatchingKey)
        ));
        assert_eq!(stanzas(&outputs[0]), ["ssh-ed25519"]);
    }

    #[test]
    fn self_key_settled_before_any_output() {
        // A forced format with no self key fails in planning, before the
        // caller opens anything.
        let sender = Sender {
            openpgp: OpenPgpSelf::CannotEncrypt,
            age: age::x25519::Identity::generate().to_public(),
        };
        assert!(self_plan(&sender, Some(Format::OpenPgp)).is_err());
        // And encrypt_each never opens an output for a plan it cannot run.
        let bad = MessagePlan {
            label: "self".into(),
            format: Format::Age,
            keys: vec![],
        };
        let (results, outputs) = run(&[bad], b"hello");
        assert!(matches!(results[0], Err(Error::NoKeys { .. })));
        assert!(outputs.is_empty());
    }

    #[test]
    fn armored_output_round_trips() {
        let plans = plan(&[ssh_person("erin", "ssh/erin_ed25519.pub")], None).unwrap();
        let mut out = Vec::new();
        let opts = EncryptOpts {
            armor: true,
            sign: true,
        };
        encrypt(&b"hello"[..], &mut out, &plans[0], &opts).unwrap();
        assert!(out.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----\n"));
        assert_eq!(open(&out, &ssh_ctx("ssh/erin_ed25519")).unwrap(), b"hello");
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
