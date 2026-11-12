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
/// plaintext is buffered (S-4).
///
/// Every plan is checked first. If one fails, the error is returned and no
/// input or output is opened. Otherwise there is one result per plan; a
/// failure does not stop the rest.
pub fn encrypt_each<R: Read, W: Write>(
    mut open_input: impl FnMut() -> io::Result<R>,
    mut open_output: impl FnMut(&MessagePlan) -> io::Result<W>,
    plans: &[MessagePlan],
    opts: &EncryptOpts,
) -> Result<Vec<Result<Sent>>> {
    let checked = plans
        .iter()
        .map(|plan| Ok((plan, checked_keys(plan)?)))
        .collect::<Result<Vec<_>>>()?;
    Ok(checked
        .into_iter()
        .map(|(plan, keys)| {
            let input = open_input()?;
            let output = open_output(plan)?;
            age_backend::encrypt(input, output, &keys, opts.armor)?;
            Ok(Sent {
                label: plan.label.clone(),
                format: plan.format,
            })
        })
        .collect())
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
    /// Another message follows the decrypted one (two pasted together).
    /// Only the first was decrypted; the caller says so (not an error).
    pub more_messages: bool,
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
    let more_messages = age_backend::decrypt(BufReader::new(reader), output, armored, &ctx.age)?;
    Ok(Decrypted {
        format: Format::Age,
        more_messages,
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
    use std::collections::HashSet;

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
    fn run(plans: &[MessagePlan], msg: &[u8]) -> (Result<Vec<Result<Sent>>>, Vec<Vec<u8>>) {
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

    /// Stanzas of a binary age header as (type, args). The crate adds a
    /// random `*-grease` stanza that holds no key; it is left out.
    fn stanzas(ct: &[u8]) -> Vec<(String, Vec<String>)> {
        let end = ct.windows(4).position(|w| w == b"\n---").unwrap();
        String::from_utf8_lossy(&ct[..end])
            .lines()
            .filter_map(|l| l.strip_prefix("-> "))
            .map(|l| {
                let mut parts = l.split(' ').map(str::to_owned);
                (parts.next().unwrap(), parts.collect())
            })
            .filter(|(t, _)| !t.ends_with("-grease"))
            .collect()
    }

    fn types(ct: &[u8]) -> Vec<String> {
        stanzas(ct).into_iter().map(|(t, _)| t).collect()
    }

    /// The age SSH key tag: the first 4 bytes of SHA-256 of the wire key,
    /// base64 without padding (age spec, ssh-ed25519 and ssh-rsa stanzas).
    fn ssh_tag(encoded: &str) -> String {
        use base64::Engine;
        use sha2::Digest;
        let b64 = encoded.split(' ').nth(1).unwrap();
        let wire = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(&sha2::Sha256::digest(&wire)[..4])
    }

    /// SSH tags and the number of X25519 keys in some fixture key files.
    fn expected_keys(files: &[&str]) -> (HashSet<String>, usize) {
        let mut tags = HashSet::new();
        let mut x25519 = 0;
        for rel in files {
            for line in identity_core::parse_public_keys(&fixture(rel)).unwrap() {
                let key = line.key.unwrap();
                if age_backend::age_key(&key).is_err() {
                    continue;
                }
                match key {
                    identity_core::PublicKey::Ssh(k) => {
                        tags.insert(ssh_tag(&k.encoded));
                    }
                    _ => x25519 += 1,
                }
            }
        }
        (tags, x25519)
    }

    const PEOPLE: [(&str, &[&str]); 3] = [
        ("erin", &["ssh/erin_ed25519.pub"]),
        ("multi", &["ssh/multi.keys"]),
        (
            "combo",
            &[
                "ssh/grace_ed25519_pw.pub",
                "age/dave.pub",
                "ssh/frank_rsa.pub",
            ],
        ),
    ];

    /// Encrypts to PEOPLE plus an age self copy. Returns the self identity
    /// dir (keep it alive) and the outputs, self copy last.
    fn send_with_self_copy() -> (tempfile::TempDir, Vec<Vec<u8>>) {
        let tmp = tempfile::tempdir().unwrap();
        let me = SelfIdentity::load_or_create(&crate::self_identity_path(tmp.path())).unwrap();
        let sender = Sender {
            openpgp: OpenPgpSelf::NoSecretKey,
            age: me.recipient(),
        };
        let people: Vec<_> = PEOPLE
            .iter()
            .map(|(label, files)| {
                let mut person = ssh_person(label, files[0]);
                for rel in &files[1..] {
                    person.keys.extend(ssh_person(label, rel).keys);
                }
                person
            })
            .collect();
        let mut plans = plan(&people, None).unwrap();
        plans.push(self_plan(&sender, None).unwrap().0);
        let (results, outputs) = run(&plans, b"hello");
        let results = results.unwrap();
        assert_eq!(results.len(), 4);
        assert_eq!(results[3].as_ref().unwrap().label, "self");
        (tmp, outputs)
    }

    fn my_ctx(dir: &tempfile::TempDir) -> DecryptCtx {
        let mut ctx = DecryptCtx::new();
        let path = crate::self_identity_path(dir.path());
        ctx.add_self_identity(SelfIdentity::load(&path).unwrap().unwrap());
        ctx
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
            ssh_person("dave", "age/dave.pub"),
            ssh_person("frank", "ssh/frank_rsa.pub"),
        ];
        let plans = plan(&people, None).unwrap();
        let (results, outputs) = run(&plans, b"hello");
        let labels: Vec<_> = results
            .unwrap()
            .into_iter()
            .map(|r| r.unwrap())
            .map(|s| (s.label, s.format))
            .collect();
        assert_eq!(
            labels,
            [
                ("erin".to_owned(), Format::Age),
                ("dave".to_owned(), Format::Age),
                ("frank".to_owned(), Format::Age)
            ]
        );
        assert_eq!(outputs.len(), 3);
    }

    #[test]
    fn encrypt_each_checks_all_plans_before_writing() {
        let opened = RefCell::new(0);
        let people = [
            ssh_person("erin", "ssh/erin_ed25519.pub"),
            Person {
                label: "alice".into(),
                keys: vec![Recipient::OpenPgp(OpenPgpCert::new(b"k".to_vec()).unwrap())],
            },
        ];
        let mut plans = plan(&people, None).unwrap();
        let bad_self = MessagePlan {
            label: "self".into(),
            format: Format::Age,
            keys: vec![],
        };
        for (plans, want_not_yet) in [
            (plans.clone(), true),
            (
                {
                    plans.truncate(1);
                    plans.push(bad_self);
                    plans
                },
                false,
            ),
        ] {
            let err = encrypt_each(
                || {
                    *opened.borrow_mut() += 1;
                    Ok(&b"hello"[..])
                },
                |_| -> io::Result<Vec<u8>> {
                    *opened.borrow_mut() += 1;
                    Ok(Vec::new())
                },
                &plans,
                &OPTS,
            )
            .unwrap_err();
            // OpenPGP waits for T08b.
            assert_eq!(
                matches!(err, Error::NotYet(Format::OpenPgp)),
                want_not_yet,
                "{err:?}"
            );
            assert_eq!(
                matches!(err, Error::NoKeys { .. }),
                !want_not_yet,
                "{err:?}"
            );
        }
        assert_eq!(*opened.borrow(), 0, "nothing may be opened");
    }

    #[test]
    fn recipient_cannot_open_others_message() {
        let people = [
            ssh_person("erin", "ssh/erin_ed25519.pub"),
            ssh_person("frank", "ssh/frank_rsa.pub"),
        ];
        let (results, outputs) = run(&plan(&people, None).unwrap(), b"hello");
        assert!(results.unwrap().iter().all(Result::is_ok));
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
        assert_eq!(types(&outputs[0]), ["ssh-ed25519"]);
        assert_eq!(types(&outputs[1]), ["ssh-rsa"]);
    }

    #[test]
    fn self_copy_opens_with_sender_key() {
        let (dir, outputs) = send_with_self_copy();
        let self_copy = &outputs[3];
        assert_eq!(open(self_copy, &my_ctx(&dir)).unwrap(), b"hello");
        assert_eq!(types(self_copy), ["X25519"], "only the sender's X25519 key");
        for secret in ["ssh/erin_ed25519", "ssh/frank_rsa"] {
            assert!(matches!(
                open(self_copy, &ssh_ctx(secret)),
                Err(Error::NoMatchingKey)
            ));
        }
        assert!(matches!(
            open(self_copy, &dave()),
            Err(Error::NoMatchingKey)
        ));
    }

    #[test]
    fn recipient_message_has_no_sender_key() {
        let (dir, outputs) = send_with_self_copy();
        let mine = my_ctx(&dir);
        for ((label, files), ct) in PEOPLE.iter().zip(&outputs) {
            assert!(
                matches!(open(ct, &mine), Err(Error::NoMatchingKey)),
                "{label}: opens with the sender's identity"
            );
            let (want_tags, want_x25519) = expected_keys(files);
            let found = stanzas(ct);
            let tags: HashSet<String> = found
                .iter()
                .filter(|(t, _)| t.starts_with("ssh-"))
                .map(|(_, args)| args[0].clone())
                .collect();
            assert_eq!(tags, want_tags, "{label}: SSH tags");
            let x25519 = found.iter().filter(|(t, _)| t == "X25519").count();
            assert_eq!(x25519, want_x25519, "{label}: X25519 stanzas");
            assert_eq!(
                found.len(),
                want_tags.len() + want_x25519,
                "{label}: {found:?}"
            );
        }
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
