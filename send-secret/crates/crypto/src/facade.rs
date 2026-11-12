//! The public encrypt and decrypt calls (SPEC section 7, plan.md).

use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use crate::age_backend::AgeKey;
use crate::detect::{Detected, open_message};
use crate::openpgp_backend::{self, Signer};
use crate::plan::{MessagePlan, OpenPgpCert, Recipient};
use crate::self_identity::SelfIdentity;
use crate::{Error, Format, Result, age_backend};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EncryptOpts {
    pub armor: bool,
    /// Sign OpenPGP messages with `signer`. age messages are never signed
    /// (section 4).
    pub sign: bool,
    /// GnuPG home for OpenPGP messages. `None` is gpg's own default
    /// (`GNUPGHOME` or `~/.gnupg`). Tests always set it.
    pub gnupg_home: Option<PathBuf>,
    /// Fingerprint of the signing key: [`crate::OpenPgpUser::signer`], the
    /// same key that is added for read-back (FR-12). Needed if `sign` is on and a message is
    /// OpenPGP; gpg's own default choice is never used.
    pub signer: Option<String>,
}

/// One message, to `plan.keys` and `plan.sender` only. Never adds any
/// other key (S-8).
pub fn encrypt(
    input: impl Read + Send,
    output: impl Write + Send,
    plan: &MessagePlan,
    opts: &EncryptOpts,
) -> Result<()> {
    prepare(plan, opts)?.encrypt(input, output)
}

/// The result of one message from [`encrypt_each`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    pub label: String,
    pub format: Format,
}

/// Runs [`encrypt`] once per plan, in order. Opens the input again for every message, so no
/// plaintext is buffered (S-4).
///
/// Every plan is checked first (keys, OpenPGP key files, signer). If one
/// fails, the error is returned and no input or output is opened.
/// Otherwise there is one result per plan; a failure does not stop the
/// rest.
pub fn encrypt_each<R: Read + Send, W: Write + Send>(
    mut open_input: impl FnMut() -> io::Result<R>,
    mut open_output: impl FnMut(&MessagePlan) -> io::Result<W>,
    plans: &[MessagePlan],
    opts: &EncryptOpts,
) -> Result<Vec<Result<Sent>>> {
    let prepared = plans
        .iter()
        .map(|plan| Ok((plan, prepare(plan, opts)?)))
        .collect::<Result<Vec<_>>>()?;
    Ok(prepared
        .into_iter()
        .map(|(plan, prepared)| {
            let input = open_input()?;
            let output = open_output(plan)?;
            prepared.encrypt(input, output)?;
            Ok(Sent {
                label: plan.label.clone(),
                format: plan.format,
            })
        })
        .collect())
}

/// A checked message, ready to write.
enum Prepared {
    Age(Vec<AgeKey>, bool),
    OpenPgp(Box<openpgp_backend::Prepared>),
}

impl Prepared {
    fn encrypt(self, input: impl Read + Send, output: impl Write + Send) -> Result<()> {
        match self {
            Prepared::Age(keys, armor) => age_backend::encrypt(input, output, &keys, armor),
            Prepared::OpenPgp(p) => p.encrypt(input, output),
        }
    }
}

/// Checks every key matches the format and can be used, before any output
/// is opened.
fn prepare(plan: &MessagePlan, opts: &EncryptOpts) -> Result<Prepared> {
    if plan.keys.is_empty() {
        return Err(Error::NoKeys {
            label: plan.label.clone(),
        });
    }
    let keys = || plan.keys.iter().chain(&plan.sender);
    if keys().any(|k| k.format() != plan.format) {
        return Err(Error::WrongFormat {
            label: plan.label.clone(),
            format: plan.format,
        });
    }
    match plan.format {
        Format::OpenPgp => {
            let certs: Vec<&OpenPgpCert> = keys()
                .filter_map(|k| match k {
                    Recipient::OpenPgp(cert) => Some(cert),
                    Recipient::Age(_) => None,
                })
                .collect();
            let signer = match (opts.sign, &opts.signer) {
                (false, _) => None,
                (true, Some(fpr)) => Some(fpr.as_str()),
                (true, None) => return Err(Error::NoSigner),
            };
            openpgp_backend::prepare(
                &plan.label,
                &certs,
                opts.gnupg_home.as_deref(),
                signer,
                opts.armor,
            )
            .map(|p| Prepared::OpenPgp(Box::new(p)))
        }
        Format::Age => Ok(Prepared::Age(
            keys()
                .filter_map(|k| match k {
                    Recipient::Age(key) => Some(key.clone()),
                    Recipient::OpenPgp(_) => None,
                })
                .collect(),
            opts.armor,
        )),
    }
}

/// The private keys decrypt may try.
#[derive(Default)]
pub struct DecryptCtx {
    age: Vec<Box<dyn age::Identity>>,
    gnupg_home: Option<PathBuf>,
}

impl DecryptCtx {
    pub fn new() -> Self {
        Self::default()
    }

    /// The GnuPG home for OpenPGP messages. Unset: gpg's own default
    /// (`GNUPGHOME` or `~/.gnupg`). Tests always set it.
    pub fn set_gnupg_home(&mut self, home: &Path) {
        self.gnupg_home = Some(home.to_path_buf());
    }

    /// The sender's own age identity, to read back sent messages.
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
    /// The first signer of an OpenPGP message. `None` if unsigned, and
    /// always for age.
    pub signer: Option<Signer>,
}

/// Decrypts one message. Text before the armor (BOM, backticks, a header
/// line) and after the END line is ignored (FR-7). OpenPGP signatures are
/// checked; a bad one is an error.
///
/// Plaintext is written before the whole message is checked (age: per
/// chunk; gpg: the integrity tag comes last). On an error the caller must
/// throw away what was written to `output`.
pub fn decrypt(
    input: impl Read + Send,
    output: impl Write + Send,
    ctx: &DecryptCtx,
) -> Result<Decrypted> {
    let (detection, reader) = open_message(input)?;
    let reader = BufReader::new(reader);
    let (format, armored) = match detection.format {
        Detected::AgeArmor => (Format::Age, true),
        Detected::AgeBinary => (Format::Age, false),
        Detected::OpenPgpArmor => (Format::OpenPgp, true),
        Detected::OpenPgpBinary => (Format::OpenPgp, false),
        Detected::Unknown => return Err(Error::UnknownFormat),
    };
    let (signer, more_messages) = match format {
        Format::Age => (
            None,
            age_backend::decrypt(reader, output, armored, &ctx.age)?,
        ),
        Format::OpenPgp => {
            openpgp_backend::decrypt(reader, output, armored, ctx.gnupg_home.as_deref())?
        }
    };
    Ok(Decrypted {
        format,
        more_messages,
        signer,
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
    fn junk_is_unknown() {
        let err = open(b"hello", &dave()).unwrap_err();
        assert!(matches!(err, Error::UnknownFormat), "{err:?}");
    }

    use crate::plan::{OpenPgpCert, OpenPgpSelf, Person, Sender, add_sender, plan};
    use std::collections::HashSet;
    use std::sync::Mutex;

    const OPTS: EncryptOpts = EncryptOpts {
        armor: false,
        sign: true,
        gnupg_home: None,
        signer: None,
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
        let outputs = Mutex::new(Vec::new());
        let results = encrypt_each(
            || Ok(msg),
            |_| {
                outputs.lock().unwrap().push(Vec::new());
                Ok(Out(&outputs))
            },
            plans,
            &OPTS,
        );
        (results, outputs.into_inner().unwrap())
    }

    /// Writes into the last buffer of the list.
    struct Out<'a>(&'a Mutex<Vec<Vec<u8>>>);
    impl Write for Out<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap()
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

    /// Encrypts to PEOPLE, with the sender's age identity added if
    /// `with_sender`. Returns the identity dir (keep it alive) and one
    /// output per person.
    fn send_to_people(with_sender: bool) -> (tempfile::TempDir, Vec<Vec<u8>>) {
        let tmp = tempfile::tempdir().unwrap();
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
        let me = my_sender(&tmp);
        if with_sender {
            add_sender(&mut plans, &me);
        }
        let (results, outputs) = run(&plans, b"hello");
        let results = results.unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(Result::is_ok));
        (tmp, outputs)
    }

    /// The sender with only an age identity, made in `dir`.
    fn my_sender(dir: &tempfile::TempDir) -> Sender {
        let me = SelfIdentity::load_or_create(&crate::self_identity_path(dir.path())).unwrap();
        Sender {
            openpgp: OpenPgpSelf::NoSecretKey,
            age: Some(me.recipient()),
        }
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
            sender: None,
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
            sender: None,
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
        let opened = std::cell::Cell::new(0);
        let people = [
            ssh_person("erin", "ssh/erin_ed25519.pub"),
            Person {
                label: "alice".into(),
                keys: vec![Recipient::OpenPgp(OpenPgpCert::new(b"k".to_vec()).unwrap())],
            },
        ];
        let mut plans = plan(&people, None).unwrap();
        let bad = MessagePlan {
            label: "dave".into(),
            format: Format::Age,
            keys: vec![],
            sender: None,
        };
        for (plans, want_no_signer) in [
            (plans.clone(), true),
            (
                {
                    plans.truncate(1);
                    plans.push(bad);
                    plans
                },
                false,
            ),
        ] {
            let err = encrypt_each(
                || {
                    opened.set(opened.get() + 1);
                    Ok(&b"hello"[..])
                },
                |_| -> io::Result<Vec<u8>> {
                    opened.set(opened.get() + 1);
                    Ok(Vec::new())
                },
                &plans,
                &OPTS,
            )
            .unwrap_err();
            // Signing is on and no signer is set.
            assert_eq!(matches!(err, Error::NoSigner), want_no_signer, "{err:?}");
            assert_eq!(
                matches!(err, Error::NoKeys { .. }),
                !want_no_signer,
                "{err:?}"
            );
        }
        assert_eq!(opened.get(), 0, "nothing may be opened");
    }

    #[test]
    fn recipient_cannot_open_others_message() {
        // With the sender's key added: still none of the other recipient's.
        let people = [
            ssh_person("erin", "ssh/erin_ed25519.pub"),
            ssh_person("frank", "ssh/frank_rsa.pub"),
        ];
        let dir = tempfile::tempdir().unwrap();
        let mut plans = plan(&people, None).unwrap();
        add_sender(&mut plans, &my_sender(&dir));
        let (results, outputs) = run(&plans, b"hello");
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
        assert_eq!(types(&outputs[0]), ["ssh-ed25519", "X25519"]);
        assert_eq!(types(&outputs[1]), ["ssh-rsa", "X25519"]);
        let mine = my_ctx(&dir);
        assert_eq!(open(&outputs[0], &mine).unwrap(), b"hello");
        assert_eq!(open(&outputs[1], &mine).unwrap(), b"hello");
    }

    /// Checks each output holds exactly its person's stanzas, plus one
    /// X25519 stanza if `extra_x25519`.
    fn assert_people_stanzas(outputs: &[Vec<u8>], extra_x25519: bool) {
        for ((label, files), ct) in PEOPLE.iter().zip(outputs) {
            let (want_tags, want_x25519) = expected_keys(files);
            let want_x25519 = want_x25519 + usize::from(extra_x25519);
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
    fn recipient_message_opens_with_sender_identity() {
        let (dir, outputs) = send_to_people(true);
        let mine = my_ctx(&dir);
        for ((label, _), ct) in PEOPLE.iter().zip(&outputs) {
            assert_eq!(open(ct, &mine).unwrap(), b"hello", "{label}");
        }
        // erin and multi have no X25519 key of their own: their one X25519
        // stanza is the sender's.
        assert_people_stanzas(&outputs, true);
        for (ct, secret) in outputs.iter().zip(["ssh/erin_ed25519", "ssh/frank_rsa"]) {
            assert_eq!(open(ct, &ssh_ctx(secret)).unwrap(), b"hello");
        }
        assert_eq!(open(&outputs[2], &dave()).unwrap(), b"hello");
    }

    #[test]
    fn without_sender_message_has_only_recipient_keys() {
        let (dir, outputs) = send_to_people(false);
        let mine = my_ctx(&dir);
        for ((label, _), ct) in PEOPLE.iter().zip(&outputs) {
            assert!(
                matches!(open(ct, &mine), Err(Error::NoMatchingKey)),
                "{label}: opens with the sender's identity"
            );
        }
        assert_people_stanzas(&outputs, false);
    }

    #[test]
    fn sender_key_of_wrong_format_is_refused() {
        let erin = ssh_person("erin", "ssh/erin_ed25519.pub");
        let wrong = MessagePlan {
            label: "erin".into(),
            format: Format::Age,
            keys: erin.keys,
            sender: Some(Recipient::OpenPgp(OpenPgpCert::new(b"k".to_vec()).unwrap())),
        };
        let err = encrypt(&b"x"[..], Vec::new(), &wrong, &OPTS).unwrap_err();
        assert!(matches!(err, Error::WrongFormat { .. }), "{err:?}");
    }

    #[test]
    fn armored_output_round_trips() {
        let plans = plan(&[ssh_person("erin", "ssh/erin_ed25519.pub")], None).unwrap();
        let mut out = Vec::new();
        let opts = EncryptOpts {
            armor: true,
            ..OPTS
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
