//! Who gets which message (FR-3, FR-11, FR-12, decision 0002). Pure: no
//! I/O, so the caller can settle every message before writing any output.

use std::fmt;

use identity_core::MAX_KEY_INPUT;

use crate::age_backend::AgeKey;
use crate::{Error, Format, PlanError, Result};

/// The label of the self copy. The CLI refuses it as a recipient label.
pub const SELF_LABEL: &str = "self";

/// An OpenPGP public key, as the bytes of a key file. The OpenPGP backend
/// checks it holds exactly one key that can encrypt (SPEC 15, F3).
#[derive(Clone, PartialEq, Eq)]
pub struct OpenPgpCert {
    bytes: Vec<u8>,
}

impl OpenPgpCert {
    /// Refuses keys over 1 MB (S-7).
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > MAX_KEY_INPUT {
            return Err(Error::KeyTooLarge {
                limit: MAX_KEY_INPUT,
            });
        }
        Ok(OpenPgpCert { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for OpenPgpCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OpenPgpCert({} bytes)", self.bytes.len())
    }
}

/// One key of a recipient.
#[derive(Debug, Clone)]
pub enum Recipient {
    OpenPgp(OpenPgpCert),
    Age(AgeKey),
}

impl Recipient {
    pub fn format(&self) -> Format {
        match self {
            Recipient::OpenPgp(_) => Format::OpenPgp,
            Recipient::Age(_) => Format::Age,
        }
    }
}

/// One person. In M1, one `--to-key` file. May hold keys of both formats.
#[derive(Debug, Clone)]
pub struct Person {
    pub label: String,
    pub keys: Vec<Recipient>,
}

/// One message: one format, and only that person's keys of that format.
#[derive(Debug, Clone)]
pub struct MessagePlan {
    pub label: String,
    pub format: Format,
    pub keys: Vec<Recipient>,
}

/// One message per person, always (FR-11). Format per person: OpenPGP if
/// they have an OpenPGP key, else age (FR-3). `force` picks the format for
/// everyone. A person with no usable key is an error naming them.
pub fn plan(people: &[Person], force: Option<Format>) -> Result<Vec<MessagePlan>, PlanError> {
    people
        .iter()
        .map(|person| {
            let has = |format| person.keys.iter().any(|k| k.format() == format);
            let format = match force {
                Some(format) => format,
                None if has(Format::OpenPgp) => Format::OpenPgp,
                None => Format::Age,
            };
            let keys: Vec<_> = person
                .keys
                .iter()
                .filter(|k| k.format() == format)
                .cloned()
                .collect();
            if keys.is_empty() {
                return Err(PlanError::Unreachable {
                    label: person.label.clone(),
                    format: force,
                });
            }
            Ok(MessagePlan {
                label: person.label.clone(),
                format,
                keys,
            })
        })
        .collect()
}

/// The sender's own keys, for the self copy (FR-12). The caller finds them
/// before any output is written.
pub struct Sender {
    pub openpgp: OpenPgpSelf,
    /// From [`crate::SelfIdentity`]. Never an SSH key. `None` if the
    /// caller knows from [`self_format`] that the self copy is OpenPGP, so
    /// no age identity is created for nothing.
    pub age: Option<age::x25519::Recipient>,
}

/// The default secret key (gpg.conf `default-key`, else the first secret
/// key) and whether it can encrypt.
#[derive(Debug, Clone)]
pub enum OpenPgpSelf {
    CanEncrypt(OpenPgpCert),
    NoSecretKey,
    CannotEncrypt,
}

/// Why the self copy uses age although no format was forced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfNote {
    NoSecretKey,
    CannotEncrypt,
}

impl fmt::Display for SelfNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SelfNote::NoSecretKey => "you have no OpenPGP secret key, so the self copy uses age",
            SelfNote::CannotEncrypt => {
                "your default OpenPGP key cannot encrypt, so the self copy uses age"
            }
        })
    }
}

/// The self copy format: forced format if given, else OpenPGP if the
/// default secret key can encrypt, else age with a note. Forced OpenPGP
/// without such a key is an error.
pub fn self_format(
    openpgp: &OpenPgpSelf,
    force: Option<Format>,
) -> Result<(Format, Option<SelfNote>), PlanError> {
    match (force, openpgp) {
        (Some(Format::Age), _) => Ok((Format::Age, None)),
        (_, OpenPgpSelf::CanEncrypt(_)) => Ok((Format::OpenPgp, None)),
        (Some(Format::OpenPgp), _) => Err(PlanError::NoSelfKey {
            format: Format::OpenPgp,
        }),
        (None, OpenPgpSelf::NoSecretKey) => Ok((Format::Age, Some(SelfNote::NoSecretKey))),
        (None, OpenPgpSelf::CannotEncrypt) => Ok((Format::Age, Some(SelfNote::CannotEncrypt))),
    }
}

/// The self copy: one message with only the sender's key, labeled `self`,
/// in the format [`self_format`] picks.
pub fn self_plan(
    sender: &Sender,
    force: Option<Format>,
) -> Result<(MessagePlan, Option<SelfNote>), PlanError> {
    let (format, note) = self_format(&sender.openpgp, force)?;
    let key = match (format, &sender.openpgp, &sender.age) {
        (Format::OpenPgp, OpenPgpSelf::CanEncrypt(cert), _) => Recipient::OpenPgp(cert.clone()),
        (Format::Age, _, Some(age)) => Recipient::Age(AgeKey::X25519(age.clone())),
        _ => return Err(PlanError::NoSelfKey { format }),
    };
    let plan = MessagePlan {
        label: SELF_LABEL.into(),
        format,
        keys: vec![key],
    };
    Ok((plan, note))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn cert() -> OpenPgpCert {
        OpenPgpCert::new(b"key bytes".to_vec()).unwrap()
    }

    fn age_key() -> Recipient {
        let id = age::x25519::Identity::generate();
        Recipient::Age(AgeKey::X25519(id.to_public()))
    }

    fn ssh_key() -> Recipient {
        let line = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/ssh/erin_ed25519.pub"),
        )
        .unwrap();
        Recipient::Age(AgeKey::Ssh(
            age::ssh::Recipient::from_str(line.trim()).unwrap(),
        ))
    }

    fn person(label: &str, keys: Vec<Recipient>) -> Person {
        Person {
            label: label.into(),
            keys,
        }
    }

    fn summary(plans: &[MessagePlan]) -> Vec<(&str, Format, usize)> {
        plans
            .iter()
            .map(|p| (p.label.as_str(), p.format, p.keys.len()))
            .collect()
    }

    fn sender(openpgp: OpenPgpSelf) -> Sender {
        Sender {
            openpgp,
            age: Some(age::x25519::Identity::generate().to_public()),
        }
    }

    #[test]
    fn plan_one_message_per_person() {
        let people = [
            person("erin", vec![ssh_key(), age_key()]),
            person("dave", vec![age_key()]),
            person("frank", vec![ssh_key()]),
        ];
        let plans = plan(&people, None).unwrap();
        assert_eq!(
            summary(&plans),
            [
                ("erin", Format::Age, 2),
                ("dave", Format::Age, 1),
                ("frank", Format::Age, 1)
            ]
        );
    }

    #[test]
    fn plan_prefers_openpgp_per_person() {
        let plans = plan(
            &[person("alice", vec![ssh_key(), cert_key(), age_key()])],
            None,
        )
        .unwrap();
        assert_eq!(summary(&plans), [("alice", Format::OpenPgp, 1)]);
        assert!(matches!(plans[0].keys[0], Recipient::OpenPgp(_)));
    }

    fn cert_key() -> Recipient {
        Recipient::OpenPgp(cert())
    }

    #[test]
    fn plan_mixed_set_gives_both_formats() {
        let people = [
            person("alice", vec![cert_key()]),
            person("erin", vec![ssh_key()]),
        ];
        let plans = plan(&people, None).unwrap();
        assert_eq!(
            summary(&plans),
            [("alice", Format::OpenPgp, 1), ("erin", Format::Age, 1)]
        );
    }

    #[test]
    fn plan_forced_format_names_unreachable() {
        let people = [
            person("alice", vec![cert_key(), ssh_key()]),
            person("bob", vec![cert_key()]),
        ];
        let plans = plan(&people[..1], Some(Format::Age)).unwrap();
        assert_eq!(summary(&plans), [("alice", Format::Age, 1)]);
        assert_eq!(
            plan(&people, Some(Format::Age)).unwrap_err(),
            PlanError::Unreachable {
                label: "bob".into(),
                format: Some(Format::Age)
            }
        );
        let erin = [person("erin", vec![ssh_key()])];
        assert_eq!(
            plan(&erin, Some(Format::OpenPgp)).unwrap_err().to_string(),
            "erin has no usable OpenPGP key"
        );
    }

    #[test]
    fn plan_no_usable_key_names_person() {
        let people = [person("dave", vec![age_key()]), person("heidi", vec![])];
        assert_eq!(
            plan(&people, None).unwrap_err().to_string(),
            "heidi has no usable key"
        );
    }

    #[test]
    fn self_plan_format_rule() {
        let s = sender(OpenPgpSelf::CanEncrypt(cert()));
        let (p, note) = self_plan(&s, None).unwrap();
        assert_eq!(
            (p.label.as_str(), p.format, note),
            ("self", Format::OpenPgp, None)
        );
        let (p, note) = self_plan(&s, Some(Format::Age)).unwrap();
        assert_eq!((p.format, note), (Format::Age, None));
        assert!(
            matches!(&p.keys[..], [Recipient::Age(AgeKey::X25519(r))] if Some(r) == s.age.as_ref())
        );
        let (p, _) = self_plan(&s, Some(Format::OpenPgp)).unwrap();
        assert_eq!(p.format, Format::OpenPgp);
    }

    #[test]
    fn self_plan_falls_back_to_age_with_note() {
        for (openpgp, want) in [
            (OpenPgpSelf::NoSecretKey, SelfNote::NoSecretKey),
            (OpenPgpSelf::CannotEncrypt, SelfNote::CannotEncrypt),
        ] {
            let s = sender(openpgp);
            let (p, note) = self_plan(&s, None).unwrap();
            assert_eq!((p.format, note), (Format::Age, Some(want)));
            assert_eq!(p.keys.len(), 1);
            assert!(note.unwrap().to_string().contains("self copy uses age"));
        }
    }

    #[test]
    fn self_plan_forced_openpgp_without_key_errors() {
        for openpgp in [OpenPgpSelf::NoSecretKey, OpenPgpSelf::CannotEncrypt] {
            assert_eq!(
                self_plan(&sender(openpgp), Some(Format::OpenPgp)).unwrap_err(),
                PlanError::NoSelfKey {
                    format: Format::OpenPgp
                }
            );
        }
    }

    #[test]
    fn self_plan_without_age_key_errors_only_when_age_is_needed() {
        let s = Sender {
            openpgp: OpenPgpSelf::CanEncrypt(cert()),
            age: None,
        };
        assert_eq!(self_plan(&s, None).unwrap().0.format, Format::OpenPgp);
        assert_eq!(
            self_plan(&s, Some(Format::Age)).unwrap_err(),
            PlanError::NoSelfKey {
                format: Format::Age
            }
        );
    }

    #[test]
    fn openpgp_cert_over_1mb_is_refused() {
        assert!(OpenPgpCert::new(vec![0; MAX_KEY_INPUT]).is_ok());
        let err = OpenPgpCert::new(vec![0; MAX_KEY_INPUT + 1]).unwrap_err();
        assert!(matches!(err, Error::KeyTooLarge { .. }), "{err:?}");
    }
}
