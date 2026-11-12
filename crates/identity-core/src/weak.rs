//! Weak key rules (Key Steward SPEC 9.4).

use crate::key::{KeyAlgo, PublicKey};
use crate::private_header::PrivateKeyProtection;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

/// Why a key is flagged. The UI turns this into text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WeakReason {
    /// RSA shorter than [`MIN_RSA_BITS`].
    RsaTooShort(u32),
    Dsa,
    /// ECDSA on a NIST curve; Ed25519 is preferred.
    EcdsaNist,
    /// The SSH private key file has no passphrase.
    PrivateKeyUnencrypted,
    /// OpenPGP key that never expires.
    NoExpiry,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyWarning {
    pub severity: Severity,
    pub reason: WeakReason,
}

pub const MIN_RSA_BITS: u32 = 3072;

/// Apply the weak key rules. `protection` is the private key header check
/// result, if there is a private key file. `Unknown` gives no warning: we
/// only warn where we can tell.
pub fn weak_key_warnings(
    key: &PublicKey,
    protection: Option<PrivateKeyProtection>,
) -> Vec<KeyWarning> {
    let mut out = Vec::new();
    let mut add = |severity, reason| out.push(KeyWarning { severity, reason });
    match &key.algo() {
        KeyAlgo::Rsa(bits) if *bits < MIN_RSA_BITS => {
            add(Severity::Warning, WeakReason::RsaTooShort(*bits))
        }
        KeyAlgo::Dsa(_) => add(Severity::Error, WeakReason::Dsa),
        KeyAlgo::Ecdsa(curve) if curve.starts_with("nistp") => {
            add(Severity::Info, WeakReason::EcdsaNist)
        }
        _ => {}
    }
    if protection == Some(PrivateKeyProtection::Unencrypted) {
        add(Severity::Warning, WeakReason::PrivateKeyUnencrypted);
    }
    if let PublicKey::OpenPgp(k) = key
        && k.expiry.is_none()
    {
        add(Severity::Info, WeakReason::NoExpiry);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{AgeRecipient, Fingerprint, KeyKind, OpenPgpKey, SshPublicKey};
    use std::time::{Duration, SystemTime};

    fn key(kind: KeyKind, algo: KeyAlgo, expiry: Option<SystemTime>) -> PublicKey {
        match kind {
            KeyKind::Ssh => PublicKey::Ssh(SshPublicKey {
                algo,
                fingerprint: Fingerprint::Ssh("SHA256:test".into()),
                comment: None,
                encoded: String::new(),
            }),
            KeyKind::OpenPgp => PublicKey::OpenPgp(OpenPgpKey {
                algo,
                fingerprint: Fingerprint::OpenPgp("00".into()),
                created: None,
                expiry,
            }),
            KeyKind::Age => PublicKey::Age(AgeRecipient("age1test".into())),
        }
    }

    type Expected = Vec<(Severity, WeakReason)>;

    #[test]
    fn weak_key_rules_table() {
        use KeyAlgo::*;
        use KeyKind::*;
        use PrivateKeyProtection::*;
        use Severity::{Error as E, Info as I, Warning as W};
        use WeakReason::*;
        let later = Some(SystemTime::now() + Duration::from_secs(86400));
        let nist = || Ecdsa("nistp256".into());
        let cases: Vec<(PublicKey, Option<PrivateKeyProtection>, Expected)> = vec![
            (key(Ssh, Ed25519, None), Some(Encrypted), vec![]),
            (
                key(Ssh, Ed25519, None),
                Some(Unencrypted),
                vec![(W, PrivateKeyUnencrypted)],
            ),
            (key(Ssh, Ed25519, None), Some(Unknown), vec![]),
            (key(Ssh, Ed25519, None), None, vec![]),
            (key(Ssh, Rsa(3072), None), Some(Encrypted), vec![]),
            (
                key(Ssh, Rsa(2048), None),
                Some(Encrypted),
                vec![(W, RsaTooShort(2048))],
            ),
            (
                key(Ssh, Rsa(1024), None),
                Some(Unencrypted),
                vec![(W, RsaTooShort(1024)), (W, PrivateKeyUnencrypted)],
            ),
            (
                key(Ssh, KeyAlgo::Dsa(1024), None),
                None,
                vec![(E, WeakReason::Dsa)],
            ),
            (
                key(Ssh, nist(), None),
                Some(Encrypted),
                vec![(I, EcdsaNist)],
            ),
            (
                key(Ssh, Ecdsa("nistp521".into()), None),
                None,
                vec![(I, EcdsaNist)],
            ),
            (key(Ssh, SkEd25519, None), None, vec![]),
            (key(Age, X25519, None), None, vec![]),
            (key(OpenPgp, Ed25519, later), None, vec![]),
            (key(OpenPgp, Ed25519, None), None, vec![(I, NoExpiry)]),
            (
                key(OpenPgp, Rsa(2048), None),
                None,
                vec![(W, RsaTooShort(2048)), (I, NoExpiry)],
            ),
            (
                key(OpenPgp, Ecdsa("brainpoolP256r1".into()), later),
                None,
                vec![],
            ),
        ];
        for (k, protection, want) in cases {
            let got: Vec<_> = weak_key_warnings(&k, protection)
                .into_iter()
                .map(|w| (w.severity, w.reason))
                .collect();
            assert_eq!(got, want, "{:?} {protection:?}", k);
        }
    }
}
