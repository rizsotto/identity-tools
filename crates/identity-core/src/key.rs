use std::fmt;
use std::time::SystemTime;

/// Which family a key belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    Ssh,
    OpenPgp,
    Age,
}

/// A key fingerprint, in the form the usual tool prints it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Fingerprint {
    /// `SHA256:<base64 without padding>`, as `ssh-keygen -l` prints it.
    Ssh(String),
    /// Full V4 or V5 fingerprint, upper case hex, as gpg prints it.
    OpenPgp(String),
    /// age X25519 keys have no separate fingerprint. This is the
    /// `age1...` recipient itself, lower case.
    Age(String),
}

impl Fingerprint {
    pub fn as_str(&self) -> &str {
        match self {
            Fingerprint::Ssh(s) | Fingerprint::OpenPgp(s) | Fingerprint::Age(s) => s,
        }
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Key algorithm with its size or curve.
///
/// Curve names follow OpenSSH and GnuPG (`nistp256`, `brainpoolP256r1`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyAlgo {
    Ed25519,
    Ecdsa(String),
    Rsa(u32),
    Dsa(u32),
    /// SSH security key (`sk-ssh-ed25519@openssh.com`).
    SkEd25519,
    /// SSH security key (`sk-ecdsa-sha2-nistp256@openssh.com`).
    SkEcdsa(String),
    /// OpenPGP ECDH on Curve25519.
    Cv25519,
    /// age X25519 recipient.
    X25519,
    /// Anything else, with the name the source used.
    Other(String),
}

/// A public key. Never holds private key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub kind: KeyKind,
    pub algo: KeyAlgo,
    pub fingerprint: Fingerprint,
    pub comment: Option<String>,
    /// Creation time. OpenPGP has one; SSH and age keys do not.
    pub created: Option<SystemTime>,
    pub expiry: Option<SystemTime>,
    /// The key in its usual text form, without comment: `<type> <base64>`
    /// for SSH, `age1...` for age.
    pub encoded: String,
}

impl PublicKey {
    /// Whether the age format can encrypt to this key: age X25519, SSH
    /// Ed25519 and SSH RSA. ECDSA and `sk-` keys are not age recipients.
    pub fn is_age_recipient(&self) -> bool {
        matches!(
            (self.kind, &self.algo),
            (KeyKind::Age, KeyAlgo::X25519)
                | (KeyKind::Ssh, KeyAlgo::Ed25519)
                | (KeyKind::Ssh, KeyAlgo::Rsa(_))
        )
    }
}
