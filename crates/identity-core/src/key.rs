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
    /// Anything else, with the name the backend gave.
    Other(String),
}

/// A public key. One variant per key family, each with the fields that
/// family really has. Never holds private key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ssh(SshPublicKey),
    Age(AgeRecipient),
    OpenPgp(OpenPgpKey),
}

impl PublicKey {
    pub fn kind(&self) -> KeyKind {
        match self {
            PublicKey::Ssh(_) => KeyKind::Ssh,
            PublicKey::Age(_) => KeyKind::Age,
            PublicKey::OpenPgp(_) => KeyKind::OpenPgp,
        }
    }

    pub fn algo(&self) -> KeyAlgo {
        match self {
            PublicKey::Ssh(k) => k.algo.clone(),
            PublicKey::Age(_) => KeyAlgo::X25519,
            PublicKey::OpenPgp(k) => k.algo.clone(),
        }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        match self {
            PublicKey::Ssh(k) => k.fingerprint.clone(),
            PublicKey::Age(k) => k.fingerprint(),
            PublicKey::OpenPgp(k) => k.fingerprint.clone(),
        }
    }

    /// Whether the age format can encrypt to this key: age X25519, SSH
    /// Ed25519, and SSH RSA from 2048 to 4096 bits (the range the `age`
    /// crate accepts, Send Secret SPEC 15 item 1). ECDSA and `sk-` keys are
    /// not age recipients.
    pub fn is_age_recipient(&self) -> bool {
        match self {
            PublicKey::Age(_) => true,
            PublicKey::Ssh(k) => match k.algo {
                KeyAlgo::Ed25519 => true,
                KeyAlgo::Rsa(bits) => (2048..=4096).contains(&bits),
                _ => false,
            },
            PublicKey::OpenPgp(_) => false,
        }
    }
}

/// An SSH public key from a `.pub` file or an `authorized_keys` style line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPublicKey {
    pub algo: KeyAlgo,
    pub fingerprint: Fingerprint,
    /// The comment as found. May hold control or bidi characters; use
    /// [`SshPublicKey::comment_display`] to show it.
    pub comment: Option<String>,
    /// `<type> <base64>`, without comment. Hand this to `ssh` or `age`.
    pub encoded: String,
}

impl SshPublicKey {
    /// The comment with control characters and bidi formatting characters
    /// removed, safe to show in a UI or a terminal.
    pub fn comment_display(&self) -> Option<String> {
        self.comment.as_deref().map(display_safe)
    }
}

/// An age X25519 recipient, `age1...`, lower case.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgeRecipient(pub(crate) String);

impl AgeRecipient {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::Age(self.0.clone())
    }
}

/// Summary of an OpenPGP key, from the GnuPG backend ([`crate::OpenPgpBackend`]).
///
/// `algo`, `created` and `expiry` are those of the primary key.
/// `can_encrypt` and `can_sign` are true if the key as a whole has a usable
/// subkey for that (not expired, revoked or disabled), as gpg computes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPgpKey {
    pub algo: KeyAlgo,
    pub fingerprint: Fingerprint,
    pub created: Option<SystemTime>,
    pub expiry: Option<SystemTime>,
    pub user_ids: Vec<UserId>,
    /// All subkeys, the primary key first, as gpg lists them.
    pub subkeys: Vec<OpenPgpSubkey>,
    pub can_encrypt: bool,
    pub can_sign: bool,
    pub revoked: bool,
    pub expired: bool,
    pub disabled: bool,
    pub invalid: bool,
}

/// One (sub)key of an OpenPGP key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPgpSubkey {
    pub algo: KeyAlgo,
    pub fingerprint: Fingerprint,
    pub created: Option<SystemTime>,
    pub expiry: Option<SystemTime>,
    pub can_encrypt: bool,
    pub can_sign: bool,
    pub can_certify: bool,
    pub can_authenticate: bool,
    pub revoked: bool,
    pub expired: bool,
}

/// An OpenPGP user ID. Fields are as found and may hold control or bidi
/// characters; use [`UserId::display`] to show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserId {
    /// The whole user ID, `Name (comment) <email>`.
    pub uid: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub revoked: bool,
    pub invalid: bool,
}

impl UserId {
    /// The user ID with control and bidi formatting characters removed.
    pub fn display(&self) -> String {
        display_safe(&self.uid)
    }

    /// Whether this user ID is valid (not revoked, not invalid) and its
    /// address is `email`. The whole address must match; only ASCII letters
    /// match case-insensitively, other characters must be equal. Angle
    /// brackets around either address are ignored. A user ID with no email
    /// field matches if the whole user ID is the address.
    pub fn has_email(&self, email: &str) -> bool {
        if self.revoked || self.invalid {
            return false;
        }
        let address = match self.email.as_deref() {
            Some(e) if !e.is_empty() => e,
            _ => &self.uid,
        };
        let address = strip_angle(address);
        let email = strip_angle(email);
        !email.is_empty() && email.contains('@') && address.eq_ignore_ascii_case(email)
    }
}

fn strip_angle(s: &str) -> &str {
    let s = s.trim();
    s.strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .unwrap_or(s)
}

fn display_safe(s: &str) -> String {
    s.chars()
        .filter(|&c| !c.is_control() && !is_bidi_control(c))
        .collect()
}

/// Unicode bidi formatting characters (marks, embeddings, overrides,
/// isolates). They can make text show in a different order than stored.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}
