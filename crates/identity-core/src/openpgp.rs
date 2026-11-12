//! GnuPG backend: a gpgme context with an explicit home dir, and key
//! listing behind [`OpenPgpBackend`] (Key Steward SPEC 8 keeps Sequoia
//! possible later). No gpgme type is part of the public API.

use std::ffi::CString;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use gpgme::{Context, KeyAlgorithm, Protocol};

use crate::error::GpgError;
use crate::key::{Fingerprint, KeyAlgo, OpenPgpKey, OpenPgpSubkey, UserId};
use crate::parse::MAX_KEY_INPUT;

/// Read access to OpenPGP keys. Never exports or returns secret key
/// material.
pub trait OpenPgpBackend {
    /// All public keys in the keyring.
    fn public_keys(&mut self) -> Result<Vec<OpenPgpKey>, GpgError>;
    /// The keys that have a secret key in the keyring (public parts only).
    fn secret_keys(&mut self) -> Result<Vec<OpenPgpKey>, GpgError>;
    /// Parse keys from bytes (armored or binary) without importing them.
    /// Input over [`MAX_KEY_INPUT`] is refused.
    fn read_keys(&mut self, bytes: &[u8]) -> Result<Vec<OpenPgpKey>, GpgError>;
    /// The key gpg signs with by default: the last `default-key` in
    /// `gpg.conf` that has a secret key, else the first secret key. `None`
    /// if there is no such key. If `default-key` is set but none of its
    /// values has a secret key, this is `None` too (gpg would not fall back
    /// either).
    fn default_secret_key(&mut self) -> Result<Option<OpenPgpKey>, GpgError>;
}

/// A gpgme context for the OpenPGP protocol.
///
/// Tests always use [`Gpg::with_home`] with a temp dir. Only the app itself
/// uses [`Gpg::user_default`].
pub struct Gpg {
    ctx: Context,
    home: Option<PathBuf>,
}

impl Gpg {
    /// A context that uses `home` as the GnuPG home dir (like `GNUPGHOME`).
    pub fn with_home(home: &Path) -> Result<Self, GpgError> {
        let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
        let c_home = CString::new(home.as_os_str().as_bytes()).map_err(|_| GpgError::UnsafePath)?;
        ctx.set_engine_home_dir(c_home)?;
        Ok(Gpg {
            ctx,
            home: Some(home.to_path_buf()),
        })
    }

    /// A context with gpg's own default home (`GNUPGHOME` or `~/.gnupg`).
    pub fn user_default() -> Result<Self, GpgError> {
        Ok(Gpg {
            ctx: Context::from_protocol(Protocol::OpenPgp)?,
            home: None,
        })
    }

    /// The home dir given to [`Gpg::with_home`], `None` for the default.
    /// A caller that needs its own gpgme context (Send Secret's `crypto`)
    /// sets the same home on it.
    pub fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }

    /// The home dir gpg really uses.
    pub fn effective_home(&self) -> Option<PathBuf> {
        match &self.home {
            Some(h) => Some(h.clone()),
            None => gpgme::init()
                .get_dir_info_raw("homedir")
                .map(|c| PathBuf::from(std::ffi::OsStr::from_bytes(c.to_bytes()))),
        }
    }

    fn collect(
        keys: impl Iterator<Item = gpgme::Result<gpgme::Key>>,
    ) -> Result<Vec<OpenPgpKey>, GpgError> {
        keys.map(|k| Ok(convert(&k?))).collect()
    }

    fn secret_key_for(&mut self, pattern: &str) -> Result<Option<OpenPgpKey>, GpgError> {
        let fpr = {
            let mut keys = self.ctx.find_secret_keys([pattern])?;
            match keys.next() {
                Some(k) => k?.fingerprint().ok().map(str::to_string),
                None => None,
            }
        };
        match fpr {
            // The public listing, so the capabilities are those of the
            // public key others encrypt to.
            Some(fpr) => Ok(Some(convert(&self.ctx.get_key(fpr)?))),
            None => Ok(None),
        }
    }
}

impl OpenPgpBackend for Gpg {
    fn public_keys(&mut self) -> Result<Vec<OpenPgpKey>, GpgError> {
        Self::collect(self.ctx.keys()?)
    }

    fn secret_keys(&mut self) -> Result<Vec<OpenPgpKey>, GpgError> {
        let fprs: Vec<String> = self
            .ctx
            .secret_keys()?
            .map(|k| Ok(k?.fingerprint().unwrap_or_default().to_string()))
            .collect::<Result<_, gpgme::Error>>()?;
        fprs.into_iter()
            .map(|f| Ok(convert(&self.ctx.get_key(f)?)))
            .collect()
    }

    fn read_keys(&mut self, bytes: &[u8]) -> Result<Vec<OpenPgpKey>, GpgError> {
        if bytes.len() > MAX_KEY_INPUT {
            return Err(GpgError::TooLarge {
                limit: MAX_KEY_INPUT,
            });
        }
        Self::collect(self.ctx.read_keys(bytes)?)
    }

    fn default_secret_key(&mut self) -> Result<Option<OpenPgpKey>, GpgError> {
        let configured = match self.effective_home() {
            Some(home) => default_keys_in_conf(&home.join("gpg.conf"))?,
            None => Vec::new(),
        };
        if configured.is_empty() {
            return Ok(self.secret_keys()?.into_iter().next());
        }
        for pattern in configured.iter().rev() {
            if let Some(key) = self.secret_key_for(pattern)? {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }
}

/// The `default-key` values in a gpg.conf, in file order. A missing file
/// has none.
fn default_keys_in_conf(path: &Path) -> Result<Vec<String>, GpgError> {
    let mut text = String::new();
    match std::fs::File::open(path) {
        Ok(f) => {
            f.take(MAX_KEY_INPUT as u64).read_to_string(&mut text)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    }
    Ok(parse_default_keys(&text))
}

fn parse_default_keys(conf: &str) -> Vec<String> {
    conf.lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("default-key")?;
            if !rest.starts_with([' ', '\t']) {
                return None;
            }
            let value = rest.trim().trim_matches('"');
            (!value.is_empty()).then(|| value.to_string())
        })
        .collect()
}

fn convert(key: &gpgme::Key) -> OpenPgpKey {
    let subkeys: Vec<OpenPgpSubkey> = key.subkeys().map(|s| convert_subkey(&s)).collect();
    let primary = subkeys.first();
    OpenPgpKey {
        algo: primary.map_or(KeyAlgo::Other(String::new()), |p| p.algo.clone()),
        fingerprint: Fingerprint::OpenPgp(key.fingerprint().unwrap_or_default().to_uppercase()),
        created: primary.and_then(|p| p.created),
        expiry: primary.and_then(|p| p.expiry),
        user_ids: key
            .user_ids()
            .map(|u| UserId {
                uid: lossy(u.id_raw()),
                name: u.name_raw().map(|c| lossy(Some(c))),
                email: u.email_raw().map(|c| lossy(Some(c))),
                revoked: u.is_revoked(),
                invalid: u.is_invalid(),
            })
            .collect(),
        can_encrypt: key.can_encrypt(),
        can_sign: key.can_sign(),
        revoked: key.is_revoked(),
        expired: key.is_expired(),
        disabled: key.is_disabled(),
        invalid: key.is_invalid(),
        subkeys,
    }
}

fn convert_subkey(s: &gpgme::Subkey<'_>) -> OpenPgpSubkey {
    OpenPgpSubkey {
        algo: algo(s.algorithm(), s.length(), s.curve().unwrap_or_default()),
        fingerprint: Fingerprint::OpenPgp(s.fingerprint().unwrap_or_default().to_uppercase()),
        created: s.creation_time(),
        expiry: s.expiration_time(),
        can_encrypt: s.can_encrypt(),
        can_sign: s.can_sign(),
        can_certify: s.can_certify(),
        can_authenticate: s.can_authenticate(),
        revoked: s.is_revoked(),
        expired: s.is_expired(),
    }
}

fn lossy(c: Option<&std::ffi::CStr>) -> String {
    c.map(|c| String::from_utf8_lossy(c.to_bytes()).into_owned())
        .unwrap_or_default()
}

/// Map gpg's algorithm and curve to [`KeyAlgo`]. Curve names follow gpg
/// (`ed25519`, `cv25519`, `nistp256`, `brainpoolP256r1`); older keys may
/// use `Ed25519` / `Curve25519`.
fn algo(a: KeyAlgorithm, bits: usize, curve: &str) -> KeyAlgo {
    let c = curve.to_ascii_lowercase();
    match a {
        KeyAlgorithm::Rsa | KeyAlgorithm::RsaEncrypt | KeyAlgorithm::RsaSign => {
            KeyAlgo::Rsa(bits as u32)
        }
        KeyAlgorithm::Dsa => KeyAlgo::Dsa(bits as u32),
        KeyAlgorithm::Eddsa if c == "ed25519" => KeyAlgo::Ed25519,
        KeyAlgorithm::Ecdh if c == "cv25519" || c == "curve25519" => KeyAlgo::Cv25519,
        KeyAlgorithm::Ecdsa => KeyAlgo::Ecdsa(curve.to_string()),
        KeyAlgorithm::Ecdh => KeyAlgo::Other(format!("ecdh {curve}")),
        KeyAlgorithm::Eddsa => KeyAlgo::Other(format!("eddsa {curve}")),
        KeyAlgorithm::Elgamal | KeyAlgorithm::ElgamalEncrypt => {
            KeyAlgo::Other(format!("elg{bits}"))
        }
        other => KeyAlgo::Other(other.name().unwrap_or("unknown").to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_key_lines() {
        let conf = "# comment\n default-key  AAAA \ndefault-keyserver x\n\
                    default-key \"bob@example.org\"\ndefault-key\n";
        assert_eq!(parse_default_keys(conf), ["AAAA", "bob@example.org"]);
    }

    #[test]
    fn maps_gpg_algorithms() {
        use KeyAlgorithm as A;
        assert_eq!(algo(A::Rsa, 3072, ""), KeyAlgo::Rsa(3072));
        assert_eq!(algo(A::Eddsa, 255, "ed25519"), KeyAlgo::Ed25519);
        assert_eq!(algo(A::Eddsa, 255, "Ed25519"), KeyAlgo::Ed25519);
        assert_eq!(algo(A::Ecdh, 255, "cv25519"), KeyAlgo::Cv25519);
        assert_eq!(algo(A::Ecdh, 255, "Curve25519"), KeyAlgo::Cv25519);
        assert_eq!(
            algo(A::Ecdsa, 256, "nistp256"),
            KeyAlgo::Ecdsa("nistp256".into())
        );
        assert_eq!(
            algo(A::Ecdh, 256, "nistp256"),
            KeyAlgo::Other("ecdh nistp256".into())
        );
    }
}
