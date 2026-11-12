//! GnuPG backend: a gpgme context with an explicit home dir, and key
//! listing behind [`OpenPgpBackend`] (Key Steward SPEC 8 keeps Sequoia
//! possible later). No gpgme type is part of the public API.

use std::ffi::CString;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use std::os::unix::fs::PermissionsExt;

use gpgme::{Context, ExportMode, KeyAlgorithm, Protocol};

use crate::error::GpgError;
use crate::key::{Fingerprint, KeyAlgo, OpenPgpKey, OpenPgpSubkey, UserId};
use crate::parse::MAX_KEY_INPUT;

/// The most keys [`Gpg::split_keys`] takes from one blob.
pub const MAX_SPLIT_KEYS: usize = 32;
/// The most user IDs [`Gpg::split_keys`] takes on one key.
pub const MAX_SPLIT_USER_IDS: usize = 100;
/// The most subkeys (not counting the primary key) [`Gpg::split_keys`]
/// takes on one key.
pub const MAX_SPLIT_SUBKEYS: usize = 50;

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
    /// The key gpg signs with by default, found with gpg 2.4's rules
    /// (checked against gpg 2.4.9):
    ///
    /// - The config file is the first of `gpg.conf-<major.minor.micro>`,
    ///   `gpg.conf-<major.minor>`, `gpg.conf-<major>` and `gpg.conf` that
    ///   exists. It is read as lossy UTF-8.
    /// - `default-key` values are tried last first. A value is skipped if it
    ///   matches no secret key or only unusable ones (revoked, expired,
    ///   disabled or invalid). A usable key that cannot sign is still
    ///   returned (gpg picks it and then fails to sign).
    /// - If no value gives a key, or there is none, it is the first secret
    ///   key that is usable and can sign.
    ///
    /// `None` if there is no such key. Callers that sign should name this
    /// key as the signer and not rely on gpg's own choice.
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

    /// The gpg.conf gpg reads in the effective home: the first existing
    /// of `gpg.conf-<major.minor.micro>`, `gpg.conf-<major.minor>`,
    /// `gpg.conf-<major>`, `gpg.conf` (the last also if none exists).
    /// `None` if the home is unknown.
    pub fn conf_file(&self) -> Option<PathBuf> {
        self.effective_home().map(|home| self.conf_path(&home))
    }

    /// Export one key (public parts only, binary) by the full fingerprint
    /// of its primary key (40 or 64 hex digits). Output over
    /// [`MAX_KEY_INPUT`] is refused.
    ///
    /// gpgme has no "no armor" switch, so `armor` in the user's gpg.conf
    /// makes gpg export armor. Such output goes through
    /// [`Gpg::split_keys`], whose throwaway home has no `armor`.
    pub fn export_key(&mut self, fingerprint: &str) -> Result<Vec<u8>, GpgError> {
        let out = self.export_as_gpg_writes(fingerprint)?;
        if is_binary(&out) {
            return Ok(out);
        }
        let mut parts = Self::split_keys(&out)?;
        if parts.len() != 1 {
            return Err(GpgError::KeyNotFound);
        }
        Ok(parts.remove(0).1)
    }

    /// [`Gpg::export_key`] without the armor fallback.
    fn export_as_gpg_writes(&mut self, fingerprint: &str) -> Result<Vec<u8>, GpgError> {
        let fpr = fingerprint.to_ascii_uppercase();
        if !matches!(fpr.len(), 40 | 64) || !fpr.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(GpgError::BadFingerprint);
        }
        match self.ctx.get_key(fpr.as_str()) {
            Ok(k) if k.fingerprint().is_ok_and(|f| f.eq_ignore_ascii_case(&fpr)) => {}
            Ok(_) => return Err(GpgError::KeyNotFound),
            Err(e) if e.code() == gpgme::Error::EOF.code() => return Err(GpgError::KeyNotFound),
            Err(e) => return Err(e.into()),
        }
        let mut out = Vec::new();
        self.ctx
            .export([fpr.as_str()], ExportMode::empty(), &mut out)?;
        if out.len() > MAX_KEY_INPUT {
            return Err(GpgError::TooLarge {
                limit: MAX_KEY_INPUT,
            });
        }
        Ok(out)
    }

    /// Split a blob of OpenPGP keys (armored or binary, maybe several
    /// concatenated) into one binary export per key, with its summary.
    ///
    /// The blob is imported into a throwaway home (mode 0700 in
    /// `$XDG_RUNTIME_DIR` or the temp dir, gpg.conf `no-autostart`, deleted
    /// before this returns), never into the user's keyring. Input over
    /// [`MAX_KEY_INPUT`] or with more than [`MAX_SPLIT_KEYS`] keys is
    /// refused, and so is a key with more than [`MAX_SPLIT_USER_IDS`] user
    /// IDs or [`MAX_SPLIT_SUBKEYS`] subkeys (checked after gpgme reads the
    /// blob, before the slower import). A blob with no key gives an empty
    /// list.
    ///
    /// gpg's CPU time grows with the number of packets (about 0.5 s to read
    /// and 0.9 s to import a key with 400 user IDs). Callers that handle
    /// fetched data run this under a deadline.
    pub fn split_keys(bytes: &[u8]) -> Result<Vec<(OpenPgpKey, Vec<u8>)>, GpgError> {
        if bytes.len() > MAX_KEY_INPUT {
            return Err(GpgError::TooLarge {
                limit: MAX_KEY_INPUT,
            });
        }
        let builder = |parent: PathBuf| {
            tempfile::Builder::new()
                .prefix("ic-split")
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in(parent)
        };
        let dir = match runtime_dir() {
            Some(runtime) => builder(runtime).or_else(|_| builder(std::env::temp_dir()))?,
            None => builder(std::env::temp_dir())?,
        };
        std::fs::write(dir.path().join("gpg.conf"), "no-autostart\n")?;
        let result = Self::split_in(dir.path(), bytes);
        dir.close()?;
        result
    }

    fn split_in(home: &Path, bytes: &[u8]) -> Result<Vec<(OpenPgpKey, Vec<u8>)>, GpgError> {
        let mut gpg = Gpg::with_home(home)?;
        let read = gpg.read_keys(bytes)?;
        if read.is_empty() {
            return Ok(Vec::new());
        }
        if read.len() > MAX_SPLIT_KEYS {
            return Err(GpgError::TooManyKeys {
                limit: MAX_SPLIT_KEYS,
            });
        }
        for key in &read {
            if key.user_ids.len() > MAX_SPLIT_USER_IDS {
                return Err(GpgError::TooComplex {
                    what: "user IDs",
                    limit: MAX_SPLIT_USER_IDS,
                });
            }
            if key.subkeys.len().saturating_sub(1) > MAX_SPLIT_SUBKEYS {
                return Err(GpgError::TooComplex {
                    what: "subkeys",
                    limit: MAX_SPLIT_SUBKEYS,
                });
            }
        }
        gpg.ctx.import(bytes)?;
        let keys = gpg.public_keys()?;
        if keys.len() > MAX_SPLIT_KEYS {
            return Err(GpgError::TooManyKeys {
                limit: MAX_SPLIT_KEYS,
            });
        }
        keys.into_iter()
            .map(|key| {
                let bytes = gpg.export_as_gpg_writes(key.fingerprint.as_str())?;
                if !is_binary(&bytes) {
                    // Armor forced from outside the home (gpgconf.conf).
                    return Err(GpgError::Gpgme("gpg exported armor".into()));
                }
                Ok((key, bytes))
            })
            .collect()
    }

    fn collect(
        keys: impl Iterator<Item = gpgme::Result<gpgme::Key>>,
    ) -> Result<Vec<OpenPgpKey>, GpgError> {
        keys.map(|k| Ok(convert(&k?))).collect()
    }

    /// The first usable secret key that `pattern` matches. A pattern gpg
    /// refuses matches nothing, as gpg ignores such a value.
    fn usable_secret_key_for(&mut self, pattern: &str) -> Result<Option<OpenPgpKey>, GpgError> {
        let fprs: Vec<String> = match self.ctx.find_secret_keys([pattern]) {
            Ok(keys) => keys
                .filter_map(Result::ok)
                .filter_map(|k| k.fingerprint().ok().map(str::to_string))
                .collect(),
            Err(_) => return Ok(None),
        };
        for fpr in fprs {
            // The public listing, so the capabilities are those of the
            // public key others encrypt to.
            let key = convert(&self.ctx.get_key(fpr)?);
            if usable(&key) {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }

    /// The gpg.conf that gpg reads: a versioned file wins over `gpg.conf`.
    fn conf_path(&self, home: &Path) -> PathBuf {
        let version = self.ctx.engine_info().version().unwrap_or("").to_string();
        conf_candidates(&version)
            .into_iter()
            .map(|name| home.join(name))
            .find(|p| p.exists())
            .unwrap_or_else(|| home.join("gpg.conf"))
    }
}

/// `$XDG_RUNTIME_DIR` if set, absolute and a dir.
fn runtime_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_dir())
}

/// Binary OpenPGP starts with a packet tag byte, which has bit 7 set.
/// Armor starts with ASCII.
fn is_binary(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(|b| b & 0x80 != 0)
}

fn usable(key: &OpenPgpKey) -> bool {
    !(key.revoked || key.expired || key.disabled || key.invalid)
}

/// `gpg.conf-2.4.9`, `gpg.conf-2.4`, `gpg.conf-2`, `gpg.conf`.
fn conf_candidates(version: &str) -> Vec<String> {
    let parts: Vec<&str> = version
        .split('.')
        .take(3)
        .take_while(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        .collect();
    let mut out: Vec<String> = (1..=parts.len())
        .rev()
        .map(|n| format!("gpg.conf-{}", parts[..n].join(".")))
        .collect();
    out.push("gpg.conf".to_string());
    out
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
            Some(home) => default_keys_in_conf(&self.conf_path(&home))?,
            None => Vec::new(),
        };
        for pattern in configured.iter().rev() {
            if let Some(key) = self.usable_secret_key_for(pattern)? {
                return Ok(Some(key));
            }
        }
        Ok(self
            .secret_keys()?
            .into_iter()
            .find(|k| usable(k) && k.can_sign))
    }
}

/// The `default-key` values in a gpg.conf, in file order. A missing file
/// has none.
fn default_keys_in_conf(path: &Path) -> Result<Vec<String>, GpgError> {
    let mut bytes = Vec::new();
    match std::fs::File::open(path) {
        Ok(f) => {
            f.take(MAX_KEY_INPUT as u64).read_to_end(&mut bytes)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    }
    Ok(parse_default_keys(&String::from_utf8_lossy(&bytes)))
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
    fn versioned_conf_names_most_specific_first() {
        assert_eq!(
            conf_candidates("2.4.9"),
            ["gpg.conf-2.4.9", "gpg.conf-2.4", "gpg.conf-2", "gpg.conf"]
        );
        assert_eq!(conf_candidates(""), ["gpg.conf"]);
        assert_eq!(
            conf_candidates("2.5.1-beta"),
            ["gpg.conf-2.5", "gpg.conf-2", "gpg.conf"]
        );
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
