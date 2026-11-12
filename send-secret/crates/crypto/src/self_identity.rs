//! The sender's own age identity for the self copy (FR-12, section 9).
//! Always a native X25519 key, never an SSH key, so the self copy carries no
//! SSH key tag that links it to the sender.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Larger files are not ours; refuse them instead of reading them.
const MAX_FILE: u64 = 64 * 1024;

/// `<config_home>/send-secret/identities`. Pass `$XDG_CONFIG_HOME` (or
/// `~/.config`); tests pass a temp dir.
pub fn self_identity_path(config_home: &Path) -> PathBuf {
    config_home.join("send-secret").join("identities")
}

/// The sender's X25519 identity.
pub struct SelfIdentity {
    identity: age::x25519::Identity,
}

impl SelfIdentity {
    /// Loads the identity at `path`, or creates it if the file does not
    /// exist: parent dir 0700, file 0600, never overwritten.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if let Some(found) = Self::load(path)? {
            return Ok(found);
        }
        let dir = path
            .parent()
            .ok_or(Error::Identity("self identity path has no parent dir"))?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let identity = age::x25519::Identity::generate();
        // Sized up front so the secret is never copied by a reallocation.
        let mut text = Zeroizing::new(String::with_capacity(512));
        write!(
            text,
            "# Send Secret self copy identity. Keep it secret.\n# public key: {}\n{}\n",
            identity.to_public(),
            identity.to_string().expose_secret()
        )
        .map_err(|_| Error::Identity("could not format the self identity"))?;
        let mut tmp = tempfile::Builder::new()
            .prefix(".identities-")
            .permissions(fs::Permissions::from_mode(0o600))
            .tempfile_in(dir)?;
        tmp.write_all(text.as_bytes())?;
        tmp.as_file().sync_all()?;
        match tmp.persist_noclobber(path) {
            Ok(_) => Ok(SelfIdentity { identity }),
            // Another run created it first: use that one.
            Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => {
                Self::load(path)?.ok_or(Error::Identity("self identity file vanished"))
            }
            Err(e) => Err(e.error.into()),
        }
    }

    /// Loads the identity at `path`. `None` if the file does not exist.
    /// Refuses a file that group or others can access.
    pub fn load(path: &Path) -> Result<Option<Self>> {
        let file = match fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(Error::Identity("self identity is not a regular file"));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::Identity(
                "self identity file is readable by others; it must be mode 0600",
            ));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_FILE {
            return Err(Error::Identity("self identity file is too large"));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::Identity("self identity file is not text"))?;
        let mut keys = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'));
        let (Some(line), None) = (keys.next(), keys.next()) else {
            return Err(Error::Identity(
                "self identity file must hold exactly one age X25519 identity",
            ));
        };
        let identity = age::x25519::Identity::from_str(line)
            .map_err(|_| Error::Identity("self identity file holds no valid X25519 identity"))?;
        Ok(Some(SelfIdentity { identity }))
    }

    /// The public key, for the age self copy.
    pub fn recipient(&self) -> age::x25519::Recipient {
        self.identity.to_public()
    }

    pub(crate) fn into_identity(self) -> Box<dyn age::Identity> {
        Box::new(self.identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn self_identity_created_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let path = self_identity_path(tmp.path());
        assert!(SelfIdentity::load(&path).unwrap().is_none());
        let created = SelfIdentity::load_or_create(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("AGE-SECRET-KEY-1"));
        assert!(text.contains(&format!("# public key: {}", created.recipient())));
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap()).unwrap().collect();
        assert_eq!(leftovers.len(), 1, "temp file left behind");
    }

    #[test]
    fn existing_identity_is_reused_not_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let path = self_identity_path(tmp.path());
        let first = SelfIdentity::load_or_create(&path).unwrap().recipient();
        let before = fs::read(&path).unwrap();
        let second = SelfIdentity::load_or_create(&path).unwrap().recipient();
        assert!(first == second);
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn loose_mode_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = self_identity_path(tmp.path());
        SelfIdentity::load_or_create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = SelfIdentity::load_or_create(&path).err().unwrap();
        assert!(err.to_string().contains("0600"), "{err}");
    }

    #[test]
    fn ssh_key_or_junk_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("identities");
        for content in [
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n",
            "",
            "# only a comment\n",
        ] {
            fs::write(&path, content).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let err = SelfIdentity::load(&path).err().unwrap();
            assert!(matches!(err, Error::Identity(_)), "{err:?}");
            assert!(!err.to_string().contains("OPENSSH"), "{err}");
        }
    }

    #[test]
    fn go_age_keygen_file_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("identities");
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/age/dave.txt");
        fs::copy(fixture, &path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let id = SelfIdentity::load(&path).unwrap().unwrap();
        let public = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/age/dave.pub"),
        )
        .unwrap();
        assert_eq!(id.recipient().to_string(), public.trim());
    }
}
