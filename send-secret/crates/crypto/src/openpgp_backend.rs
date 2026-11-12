//! OpenPGP backend over gpgme: sign and encrypt in one operation to a key
//! that is not imported (SPEC 15, F3), decrypt and verify. Armor is gpg's
//! own, unchanged (decision 0003). Data streams through gpgme callbacks
//! straight between the caller's reader and writer, so no plaintext temp
//! file and no plaintext buffer of ours exist (S-4, S-5).

use std::ffi::CString;
use std::io::{BufRead, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use gpgme::{Context, Data, EncryptFlags, ExportMode, Protocol, Validity};
use identity_core::{Fingerprint, Gpg, OpenPgpBackend};

use crate::age_backend::UntilArmorEnd;
use crate::plan::{OpenPgpCert, OpenPgpSelf};
use crate::recipient_file::RecipientFile;
use crate::{Error, Result};

const OPENPGP_END_MARKER: &[u8] = b"-----END PGP MESSAGE-----";

/// The user's own OpenPGP keys: the self copy key and the signer. Both are
/// the default secret key (`OpenPgpBackend::default_secret_key`), so they
/// can not differ.
#[derive(Debug, Clone)]
pub struct OpenPgpUser {
    pub self_key: OpenPgpSelf,
    /// Fingerprint of the default secret key, if it can sign.
    pub signer: Option<String>,
}

/// Finds the default secret key in `home` (`None`: gpg's own default,
/// `GNUPGHOME` or `~/.gnupg`). Nothing is changed in the keyring.
pub fn openpgp_user(home: Option<&Path>) -> Result<OpenPgpUser> {
    let Some(key) = gpg(home)?.default_secret_key().map_err(gpg_error)? else {
        return Ok(OpenPgpUser {
            self_key: OpenPgpSelf::NoSecretKey,
            signer: None,
        });
    };
    let fpr = key.fingerprint.as_str().to_owned();
    let self_key = if key.can_encrypt {
        let mut bytes = Vec::new();
        context(home)?
            .export([fpr.as_str()], ExportMode::empty(), &mut bytes)
            .map_err(op_error)?;
        OpenPgpSelf::CanEncrypt(OpenPgpCert::new(bytes)?)
    } else {
        OpenPgpSelf::CannotEncrypt
    };
    Ok(OpenPgpUser {
        self_key,
        signer: key.can_sign.then_some(fpr),
    })
}

/// One OpenPGP message, checked and ready: the recipient key file exists
/// and can encrypt, and the signer (if any) is set.
pub(crate) struct Prepared {
    ctx: Context,
    /// Kept alive until the operation is done: `recipients` names them.
    _files: Vec<RecipientFile>,
    recipients: CString,
    sign: bool,
}

/// gpg.conf options that add a recipient. `GPGME_ENCRYPT_NO_ENCRYPT_TO`
/// only turns off `encrypt-to` and `hidden-encrypt-to`. gpg takes no
/// abbreviated option names in gpg.conf (checked with gpg 2.4.9).
const ADDS_RECIPIENT: [&str; 4] = [
    "recipient",
    "hidden-recipient",
    "recipient-file",
    "hidden-recipient-file",
];

/// Refuses a gpg.conf that would add keys to the message, or (when
/// signing) a second signer, since gpgme can not turn those off (S-8).
/// Reads the same file gpg reads (versioned names first).
fn check_gpg_conf(gpg: &Gpg, sign: bool) -> Result<()> {
    let Some(file) = gpg.conf_file() else {
        return Ok(());
    };
    let mut bytes = Vec::new();
    match std::fs::File::open(&file) {
        Ok(f) => {
            f.take(identity_core::MAX_KEY_INPUT as u64)
                .read_to_end(&mut bytes)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    let text = String::from_utf8_lossy(&bytes);
    for line in text.lines() {
        let name = line
            .trim_start_matches([' ', '\t'])
            .split([' ', '\t'])
            .next()
            .unwrap_or_default();
        if ADDS_RECIPIENT.contains(&name) || (sign && name == "local-user") {
            return Err(Error::GpgConf {
                file,
                option: name.to_owned(),
            });
        }
    }
    Ok(())
}

/// Checks the keys, the user's gpg.conf and the signer before any output
/// is written. All `certs` go into one message (one person's keys, FR-4).
pub(crate) fn prepare(
    label: &str,
    certs: &[&OpenPgpCert],
    home: Option<&Path>,
    signer: Option<&str>,
    armor: bool,
) -> Result<Prepared> {
    let mut gpg = gpg(home)?;
    check_gpg_conf(&gpg, signer.is_some())?;
    let mut files = Vec::new();
    for cert in certs {
        let found = RecipientFile::all(&mut gpg, cert.as_bytes()).map_err(|e| Error::BadKey {
            label: label.to_owned(),
            reason: e.to_string(),
        })?;
        files.extend(found);
    }
    let recipients = RecipientFile::joined(&files);
    let mut ctx = context(home)?;
    ctx.set_armor(armor);
    if let Some(fpr) = signer {
        let key = ctx.get_secret_key(fpr).map_err(|_| Error::NoSigner)?;
        if !key.can_sign() {
            return Err(Error::NoSigner);
        }
        ctx.add_signer(&key).map_err(op_error)?;
    }
    Ok(Prepared {
        ctx,
        _files: files,
        recipients,
        sign: signer.is_some(),
    })
}

impl Prepared {
    /// Encrypts (and signs, if a signer was set) `input` to the recipient
    /// keys only. gpgme fails the operation if the signer can not sign
    /// (`GPG_ERR_UNUSABLE_SECKEY`). `GPGME_ENCRYPT_NO_ENCRYPT_TO` keeps
    /// gpg.conf `encrypt-to` keys out; `check_gpg_conf` refused the other
    /// options that add keys (S-8).
    pub(crate) fn encrypt(
        self,
        input: impl Read + Send,
        mut output: impl Write + Send,
    ) -> Result<()> {
        {
            let plain = Data::from_reader(input).map_err(|e| op_error(e.error()))?;
            let cipher = Data::from_writer(&mut output).map_err(|e| op_error(e.error()))?;
            let op = if self.sign {
                gpgme_sys::gpgme_op_encrypt_sign_ext
            } else {
                gpgme_sys::gpgme_op_encrypt_ext
            };
            // SAFETY: `self.ctx`, `plain` and `cipher` are live gpgme objects
            // owned by safe wrappers that outlive the call. Both functions
            // take the same arguments. A null key array is allowed with a
            // recipient string; the string is the NUL-terminated
            // `--file\n<path>` lines from `RecipientFile::joined` (paths
            // checked there), owned by `self` past the call, and the files
            // it names live in `self._files`.
            let err = unsafe {
                op(
                    self.ctx.as_raw(),
                    std::ptr::null_mut(),
                    self.recipients.as_ptr(),
                    EncryptFlags::NO_ENCRYPT_TO.bits(),
                    plain.as_raw(),
                    cipher.as_raw(),
                )
            };
            if err != 0 {
                return Err(op_error(gpgme::Error::new(err)));
            }
        }
        output.flush()?;
        Ok(())
    }
}

/// How a signature checked out. A bad signature is an error, not a status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureStatus {
    Good,
    /// The signer's public key is not in the keyring, so it was not checked.
    UnknownKey,
    KeyExpired,
    KeyRevoked,
    SignatureExpired,
    /// gpg could not check it for another reason.
    NotChecked,
}

/// How much the keyring trusts the signer's key (gpg's key validity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerValidity {
    Unknown,
    Never,
    Marginal,
    Full,
    Ultimate,
}

/// The signer of a decrypted OpenPGP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    /// As gpg reports it: the full fingerprint, or a key ID for old
    /// signatures without one.
    pub fingerprint: Fingerprint,
    pub status: SignatureStatus,
    pub validity: SignerValidity,
}

/// Decrypts one OpenPGP message starting at the first byte of `input`.
/// Armored input is cut after the END line; the result's bool says if
/// another message follows. Returns the first signer, if signed.
///
/// gpg writes plaintext before it checks the integrity tag at the end, so
/// on an error the caller must throw away what was written.
pub(crate) fn decrypt(
    input: impl BufRead + Send,
    mut output: impl Write + Send,
    armored: bool,
    home: Option<&Path>,
) -> Result<(Option<Signer>, bool)> {
    let mut ctx = context(home)?;
    let more = Arc::new(AtomicBool::new(false));
    let result = {
        let cipher = if armored {
            Data::from_reader(UntilArmorEnd::new(
                input,
                OPENPGP_END_MARKER,
                Arc::clone(&more),
            ))
            .map_err(|e| op_error(e.error()))?
        } else {
            Data::from_reader(input).map_err(|e| op_error(e.error()))?
        };
        let plain = Data::from_writer(&mut output).map_err(|e| op_error(e.error()))?;
        ctx.decrypt_and_verify(cipher, plain)
    };
    let (_, verification) = result.map_err(map_decrypt_error)?;
    output.flush()?;
    let mut signer = None;
    for sig in verification.signatures() {
        let status = match sig.status() {
            Ok(()) => SignatureStatus::Good,
            Err(e) => match e.code() {
                c if c == gpgme::Error::BAD_SIGNATURE.code() => return Err(Error::BadSignature),
                c if c == gpgme::Error::NO_PUBKEY.code() => SignatureStatus::UnknownKey,
                c if c == gpgme::Error::KEY_EXPIRED.code() => SignatureStatus::KeyExpired,
                c if c == gpgme::Error::CERT_REVOKED.code() => SignatureStatus::KeyRevoked,
                c if c == gpgme::Error::SIG_EXPIRED.code() => SignatureStatus::SignatureExpired,
                _ => SignatureStatus::NotChecked,
            },
        };
        signer.get_or_insert(Signer {
            fingerprint: Fingerprint::OpenPgp(sig.fingerprint().unwrap_or_default().to_uppercase()),
            status,
            validity: match sig.validity() {
                Validity::Never => SignerValidity::Never,
                Validity::Marginal => SignerValidity::Marginal,
                Validity::Full => SignerValidity::Full,
                Validity::Ultimate => SignerValidity::Ultimate,
                _ => SignerValidity::Unknown,
            },
        });
    }
    Ok((signer, more.load(Ordering::Relaxed)))
}

fn map_decrypt_error(e: gpgme::Error) -> Error {
    let code = e.code();
    let is = |known: gpgme::Error| code == known.code();
    if is(gpgme::Error::NO_SECKEY) {
        Error::NoMatchingKey
    } else if is(gpgme::Error::BAD_PASSPHRASE) || is(gpgme::Error::CANCELED) {
        Error::KeyLocked
    } else if is(gpgme::Error::DECRYPT_FAILED)
        || is(gpgme::Error::BAD_DATA)
        || is(gpgme::Error::NO_DATA)
    {
        Error::Corrupt
    } else {
        op_error(e)
    }
}

fn context(home: Option<&Path>) -> Result<Context> {
    let mut ctx = Context::from_protocol(Protocol::OpenPgp).map_err(op_error)?;
    if let Some(home) = home {
        let home = CString::new(home.as_os_str().as_bytes())
            .map_err(|_| Error::OpenPgp("unsafe GnuPG home dir path".into()))?;
        ctx.set_engine_home_dir(home).map_err(op_error)?;
    }
    Ok(ctx)
}

fn gpg(home: Option<&Path>) -> Result<Gpg> {
    match home {
        Some(home) => Gpg::with_home(home),
        None => Gpg::user_default(),
    }
    .map_err(gpg_error)
}

fn gpg_error(e: identity_core::GpgError) -> Error {
    Error::OpenPgp(e.to_string())
}

/// gpgme error text comes from libgpg-error: fixed strings, no data.
fn op_error(e: gpgme::Error) -> Error {
    Error::OpenPgp(e.to_string())
}
