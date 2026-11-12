//! Shared steps for network sources: fetched bytes to [`FoundKey`]s.
//! Every fetched byte is hostile (S-7). Errors never hold fetched bytes.

use identity_core::{Gpg, GpgError, KeyAlgo, OpenPgpKey, ParsedLine, PublicKey, parse_public_keys};
use tokio::time::{Instant, timeout_at};

use crate::model::{
    Found, FoundKey, KeyBytes, RejectReason, Rejected, Source, SourceError, Unusable,
};
use crate::net::{Fetched, Net};

/// The `Net` of a network source, or the error when lookups are off.
pub(crate) fn need_net(net: Option<&Net>) -> Result<&Net, SourceError> {
    net.ok_or_else(|| SourceError::Net("network lookups are off for this resolver".into()))
}

/// Where a fetched answer came from (S-3): the final URL, and the first one
/// when a redirect changed it.
pub(crate) fn source_of(kind: crate::SourceKind, fetched: &Fetched) -> Source {
    Source {
        kind,
        location: fetched.url.to_string(),
        first_url: (fetched.url != fetched.first_url).then(|| fetched.first_url.to_string()),
    }
}

/// An `authorized_keys` style list (`.keys`). Keys age can not use are kept
/// with their note (FR-4); lines that are no key become rejects.
pub(crate) fn ssh_list(body: &[u8], source: &Source) -> Result<Found, SourceError> {
    let lines = parse_public_keys(body).map_err(|e| SourceError::Malformed(e.to_string()))?;
    let mut found = Found::default();
    for ParsedLine { line, key } in lines {
        match key {
            Ok(key) => {
                let (bytes, usable) = match &key {
                    PublicKey::Ssh(k) => (KeyBytes::Ssh(k.encoded.clone()), ssh_usable(&k.algo)),
                    PublicKey::Age(k) => (KeyBytes::Age(k.as_str().to_string()), Ok(())),
                    PublicKey::OpenPgp(_) => continue,
                };
                found.keys.push(FoundKey {
                    key,
                    bytes,
                    source: source.clone(),
                    usable,
                    shown_user_ids: Vec::new(),
                });
            }
            Err(error) => found.rejected.push(Rejected {
                fingerprint: None,
                source: source.clone(),
                reason: RejectReason::BadLine { line, error },
            }),
        }
    }
    Ok(found)
}

fn ssh_usable(algo: &KeyAlgo) -> Result<(), Unusable> {
    match algo {
        KeyAlgo::Ed25519 => Ok(()),
        KeyAlgo::Rsa(bits) if (2048..=4096).contains(bits) => Ok(()),
        KeyAlgo::Rsa(bits) => Err(Unusable::RsaSize(*bits)),
        KeyAlgo::Ecdsa(_) => Err(Unusable::EcdsaNotAge),
        KeyAlgo::SkEd25519 | KeyAlgo::SkEcdsa(_) => Err(Unusable::SkKey),
        _ => Err(Unusable::SshType),
    }
}

/// The keys in an OpenPGP blob, one export each. Runs gpg on a blocking
/// thread under `deadline`, as its time grows with the packets. More keys
/// than identity-core allows give one [`RejectReason::TooManyKeys`].
pub(crate) async fn split_blob(
    body: Vec<u8>,
    source: &Source,
    deadline: Instant,
) -> Result<SplitBlob, SourceError> {
    let task = tokio::task::spawn_blocking(move || Gpg::split_keys(&body));
    match timeout_at(deadline, task).await {
        Err(_) => Err(SourceError::Timeout),
        Ok(Err(_)) => Err(SourceError::Malformed("reading the keys failed".into())),
        Ok(Ok(Ok(keys))) => Ok(SplitBlob::Keys(keys)),
        Ok(Ok(Err(GpgError::TooManyKeys { .. }))) => Ok(SplitBlob::TooMany(Rejected {
            fingerprint: None,
            source: source.clone(),
            reason: RejectReason::TooManyKeys,
        })),
        Ok(Ok(Err(GpgError::TooLarge { .. }))) => Err(SourceError::TooLarge),
        Ok(Ok(Err(e))) => Err(SourceError::Malformed(e.to_string())),
    }
}

pub(crate) enum SplitBlob {
    Keys(Vec<(OpenPgpKey, Vec<u8>)>),
    TooMany(Rejected),
}

/// One split OpenPGP key as a [`FoundKey`], showing `shown_user_ids`.
pub(crate) fn openpgp_found(
    key: OpenPgpKey,
    bytes: Vec<u8>,
    source: &Source,
    shown_user_ids: Vec<identity_core::UserId>,
) -> FoundKey {
    let usable = openpgp_usable(&key);
    FoundKey {
        key: PublicKey::OpenPgp(key),
        bytes: KeyBytes::OpenPgp(bytes),
        source: source.clone(),
        usable,
        shown_user_ids,
    }
}

fn openpgp_usable(key: &OpenPgpKey) -> Result<(), Unusable> {
    if key.revoked {
        return Err(Unusable::Revoked);
    }
    if key.expired {
        return Err(Unusable::Expired);
    }
    if key.can_encrypt && !key.disabled && !key.invalid {
        return Ok(());
    }
    let mut enc = key.subkeys.iter().filter(|s| s.can_encrypt).peekable();
    if enc.peek().is_some() && enc.all(|s| s.expired && !s.revoked) {
        return Err(Unusable::Expired);
    }
    Err(Unusable::NoEncryptionSubkey)
}
