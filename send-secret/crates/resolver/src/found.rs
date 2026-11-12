//! Shared steps for sources: fetched or pasted bytes to [`FoundKey`]s.
//! Every fetched byte is hostile (S-7). Errors never hold fetched bytes.

use identity_core::{
    Gpg, GpgError, KeyAlgo, KeyError, OpenPgpKey, ParsedLine, PublicKey, UserId, parse_public_keys,
};
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
/// with their note (FR-4); lines that are no key become rejects next to
/// good keys. An answer with bad lines and no key at all (a captive portal
/// page, an HTML error) is malformed.
pub(crate) fn ssh_list(body: &[u8], source: &Source) -> Result<Found, SourceError> {
    let lines = parse_public_keys(body).map_err(|e| match e {
        KeyError::TooLarge { .. } => SourceError::TooLarge,
        e => SourceError::Malformed(e.to_string()),
    })?;
    let mut found = Found::default();
    for ParsedLine { line, key } in lines {
        match key {
            Ok(key) => {
                let bytes = match &key {
                    PublicKey::Ssh(k) => KeyBytes::Ssh(k.encoded.clone()),
                    PublicKey::Age(k) => KeyBytes::Age(k.as_str().to_string()),
                    PublicKey::OpenPgp(_) => continue,
                };
                found.keys.push(FoundKey {
                    usable: age_usable(&key),
                    key,
                    bytes,
                    source: source.clone(),
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
    if found.keys.is_empty() && !found.rejected.is_empty() {
        return Err(SourceError::Malformed("no key in the answer".into()));
    }
    Ok(found)
}

/// The FR-4 skip note for an SSH key or age recipient.
pub(crate) fn age_usable(key: &PublicKey) -> Result<(), Unusable> {
    if key.is_age_recipient() {
        return Ok(());
    }
    Err(match key.algo() {
        KeyAlgo::Ecdsa(_) => Unusable::EcdsaNotAge,
        KeyAlgo::SkEd25519 | KeyAlgo::SkEcdsa(_) => Unusable::SkKey,
        KeyAlgo::Rsa(bits) => Unusable::RsaSize(bits),
        _ => Unusable::SshType,
    })
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
        Ok(Ok(Err(e @ GpgError::TooComplex { .. }))) => Err(SourceError::Malformed(e.to_string())),
        Ok(Ok(Err(_))) => Err(SourceError::Malformed("not a valid OpenPGP key".into())),
    }
}

/// What splitting a blob gave.
pub(crate) enum SplitBlob {
    Keys(Vec<(OpenPgpKey, Vec<u8>)>),
    TooMany(Rejected),
}

/// One split OpenPGP key as a [`FoundKey`], showing `shown_user_ids`.
pub(crate) fn openpgp_found(
    key: OpenPgpKey,
    bytes: Vec<u8>,
    source: &Source,
    shown_user_ids: Vec<UserId>,
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

/// The FR-4 skip note for an OpenPGP key, or `Ok` when it can be
/// encrypted to: a subkey that can encrypt and is neither expired nor
/// revoked.
pub(crate) fn openpgp_usable(key: &OpenPgpKey) -> Result<(), Unusable> {
    if key.revoked {
        return Err(Unusable::Revoked);
    }
    if key.expired {
        return Err(Unusable::Expired);
    }
    if key.disabled || key.invalid {
        return Err(Unusable::Disabled);
    }
    let enc = || key.subkeys.iter().filter(|s| s.can_encrypt && !s.revoked);
    if enc().any(|s| !s.expired) {
        return Ok(());
    }
    if enc().any(|s| s.expired) {
        return Err(Unusable::Expired);
    }
    Err(Unusable::NoEncryptionSubkey)
}

/// User IDs that are not revoked and not invalid.
pub(crate) fn valid_user_ids(key: &OpenPgpKey) -> Vec<UserId> {
    key.user_ids
        .iter()
        .filter(|u| !u.revoked && !u.invalid)
        .cloned()
        .collect()
}

/// S-6 for WKD and keys.openpgp.org: keep a key only if a valid user ID has
/// the queried email. Other user IDs are dropped from the summary too, so
/// they are never shown or stored. Keys without a match are rejected.
pub(crate) fn keep_matching(
    keys: Vec<(OpenPgpKey, Vec<u8>)>,
    email: &str,
    source: &Source,
    found: &mut Found,
) {
    for (mut key, bytes) in keys {
        let shown: Vec<_> = key
            .user_ids
            .iter()
            .filter(|u| u.has_email(email))
            .cloned()
            .collect();
        if shown.is_empty() {
            found.rejected.push(Rejected {
                fingerprint: Some(key.fingerprint.clone()),
                source: source.clone(),
                reason: RejectReason::EmailMismatch,
            });
        } else {
            key.user_ids = shown.clone();
            found.keys.push(openpgp_found(key, bytes, source, shown));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity_core::{Fingerprint, MAX_KEY_INPUT, OpenPgpSubkey, SshPublicKey};

    fn subkey(can_encrypt: bool, expired: bool, revoked: bool) -> OpenPgpSubkey {
        OpenPgpSubkey {
            algo: KeyAlgo::Cv25519,
            fingerprint: Fingerprint::OpenPgp("B".repeat(40)),
            created: None,
            expiry: None,
            can_encrypt,
            can_sign: false,
            can_certify: false,
            can_authenticate: false,
            revoked,
            expired,
        }
    }

    fn key(subkeys: Vec<OpenPgpSubkey>) -> OpenPgpKey {
        OpenPgpKey {
            algo: KeyAlgo::Ed25519,
            fingerprint: Fingerprint::OpenPgp("A".repeat(40)),
            created: None,
            expiry: None,
            user_ids: Vec::new(),
            subkeys,
            can_encrypt: true,
            can_sign: true,
            revoked: false,
            expired: false,
            disabled: false,
            invalid: false,
        }
    }

    #[test]
    fn openpgp_usable_rules() {
        let primary = subkey(false, false, false);
        let good = subkey(true, false, false);
        let old = subkey(true, true, false);
        let gone = subkey(true, false, true);
        let cases = [
            (vec![primary.clone(), good.clone()], Ok(())),
            (vec![primary.clone(), old.clone(), good.clone()], Ok(())),
            (vec![primary.clone(), old.clone()], Err(Unusable::Expired)),
            (
                vec![primary.clone(), gone.clone()],
                Err(Unusable::NoEncryptionSubkey),
            ),
            (vec![primary.clone()], Err(Unusable::NoEncryptionSubkey)),
        ];
        for (subkeys, want) in cases {
            assert_eq!(openpgp_usable(&key(subkeys.clone())), want, "{subkeys:?}");
        }
        let mut k = key(vec![primary.clone(), good.clone()]);
        k.disabled = true;
        assert_eq!(openpgp_usable(&k), Err(Unusable::Disabled));
        k.disabled = false;
        k.invalid = true;
        assert_eq!(openpgp_usable(&k), Err(Unusable::Disabled));
        k.expired = true;
        assert_eq!(openpgp_usable(&k), Err(Unusable::Expired));
        k.revoked = true;
        assert_eq!(openpgp_usable(&k), Err(Unusable::Revoked));
    }

    #[test]
    fn dsa_and_unknown_ssh_types_get_a_note() {
        for algo in [KeyAlgo::Dsa(1024), KeyAlgo::Other("x".into())] {
            let k = PublicKey::Ssh(SshPublicKey {
                algo,
                fingerprint: Fingerprint::Ssh("SHA256:x".into()),
                comment: None,
                encoded: "x y".into(),
            });
            assert_eq!(age_usable(&k), Err(Unusable::SshType));
        }
    }

    fn source() -> Source {
        Source {
            kind: crate::SourceKind::GitLab,
            location: "test".into(),
            first_url: None,
        }
    }

    #[test]
    fn ssh_list_over_1mb_is_too_large() {
        let body = vec![b'#'; MAX_KEY_INPUT + 1];
        assert_eq!(ssh_list(&body, &source()), Err(SourceError::TooLarge));
    }
}
