//! The S-3 gate (plan.md, "S-3 gate"). [`remove_old`] is the only code
//! that calls a provider's remove with the old key, and it needs a
//! [`RemovePermit`], which only [`may_remove_old`] makes.

use std::fs;

use identity_core::Fingerprint;
use inventory::{Phase, Purpose, Rotation, RotationLocation};
use providers::{KeyRef, Provider, ProviderError, PublicKeyRef, RemoveOpts, VerifyStatus};

use crate::sites::{Providers, Removed};

/// Leave to remove the old key at one location, now. Not `Clone`: one
/// permit, one removal.
#[derive(Debug)]
pub(crate) struct RemovePermit {
    location: i64,
}

/// Leave to remove the new key at one location (abort with rollback).
#[derive(Debug)]
pub(crate) struct RollbackPermit {
    location: i64,
}

pub(crate) fn new_ref(rot: &Rotation, purpose: Purpose) -> Option<KeyRef> {
    rot.new_fingerprint.as_ref().map(|f| KeyRef {
        fingerprint: f.clone(),
        purpose,
        identity_file: Some(rot.new_key_path.clone()),
    })
}

pub(crate) fn old_ref(rot: &Rotation, purpose: Purpose) -> KeyRef {
    KeyRef {
        fingerprint: rot.old_fingerprint.clone(),
        purpose,
        identity_file: Some(rot.old_key_path.clone()),
    }
}

/// Every purpose served by the remote objects that a removal of `key`
/// for `purpose` deletes. A forge lists one entry per purpose with the
/// same `remote_id` when one object serves several (GitLab
/// `auth_and_signing`, Forgejo).
pub(crate) fn served_purposes(
    listed: &[PublicKeyRef],
    key: &Fingerprint,
    purpose: Purpose,
) -> Vec<Purpose> {
    let ids: Vec<&Option<String>> = listed
        .iter()
        .filter(|k| &k.fingerprint == key && k.purpose == purpose)
        .map(|k| &k.remote_id)
        .collect();
    let mut out = vec![purpose];
    for k in listed {
        let same_object = k.remote_id.is_some() && ids.contains(&&k.remote_id);
        if &k.fingerprint == key && same_object && !out.contains(&k.purpose) {
            out.push(k.purpose);
        }
    }
    out
}

pub(crate) fn listed(listed: &[PublicKeyRef], key: &Fingerprint, purpose: Purpose) -> bool {
    listed
        .iter()
        .any(|k| &k.fingerprint == key && k.purpose == purpose)
}

async fn verified(p: &dyn Provider, loc: &RotationLocation, key: &KeyRef) -> Result<(), String> {
    match p.verify(&loc.target, key).await {
        Ok(VerifyStatus::Verified) => Ok(()),
        Ok(v) => Err(status_text(&v)),
        Err(e) => Err(e.to_string()),
    }
}

pub(crate) fn status_text(v: &VerifyStatus) -> String {
    match v.to_status() {
        inventory::Status::Error(r) => r,
        s => s.as_str().to_string(),
    }
}

/// The S-3 gate. Every check runs now, in this process; nothing is read
/// from the journal:
///
/// 1. the new key is not the old key;
/// 2. the new private key file is still there;
/// 3. the location is `Verified`, and a verify of the new key there,
///    run right now, says `Verified`;
/// 4. for every purpose that the old key's remote object at this site
///    serves, the new key is verified for that purpose too, right now.
///
/// SSH: the removal itself logs in with the new key and keeps it in the
/// file (`RemoveOpts::keep`); if that login fails, nothing is removed.
pub(crate) async fn may_remove_old(
    providers: &dyn Providers,
    p: &dyn Provider,
    rot: &Rotation,
    loc: &RotationLocation,
) -> Result<RemovePermit, String> {
    let label = loc.target.label();
    let Some(new) = new_ref(rot, loc.purpose) else {
        return Err("the new key has not been made yet".into());
    };
    if new.fingerprint == rot.old_fingerprint {
        return Err("the new key has the same fingerprint as the old key".into());
    }
    if fs::symlink_metadata(&rot.new_key_path).is_err() {
        return Err(format!(
            "the new private key file {} is gone",
            rot.new_key_path.display()
        ));
    }
    if loc.phase != Phase::Verified {
        return Err(format!("{label} is {}, not verified", loc.phase.as_str()));
    }
    verified(p, loc, &new)
        .await
        .map_err(|e| format!("the new key does not log in at {label} right now: {e}"))?;
    let keys = providers
        .list_as(loc.kind, &loc.target, &new)
        .await
        .map_err(|e| format!("cannot list the keys at {label}: {e}"))?;
    for purpose in served_purposes(&keys, &rot.old_fingerprint, loc.purpose) {
        if purpose == loc.purpose {
            continue;
        }
        let key = KeyRef {
            purpose,
            ..new.clone()
        };
        verified(p, loc, &key).await.map_err(|e| {
            format!(
                "the old key's entry at {label} also serves {}, and the new key is not \
                 verified for it: {e}",
                purpose.as_str()
            )
        })?;
    }
    Ok(RemovePermit {
        location: loc.location_id,
    })
}

/// Removes the old key at `loc`. SSH logs in with the new key, which must
/// stay in the file.
pub(crate) async fn remove_old(
    providers: &dyn Providers,
    permit: RemovePermit,
    rot: &Rotation,
    loc: &RotationLocation,
) -> Result<Removed, ProviderError> {
    assert_eq!(
        permit.location, loc.location_id,
        "permit for another location"
    );
    let opts = RemoveOpts {
        purpose: loc.purpose,
        keep: new_ref(rot, loc.purpose),
    };
    providers
        .remove_key(loc.kind, &loc.target, &rot.old_fingerprint, &opts)
        .await
}

/// The rollback gate, the mirror of [`may_remove_old`]: the location is
/// not `OldRemoved`, the old key is listed there and logs in right now,
/// for every purpose the new key's remote object serves.
pub(crate) async fn may_roll_back(
    providers: &dyn Providers,
    p: &dyn Provider,
    rot: &Rotation,
    loc: &RotationLocation,
) -> Result<RollbackPermit, String> {
    let label = loc.target.label();
    if matches!(loc.phase, Phase::OldRemoved | Phase::RolledBack) {
        return Err(format!(
            "{label} is {}; the new key stays",
            loc.phase.as_str()
        ));
    }
    let Some(new) = &rot.new_fingerprint else {
        return Err("the new key has not been made yet".into());
    };
    let keys = providers
        .list_as(loc.kind, &loc.target, &old_ref(rot, loc.purpose))
        .await
        .map_err(|e| format!("cannot list the keys at {label}: {e}"))?;
    if !listed(&keys, &rot.old_fingerprint, loc.purpose) {
        return Err(format!(
            "the old key is not listed at {label}; the new key stays"
        ));
    }
    for purpose in served_purposes(&keys, new, loc.purpose) {
        verified(p, loc, &old_ref(rot, purpose))
            .await
            .map_err(|e| {
                format!(
                    "the old key does not log in at {label} right now, so the new key stays: {e}"
                )
            })?;
    }
    Ok(RollbackPermit {
        location: loc.location_id,
    })
}

/// Removes the new key at `loc`. SSH logs in with the old key, which must
/// stay in the file.
pub(crate) async fn roll_back(
    providers: &dyn Providers,
    permit: RollbackPermit,
    rot: &Rotation,
    loc: &RotationLocation,
) -> Result<Removed, ProviderError> {
    assert_eq!(
        permit.location, loc.location_id,
        "permit for another location"
    );
    let new = rot
        .new_fingerprint
        .as_ref()
        .expect("a rollback permit needs the new key");
    let opts = RemoveOpts {
        purpose: loc.purpose,
        keep: Some(old_ref(rot, loc.purpose)),
    };
    providers
        .remove_key(loc.kind, &loc.target, new, &opts)
        .await
}
