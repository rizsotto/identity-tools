//! Forge `add` and `remove`, the same for every forge (M2 plan, "Forge
//! add and remove"). Each write is decided by exact documented status
//! codes: 201 for a new key, 204 for a removed one. Anything else, a lost
//! answer included, is settled by listing again. A write is never sent
//! twice. The text of an error body is shown to the user but never
//! decides anything.

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use identity_core::{Fingerprint, PublicKey, SshPublicKey};
use inventory::{LocationKind, Purpose, Target};
use serde_json::Value;

use super::Listing;
use crate::error::ProviderError;
use crate::http::{HttpClient, HttpReply};
use crate::provider::{AddOpts, KeyRef, RemoveOpts};

/// Title length used for generated titles on a forge with no known limit.
const DEFAULT_TITLE_LIMIT: usize = 50;
/// Room kept in a generated title for ` YYYY-MM-DD` and a ` (NN)` suffix.
const TITLE_TAIL: usize = 16;
/// Longest forge message kept in an error.
const MAX_MESSAGE: usize = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Op {
    Add,
    Remove,
}

/// What differs between the forges.
#[async_trait]
pub(super) trait ForgeWrites: Send + Sync {
    fn kind(&self) -> LocationKind;

    /// The HTTP client for the account, after the token owner check.
    async fn session(&self, target: &Target) -> Result<HttpClient, ProviderError>;

    /// The account's SSH keys, all purposes.
    async fn ssh_keys(&self, client: &HttpClient) -> Result<Listing, ProviderError>;

    /// Path and JSON body of the `POST` that adds `key`.
    fn add_request(
        &self,
        key: &SshPublicKey,
        title: &str,
        purpose: Purpose,
        like: Option<&KeyRef>,
        listing: &Listing,
    ) -> (String, Value);

    /// Path of the `DELETE` for the remote object `id`.
    fn delete_path(&self, purpose: Purpose, id: &str) -> String;

    /// The token scopes the write needs, as advice for the user.
    fn scopes(&self, op: Op, purpose: Purpose) -> String;

    /// Longest title in characters, if the forge has a known limit.
    fn max_title(&self) -> Option<usize>;

    /// Refuses an add the forge cannot do, before the `POST`. The key is
    /// not listed for `purpose`.
    fn check_add(
        &self,
        _listing: &Listing,
        _key: &SshPublicKey,
        _purpose: Purpose,
    ) -> Result<(), ProviderError> {
        Ok(())
    }
}

pub(super) async fn add<F: ForgeWrites>(
    f: &F,
    target: &Target,
    key: &PublicKey,
    opts: &AddOpts,
) -> Result<(), ProviderError> {
    let key = match key {
        PublicKey::Ssh(k) if is_ssh(opts.purpose) => k,
        _ => return Err(unsupported(f.kind())),
    };
    let limit = f.max_title();
    if let (Some(t), Some(max)) = (&opts.title, limit)
        && t.chars().count() > max
    {
        return Err(ProviderError::Unsupported(format!(
            "the title is longer than {max} characters, the limit on {}",
            f.kind()
        )));
    }
    let client = f.session(target).await?;
    let listing = f.ssh_keys(&client).await?;
    check_usable(f.kind(), &listing, &key.fingerprint)?;
    if has(&listing, &key.fingerprint, opts.purpose) {
        return Ok(());
    }
    f.check_add(&listing, key, opts.purpose)?;
    let base = match &opts.title {
        Some(t) => t.clone(),
        None => default_title(key, &today_utc(), limit.unwrap_or(DEFAULT_TITLE_LIMIT)),
    };
    let title = free_title(&base, &listing, limit);
    let (path, body) = f.add_request(key, &title, opts.purpose, opts.like.as_ref(), &listing);
    let failure = match client.post_json(&path, &body).await {
        Ok(r) if r.status == 201 => return Ok(()),
        Ok(r) if r.status == 401 || r.status == 403 => {
            return Err(denied(f, r.status, Op::Add, opts.purpose));
        }
        Ok(r) => write_failed(f.kind(), &r),
        Err(e) => e,
    };
    // The answer may be lost, or the key was added meanwhile.
    let again = relist(f, &client, &failure).await?;
    if has(&again, &key.fingerprint, opts.purpose) {
        Ok(())
    } else {
        Err(failure)
    }
}

pub(super) async fn remove<F: ForgeWrites>(
    f: &F,
    target: &Target,
    key: &Fingerprint,
    opts: &RemoveOpts,
) -> Result<(), ProviderError> {
    if !is_ssh(opts.purpose) || !matches!(key, Fingerprint::Ssh(_)) {
        return Err(unsupported(f.kind()));
    }
    let client = f.session(target).await?;
    let listing = f.ssh_keys(&client).await?;
    let mut failure = None;
    for id in objects(f.kind(), &listing, key, opts.purpose)? {
        match client.delete(&f.delete_path(opts.purpose, &id)).await {
            Ok(r) if r.status == 204 => {}
            Ok(r) if r.status == 401 || r.status == 403 => {
                return Err(denied(f, r.status, Op::Remove, opts.purpose));
            }
            // 404 (already gone) is settled by the list below, like the rest.
            Ok(r) => {
                failure.get_or_insert(write_failed(f.kind(), &r));
            }
            Err(e) => {
                failure.get_or_insert(e);
            }
        }
    }
    let Some(failure) = failure else {
        return Ok(());
    };
    let again = relist(f, &client, &failure).await?;
    if objects(f.kind(), &again, key, opts.purpose)?.is_empty() {
        Ok(())
    } else {
        Err(failure)
    }
}

fn is_ssh(p: Purpose) -> bool {
    matches!(p, Purpose::SshAuth | Purpose::SshSigning)
}

fn unsupported(kind: LocationKind) -> ProviderError {
    ProviderError::Unsupported(format!(
        "only SSH keys for login or signing can be added to or removed from {kind}"
    ))
}

fn has(listing: &Listing, fpr: &Fingerprint, purpose: Purpose) -> bool {
    listing
        .keys
        .iter()
        .any(|k| k.purpose == purpose && &k.fingerprint == fpr)
}

/// The list after a write that gave no clear answer. If it fails too,
/// the error names both.
async fn relist<F: ForgeWrites>(
    f: &F,
    client: &HttpClient,
    failure: &ProviderError,
) -> Result<Listing, ProviderError> {
    f.ssh_keys(client)
        .await
        .map_err(|e| ProviderError::Unsettled {
            forge: f.kind(),
            write: failure.to_string(),
            list: e.to_string(),
        })
}

/// A listed key with this fingerprint that we cannot place (for example an
/// unknown GitLab usage type) stops any write: we cannot tell what it
/// serves.
fn check_usable(
    kind: LocationKind,
    listing: &Listing,
    fpr: &Fingerprint,
) -> Result<(), ProviderError> {
    match listing.unusable_ssh.iter().find(|(f, _)| f == fpr) {
        Some((_, why)) => Err(ProviderError::BadResponse {
            forge: kind,
            what: format!("the key is listed with {why}; change or remove it on the web"),
        }),
        None => Ok(()),
    }
}

/// Remote ids of the objects with this key and purpose, each once. A
/// matching object without a plain number id is an error, so a key is
/// never reported removed while it stays.
fn objects(
    kind: LocationKind,
    listing: &Listing,
    fpr: &Fingerprint,
    purpose: Purpose,
) -> Result<Vec<String>, ProviderError> {
    check_usable(kind, listing, fpr)?;
    let mut ids: Vec<String> = Vec::new();
    for k in &listing.keys {
        if k.purpose != purpose || &k.fingerprint != fpr {
            continue;
        }
        let id = k
            .remote_id
            .as_ref()
            .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| ProviderError::BadResponse {
                forge: kind,
                what: "a listed key with this fingerprint has no usable id".into(),
            })?;
        if !ids.contains(id) {
            ids.push(id.clone());
        }
    }
    Ok(ids)
}

fn denied<F: ForgeWrites>(f: &F, status: u16, op: Op, purpose: Purpose) -> ProviderError {
    let why = if status == 401 {
        "The token was not accepted; it may be expired or revoked."
    } else {
        "The token does not have the rights for this."
    };
    ProviderError::Denied {
        forge: f.kind(),
        status,
        advice: format!("{why} It needs {}.", f.scopes(op, purpose)),
    }
}

fn write_failed(forge: LocationKind, r: &HttpReply) -> ProviderError {
    ProviderError::WriteFailed {
        forge,
        status: r.status,
        message: message(&r.body),
    }
}

/// The forge's error text for the user. The body is already scrubbed of
/// the token by the HTTP client.
fn message(body: &Value) -> String {
    let text = match body {
        Value::Null => "no details".to_string(),
        Value::String(s) => s.clone(),
        _ => match (&body["message"], &body["error"]) {
            (Value::String(s), _) | (_, Value::String(s)) => s.clone(),
            (Value::Null, Value::Null) => body.to_string(),
            (m, Value::Null) => m.to_string(),
            (_, e) => e.to_string(),
        },
    };
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_MESSAGE)
        .collect()
}

/// `<comment> <YYYY-MM-DD>`, or `key-steward <YYYY-MM-DD>` without a
/// comment. The comment is cut so a ` (NN)` suffix still fits in `limit`.
fn default_title(key: &SshPublicKey, today: &str, limit: usize) -> String {
    let max_comment = limit.saturating_sub(TITLE_TAIL).max(1);
    let comment: String = key
        .comment_display()
        .map(|c| c.trim().chars().take(max_comment).collect::<String>())
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| "key-steward".into());
    format!("{comment} {today}")
}

/// `base`, or `base (2)`, `base (3)`, ... if a listed key has that title.
/// Forgejo and Gitea refuse a title the user already has. With a suffix,
/// `base` is cut so the title stays within `limit` characters.
fn free_title(base: &str, listing: &Listing, limit: Option<usize>) -> String {
    let taken = |t: &str| listing.keys.iter().any(|k| k.title.as_deref() == Some(t));
    if !taken(base) {
        return base.to_string();
    }
    (2..)
        .map(|n| {
            let suffix = format!(" ({n})");
            let keep = limit.map_or(usize::MAX, |l| l.saturating_sub(suffix.chars().count()));
            let cut: String = base.chars().take(keep).collect();
            cut + &suffix
        })
        .find(|t| !taken(t))
        .unwrap_or_else(|| base.to_string())
}

/// Today's date in UTC, `YYYY-MM-DD`.
fn today_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    civil_date((secs / 86_400) as i64)
}

/// The date `days` after 1970-01-01 (proleptic Gregorian), from Howard
/// Hinnant's `civil_from_days`.
fn civil_date(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::PublicKeyRef;
    use identity_core::parse_public_keys;
    use serde_json::json;

    fn ssh_key(line: &str) -> SshPublicKey {
        match parse_public_keys(line.as_bytes()).unwrap().remove(0).key {
            Ok(PublicKey::Ssh(k)) => k,
            other => panic!("{other:?}"),
        }
    }

    const BLOB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAMl5AYo+0XU3NureorqVJl9BQCzJ/7O6oQuY+n0zaV+";

    #[test]
    fn civil_dates() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(11_016), "2000-02-29");
        assert_eq!(civil_date(20_769), "2026-11-12");
        assert_eq!(civil_date(-1), "1969-12-31");
    }

    #[test]
    fn titles() {
        let k = ssh_key(&format!("{BLOB} me@laptop"));
        assert_eq!(default_title(&k, "2026-11-12", 50), "me@laptop 2026-11-12");
        let k = ssh_key(BLOB);
        assert_eq!(
            default_title(&k, "2026-11-12", 50),
            "key-steward 2026-11-12"
        );
        let long = "ж".repeat(80);
        let t = default_title(&ssh_key(&format!("{BLOB} {long}")), "2026-11-12", 50);
        assert!(t.chars().count() + " (99)".len() <= 50, "{t}");
        assert!(t.starts_with("жжж"), "{t}");

        let mut l = Listing::default();
        assert_eq!(free_title("a", &l, None), "a");
        for t in ["a", "a (2)"] {
            l.keys.push(PublicKeyRef {
                fingerprint: Fingerprint::Ssh("SHA256:x".into()),
                purpose: Purpose::SshAuth,
                title: Some(t.into()),
                remote_id: None,
            });
        }
        assert_eq!(free_title("a", &l, None), "a (3)");
        assert_eq!(free_title("a", &l, Some(5)), "a (3)");
        assert_eq!(free_title("b", &l, None), "b");
        l.keys[0].title = Some("ééé".into());
        assert_eq!(free_title("ééé", &l, Some(5)), "é (2)");
    }

    #[test]
    fn messages() {
        assert_eq!(
            message(&json!({ "message": "Validation Failed" })),
            "Validation Failed"
        );
        assert_eq!(
            message(&json!({ "error": "title is missing" })),
            "title is missing"
        );
        assert_eq!(
            message(&json!({ "message": { "key": ["has already been taken"] } })),
            r#"{"key":["has already been taken"]}"#
        );
        assert_eq!(message(&json!("a\nb")), "a b");
        assert_eq!(message(&Value::Null), "no details");
        assert_eq!(message(&json!("x".repeat(1000))).len(), MAX_MESSAGE);
    }
}
