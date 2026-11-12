//! Plan and pre-flight: the dry-run (FR-10, S-7, plan.md "Plan and
//! pre-flight").
//!
//! Only reads: the ssh dir, the store, the ssh config, and each location
//! through its provider (a test login with the old key, the
//! `authorized_keys` read script, the forge key lists). Nothing is
//! written anywhere, the database included.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use identity_core::{Fingerprint, scan_ssh_dir};
use inventory::{
    Location, LocationId, LocationKind, NewRotation, Purpose, Store, StoreError, Target,
};
use providers::{KeyRef, PublicKeyRef, VerifyStatus};
use serde_json::{Value, json};

use crate::config::{ConfigMode, ConfigPlan, ListedLine, change_text, plan_config_change};
use crate::engine::EngineEnv;
use crate::files::{RETIRED_DIR, file_name, pub_path};
use crate::gate::{served_purposes, status_text};
use crate::keygen::{KeyType, Passphrase, read_public};
use crate::sites::Providers;

/// Stamp for the dry-run's config plan. Never written.
const PLAN_STAMP: &str = "dry-run";
/// Longest options text shown for one `authorized_keys` line.
const MAX_OPTIONS: usize = 200;

/// What the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRequest {
    /// The old key: a path (private or `.pub`) or a `SHA256:` fingerprint.
    pub key: String,
    pub key_type: KeyType,
    /// Default: `<old path>-<YYYYMMDD>`.
    pub new_path: Option<PathBuf>,
    /// Locations the user leaves out. The old key stays there.
    pub skip: Vec<LocationId>,
    pub update_config: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Pre-flight said no. Nothing was changed.
    #[error("{0}")]
    Refused(String),
}

/// One action at one location, in the order the rotation runs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// SSH: log in with the old key, insert the new key after this line
    /// with the same options.
    SshAdd {
        after_line: usize,
        options: Option<String>,
    },
    /// SSH: test login with the new key.
    SshVerify,
    /// SSH: log in with the new key (checked again right before), drop
    /// this line.
    SshRemove { line: usize },
    /// SSH: after the removal, a login with the old key must fail.
    SshOldRefused,
    /// Forge request. `path` is under the forge's API root.
    Http {
        method: &'static str,
        path: String,
        note: Option<String>,
    },
    /// Forge: the new key is in the key list.
    ForgeVerify,
}

impl Action {
    fn step(&self) -> &'static str {
        match self {
            Action::Http { method: "GET", .. } => "owner_check",
            Action::SshAdd { .. } => "install",
            Action::Http { method: "POST", .. } => "install",
            Action::SshVerify | Action::ForgeVerify => "verify",
            Action::SshRemove { .. } | Action::Http { .. } => "remove_old",
            Action::SshOldRefused => "check_old_refused",
        }
    }

    fn text(&self) -> String {
        match self {
            Action::SshAdd {
                after_line,
                options,
            } => {
                let opts = match options {
                    Some(o) => format!("with the same options ({o})"),
                    None => "without options, as on that line".into(),
                };
                format!(
                    "~/.ssh/authorized_keys: add the new key after line {after_line} {opts} \
                     (logs in with the old key; backup kept on the server)"
                )
            }
            Action::SshVerify => "test login with the new key".into(),
            Action::SshRemove { line } => format!(
                "~/.ssh/authorized_keys: remove line {line} (the old key), after a fresh test \
                 login with the new key; logs in with the new key"
            ),
            Action::SshOldRefused => "check that the old key no longer logs in".into(),
            Action::Http { method, path, note } => match note {
                Some(n) => format!("{method} {path} ({n})"),
                None => format!("{method} {path}"),
            },
            Action::ForgeVerify => "check that the forge lists the new key".into(),
        }
    }

    fn json(&self) -> Value {
        let mut v = json!({ "step": self.step(), "text": self.text() });
        match self {
            Action::SshAdd {
                after_line,
                options,
            } => {
                v["file"] = json!("~/.ssh/authorized_keys");
                v["after_line"] = json!(after_line);
                v["options"] = json!(options);
            }
            Action::SshRemove { line } => {
                v["file"] = json!("~/.ssh/authorized_keys");
                v["line"] = json!(line);
            }
            Action::Http { method, path, .. } => {
                v["method"] = json!(method);
                v["path"] = json!(path);
            }
            _ => {}
        }
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The rotation changes this location.
    Rotate(Vec<Action>),
    /// Left out by the user. The old key stays.
    Skipped,
    /// Pre-flight found a reason not to touch it. The old key stays.
    NotRotated(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanLocation {
    pub id: LocationId,
    pub kind: LocationKind,
    pub target: Target,
    pub purpose: Purpose,
    pub outcome: Outcome,
    /// Facts for the user: token scopes, `cert-authority` lines.
    pub notes: Vec<String>,
}

/// A line the retire step drops from the ssh config (in the file as the
/// config step leaves it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedLine {
    pub path: PathBuf,
    pub line: usize,
    pub text: String,
}

/// The dry-run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub old_fingerprint: Fingerprint,
    pub old_path: PathBuf,
    pub new_path: PathBuf,
    pub key_type: KeyType,
    pub update_config: bool,
    /// The `ssh-keygen` run, as text.
    pub keygen: String,
    pub locations: Vec<PlanLocation>,
    /// Config step (before any removal): new lines above the old ones.
    pub config: ConfigPlan,
    /// Retire step: the old lines the config step paired.
    pub config_at_retire: Vec<DroppedLine>,
    /// Lines with `%` tokens: shown, never changed.
    pub config_listed: Vec<ListedLine>,
    /// The old key files and where retire moves them.
    pub retire: Vec<(PathBuf, PathBuf)>,
    /// Why retire will not run, if known now.
    pub retire_blocked: Vec<String>,
    pub warnings: Vec<String>,
}

impl Plan {
    /// The locations the rotation changes.
    pub fn rotated(&self) -> Vec<LocationId> {
        self.locations
            .iter()
            .filter(|l| matches!(l.outcome, Outcome::Rotate(_)))
            .map(|l| l.id)
            .collect()
    }

    /// The rotation row `rotate start` writes after the user confirmed.
    pub fn new_rotation(&self) -> NewRotation {
        NewRotation {
            old_fingerprint: self.old_fingerprint.clone(),
            old_key_path: self.old_path.clone(),
            new_key_path: self.new_path.clone(),
            new_key_type: self.key_type.as_str().into(),
            update_config: self.update_config,
            state: String::new(),
            locations: self.rotated(),
        }
    }

    pub fn render_text(&self) -> String {
        let mut s = String::new();
        let line = |s: &mut String, t: String| {
            s.push_str(&t);
            s.push('\n');
        };
        line(&mut s, "Dry-run: nothing has been changed.".into());
        line(
            &mut s,
            format!(
                "Old key: {} ({})",
                self.old_path.display(),
                self.old_fingerprint
            ),
        );
        line(
            &mut s,
            format!(
                "New key: {} ({})",
                self.new_path.display(),
                self.key_type.as_str()
            ),
        );
        line(&mut s, String::new());
        line(&mut s, "1. Make the new key:".into());
        line(&mut s, format!("   {}", self.keygen));

        let rotated: Vec<&PlanLocation> = self
            .locations
            .iter()
            .filter(|l| matches!(l.outcome, Outcome::Rotate(_)))
            .collect();
        line(&mut s, String::new());
        line(
            &mut s,
            format!(
                "2. Locations that will be changed ({}): all installs, then all checks, \
                 then the config step, then all removals.",
                rotated.len()
            ),
        );
        for l in &rotated {
            line(&mut s, format!("   [{}] {}", l.id, describe(l)));
            if let Outcome::Rotate(actions) = &l.outcome {
                for a in actions {
                    line(&mut s, format!("       {:<17} {}", a.step(), a.text()));
                }
            }
            for n in &l.notes {
                line(&mut s, format!("       note: {n}"));
            }
        }
        let untouched: Vec<&PlanLocation> = self
            .locations
            .iter()
            .filter(|l| !matches!(l.outcome, Outcome::Rotate(_)))
            .collect();
        if !untouched.is_empty() {
            line(
                &mut s,
                "   Not touched (the old key stays there):".to_string(),
            );
            for l in &untouched {
                let why = match &l.outcome {
                    Outcome::Skipped => "skipped (--skip)".to_string(),
                    Outcome::NotRotated(r) => r.clone(),
                    Outcome::Rotate(_) => unreachable!(),
                };
                line(&mut s, format!("   [{}] {}: {why}", l.id, describe(l)));
                for n in &l.notes {
                    line(&mut s, format!("       note: {n}"));
                }
            }
        }

        line(&mut s, String::new());
        if self.update_config {
            line(
                &mut s,
                "3. ssh config, in two phases so it always names a key each host accepts:".into(),
            );
            if self.config.is_empty() {
                line(&mut s, "   no IdentityFile line names the old key.".into());
            } else {
                line(
                    &mut s,
                    format!(
                        "   a) before any removal: add `IdentityFile {}` above each line \
                         with the old key (backup kept):",
                        self.new_path.display()
                    ),
                );
                for d in self.config.diff().lines() {
                    line(&mut s, format!("      {d}"));
                }
                line(
                    &mut s,
                    "   b) at retire: remove the old lines (only if retire runs):".into(),
                );
                for d in &self.config_at_retire {
                    line(
                        &mut s,
                        format!("      {}:{}: -{}", d.path.display(), d.line, d.text),
                    );
                }
            }
        } else {
            line(
                &mut s,
                "3. ssh config: not changed (no --update-config).".into(),
            );
        }
        for l in &self.config_listed {
            line(
                &mut s,
                format!(
                    "   left alone (has % tokens): {}:{}: {}",
                    l.path.display(),
                    l.line,
                    l.text
                ),
            );
        }

        line(&mut s, String::new());
        line(
            &mut s,
            "4. Retire, after every removal and your confirm (never deleted):".into(),
        );
        for (from, to) in &self.retire {
            line(
                &mut s,
                format!(
                    "   move {} -> {} (a -N suffix if the name is taken)",
                    from.display(),
                    to.display()
                ),
            );
        }
        for r in &self.retire_blocked {
            line(&mut s, format!("   will not run: {r}"));
        }

        if !self.warnings.is_empty() {
            line(&mut s, String::new());
            for w in &self.warnings {
                line(&mut s, format!("Warning: {w}"));
            }
        }
        s
    }

    pub fn to_json(&self) -> Value {
        let locations: Vec<Value> = self
            .locations
            .iter()
            .map(|l| {
                let (outcome, reason, actions) = match &l.outcome {
                    Outcome::Rotate(a) => ("rotate", None, a.iter().map(Action::json).collect()),
                    Outcome::Skipped => ("skipped", None, Vec::new()),
                    Outcome::NotRotated(r) => ("not_rotated", Some(r.clone()), Vec::new()),
                };
                json!({
                    "id": l.id,
                    "kind": l.kind.as_str(),
                    "target": l.target.label(),
                    "purpose": l.purpose.as_str(),
                    "outcome": outcome,
                    "reason": reason,
                    "actions": actions,
                    "notes": l.notes,
                })
            })
            .collect();
        let insert: Vec<Value> = self
            .config
            .files
            .iter()
            .flat_map(|f| {
                f.changes.iter().map(|c| {
                    json!({
                        "file": f.path,
                        "line": c.line,
                        "before": c.before,
                        "after": c.after.lines().collect::<Vec<_>>(),
                    })
                })
            })
            .collect();
        let at_retire: Vec<Value> = self
            .config_at_retire
            .iter()
            .map(|d| json!({ "file": d.path, "line": d.line, "remove": d.text }))
            .collect();
        let listed: Vec<Value> = self
            .config_listed
            .iter()
            .map(|l| json!({ "file": l.path, "line": l.line, "text": l.text }))
            .collect();
        json!({
            "dry_run": true,
            "old_key": { "path": self.old_path, "fingerprint": self.old_fingerprint.as_str() },
            "new_key": { "path": self.new_path, "type": self.key_type.as_str() },
            "keygen": self.keygen,
            "locations": locations,
            "config": {
                "update": self.update_config,
                "insert_before_removals": insert,
                "remove_at_retire": at_retire,
                "left_alone": listed,
            },
            "retire": {
                "moves": self.retire.iter().map(|(f, t)| json!({ "from": f, "to": t })).collect::<Vec<_>>(),
                "blocked": self.retire_blocked,
            },
            "warnings": self.warnings,
        })
    }
}

fn describe(l: &PlanLocation) -> String {
    format!(
        "{} {} ({})",
        l.kind.as_str(),
        l.target.label(),
        l.purpose.as_str()
    )
}

/// A key in the ssh dir, by path (private or `.pub`) or `SHA256:`
/// fingerprint: its private path and fingerprint. The key must have a
/// private key file (never opened, S-1).
pub fn find_key(ssh_dir: &Path, key: &str) -> Result<(PathBuf, Fingerprint), PlanError> {
    let scan = scan_ssh_dir(ssh_dir).map_err(|e| {
        PlanError::Refused(format!(
            "cannot read the ssh dir {}: {e}",
            ssh_dir.display()
        ))
    })?;
    let by_fpr = key.starts_with("SHA256:");
    let wanted = (!by_fpr).then(|| {
        let p = Path::new(key);
        let p = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        match p.to_str().and_then(|s| s.strip_suffix(".pub")) {
            Some(s) => PathBuf::from(s),
            None => p,
        }
    });
    let mut hits = Vec::new();
    for file in &scan.keys {
        let Ok(k) = &file.key else { continue };
        let Some(private) = &file.private_path else {
            continue;
        };
        let hit = match &wanted {
            None => k.fingerprint.as_str() == key,
            Some(w) => std::fs::canonicalize(private).is_ok_and(|p| &p == w),
        };
        if hit {
            hits.push((private.clone(), k.fingerprint.clone()));
        }
    }
    if hits.len() > 1 {
        let paths: Vec<String> = hits.iter().map(|h| h.0.display().to_string()).collect();
        return Err(PlanError::Refused(format!(
            "several key files hold {key} ({}); name the one to rotate by its path",
            paths.join(", ")
        )));
    }
    if let Some(hit) = hits.pop() {
        return Ok(hit);
    }
    Err(PlanError::Refused(format!(
        "no SSH key {key} with a private key file in {}",
        ssh_dir.display()
    )))
}

/// `<old>-YYYYMMDD`, today in UTC.
fn default_new_path(old: &Path) -> PathBuf {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut s = old.as_os_str().to_owned();
    s.push(format!("-{}", civil_date((secs / 86_400) as i64)));
    PathBuf::from(s)
}

/// `YYYYMMDD` for days since 1970-01-01 (Hinnant's `civil_from_days`).
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
    format!("{y:04}{m:02}{d:02}")
}

fn check_new_path(new: &Path, old: &Path, old_fpr: &Fingerprint) -> Result<(), PlanError> {
    if new == old {
        return Err(PlanError::Refused(
            "the new key path is the old key path".into(),
        ));
    }
    let new_pub = pub_path(new);
    if let Ok(g) = read_public(new, &new_pub)
        && &g.fingerprint == old_fpr
    {
        return Err(PlanError::Refused(format!(
            "the new key has the same fingerprint as the old key ({}): {} is the old key",
            old_fpr,
            new_pub.display()
        )));
    }
    for p in [new, new_pub.as_path()] {
        if std::fs::symlink_metadata(p).is_ok() {
            return Err(PlanError::Refused(format!(
                "{} already exists; pick another --new-path (files are never overwritten)",
                p.display()
            )));
        }
    }
    Ok(())
}

fn keygen_text(env: &EngineEnv, key_type: KeyType, new: &Path) -> String {
    let t = match key_type {
        KeyType::Rsa => "-t rsa -b 4096",
        KeyType::Ed25519 => "-t ed25519",
        KeyType::Ecdsa => "-t ecdsa",
    };
    let comment = env.comment.as_deref().unwrap_or("<default comment>");
    let pass = match env.passphrase {
        Passphrase::Empty => " -N ''",
        Passphrase::Terminal => "",
    };
    format!(
        "{} {t} -C {comment:?}{pass} -f <temp dir in {}>/id, then link to {} and {}",
        env.keygen_program.display(),
        new.parent().unwrap_or(Path::new(".")).display(),
        new.display(),
        pub_path(new).display()
    )
}

fn rotatable(l: &Location) -> bool {
    matches!(
        l.kind,
        LocationKind::SshServer
            | LocationKind::GitHub
            | LocationKind::GitLab
            | LocationKind::Forgejo
    ) && matches!(l.purpose, Purpose::SshAuth | Purpose::SshSigning)
}

/// The API path for adding a key, under the forge's API root.
fn forge_keys_path(kind: LocationKind, purpose: Purpose) -> &'static str {
    match (kind, purpose) {
        (LocationKind::GitHub, Purpose::SshSigning) => "/user/ssh_signing_keys",
        (LocationKind::GitHub, _) => "/user/keys",
        (LocationKind::GitLab, _) => "/api/v4/user/keys",
        _ => "/api/v1/user/keys",
    }
}

fn scopes_note(kind: LocationKind, purpose: Purpose) -> String {
    match (kind, purpose) {
        (LocationKind::GitHub, Purpose::SshSigning) => {
            "token needs write:ssh_signing_key and admin:ssh_signing_key (classic) or \
             \"SSH signing keys: write\" (fine-grained)"
        }
        (LocationKind::GitHub, _) => {
            "token needs write:public_key and admin:public_key (classic) or \
             \"Git SSH keys: write\" (fine-grained)"
        }
        (LocationKind::GitLab, _) => "token needs the api scope",
        _ => "token needs the write:user scope",
    }
    .into()
}

fn options_text(raw: &Option<Vec<u8>>) -> Option<String> {
    raw.as_ref().map(|o| {
        let s: String = String::from_utf8_lossy(o)
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        if s.chars().count() > MAX_OPTIONS {
            let cut: String = s.chars().take(MAX_OPTIONS).collect();
            format!("{cut}...")
        } else {
            s
        }
    })
}

/// Pre-flight of one location: a test login with the old key, then a
/// read of its keys.
async fn preflight(
    providers: &dyn Providers,
    old: &KeyRef,
    loc: &Location,
) -> (Outcome, Vec<String>) {
    let mut notes = Vec::new();
    let not = |r: String| Outcome::NotRotated(r);
    let Some(p) = providers.provider(loc.kind) else {
        return (not(format!("no provider for {}", loc.kind)), notes);
    };
    let old = KeyRef {
        purpose: loc.purpose,
        ..old.clone()
    };
    match p.verify(&loc.target, &old).await {
        Ok(VerifyStatus::Verified) => {}
        Ok(v) => {
            return (
                not(format!("the old key does not log in: {}", status_text(&v))),
                notes,
            );
        }
        Err(e) => return (not(format!("cannot check the old key: {e}")), notes),
    }
    if loc.kind == LocationKind::SshServer {
        let lines = match providers.ssh_lines(&loc.target, &old).await {
            Ok(l) => l,
            Err(e) => return (not(format!("cannot read authorized_keys: {e}")), notes),
        };
        let ca: Vec<String> = lines
            .iter()
            .filter(|l| l.cert_authority && l.key.fingerprint == old.fingerprint)
            .map(|l| l.line.to_string())
            .collect();
        if !ca.is_empty() {
            notes.push(format!(
                "cert-authority line(s) {} hold the old key; they stay, and they block retire",
                ca.join(", ")
            ));
        }
        let own: Vec<_> = lines
            .iter()
            .filter(|l| !l.cert_authority && l.key.fingerprint == old.fingerprint)
            .collect();
        if own.is_empty() {
            return (
                not(
                    "the old key is not in ~/.ssh/authorized_keys (does sshd read another \
                     AuthorizedKeysFile?)"
                        .into(),
                ),
                notes,
            );
        }
        let mut actions: Vec<Action> = own
            .iter()
            .map(|l| Action::SshAdd {
                after_line: l.line,
                options: options_text(&l.options),
            })
            .collect();
        actions.push(Action::SshVerify);
        actions.extend(own.iter().map(|l| Action::SshRemove { line: l.line }));
        actions.push(Action::SshOldRefused);
        return (Outcome::Rotate(actions), notes);
    }

    let keys: Vec<PublicKeyRef> = match providers.list_as(loc.kind, &loc.target, &old).await {
        Ok(k) => k,
        Err(e) => return (not(format!("cannot list the keys: {e}")), notes),
    };
    let ids: BTreeSet<String> = keys
        .iter()
        .filter(|k| k.fingerprint == old.fingerprint && k.purpose == loc.purpose)
        .filter_map(|k| k.remote_id.clone())
        .collect();
    if ids.is_empty() {
        return (
            not(format!(
                "the forge does not list the old key for {}",
                loc.purpose.as_str()
            )),
            notes,
        );
    }
    let path = forge_keys_path(loc.kind, loc.purpose);
    let served = served_purposes(&keys, &old.fingerprint, loc.purpose);
    let add_note = match loc.kind {
        LocationKind::GitLab => Some(if served.len() > 1 {
            "usage_type auth_and_signing, like the old key".to_string()
        } else {
            format!("usage_type like the old key ({})", loc.purpose.as_str())
        }),
        LocationKind::Forgejo => Some("one key serves auth and signing".into()),
        _ => None,
    };
    let mut actions = vec![
        Action::Http {
            method: "GET",
            path: match loc.kind {
                LocationKind::GitHub => "/user".into(),
                LocationKind::GitLab => "/api/v4/user".into(),
                _ => "/api/v1/user".into(),
            },
            note: Some("token owner check before each write".into()),
        },
        Action::Http {
            method: "POST",
            path: path.into(),
            note: add_note,
        },
        Action::ForgeVerify,
    ];
    let del_note = (served.len() > 1)
        .then(|| "only after the new key is verified for auth and signing".to_string());
    actions.extend(ids.iter().map(|id| Action::Http {
        method: "DELETE",
        path: format!("{path}/{id}"),
        note: del_note.clone(),
    }));
    notes.push(scopes_note(loc.kind, loc.purpose));
    (Outcome::Rotate(actions), notes)
}

/// Builds the dry-run. Reads only; writes nothing (FR-10, S-7).
pub async fn plan(
    store: &Store,
    providers: &dyn Providers,
    env: &EngineEnv,
    req: &PlanRequest,
) -> Result<Plan, PlanError> {
    let (old_path, old_fpr) = find_key(&env.ssh_dir, &req.key)?;
    let new_path = req
        .new_path
        .clone()
        .unwrap_or_else(|| default_new_path(&old_path));
    check_new_path(&new_path, &old_path, &old_fpr)?;

    let stored = store.list_for_key(&old_fpr)?;
    if stored.is_empty() {
        return Err(PlanError::Refused(format!(
            "no stored locations for {old_fpr}; add them first (locations import-ssh-config, \
             locations add-forge)"
        )));
    }
    let old = KeyRef {
        fingerprint: old_fpr.clone(),
        purpose: Purpose::SshAuth,
        identity_file: Some(old_path.clone()),
    };
    let mut locations = Vec::new();
    for loc in &stored {
        let (outcome, notes) = if req.skip.contains(&loc.id) {
            (Outcome::Skipped, Vec::new())
        } else if !rotatable(loc) {
            (
                Outcome::NotRotated(format!(
                    "Key Steward does not rotate {} {} locations",
                    loc.kind.as_str(),
                    loc.purpose.as_str()
                )),
                Vec::new(),
            )
        } else {
            preflight(providers, &old, loc).await
        };
        locations.push(PlanLocation {
            id: loc.id,
            kind: loc.kind,
            target: loc.target.clone(),
            purpose: loc.purpose,
            outcome,
            notes,
        });
    }
    for id in &req.skip {
        if !stored.iter().any(|l| l.id == *id) {
            return Err(PlanError::Refused(format!(
                "--skip {id}: no location {id} holds the old key"
            )));
        }
    }

    let mut warnings = Vec::new();
    let mut retire_blocked = Vec::new();
    for l in &locations {
        if !matches!(l.outcome, Outcome::Rotate(_)) {
            retire_blocked.push(format!("the old key stays at {}", l.target.label()));
        }
        if l.notes.iter().any(|n| n.starts_with("cert-authority")) {
            retire_blocked.push(format!(
                "{} trusts the old key as a certificate authority",
                l.target.label()
            ));
        }
    }

    let insert = plan_config_change(
        &env.config_files,
        &old_path,
        &new_path,
        &env.home,
        PLAN_STAMP,
        ConfigMode::InsertAbove,
    );
    let (config, config_at_retire, config_listed) = match (req.update_config, insert) {
        (true, Err(e)) => {
            return Err(PlanError::Refused(format!(
                "cannot plan the ssh config update: {e}"
            )));
        }
        (true, Ok(p)) => {
            let mut dropped = Vec::new();
            for f in &p.files {
                let u = change_text(
                    &f.updated,
                    &old_path,
                    &new_path,
                    &env.home,
                    ConfigMode::RemovePaired,
                );
                dropped.extend(u.changes.into_iter().map(|c| DroppedLine {
                    path: f.path.clone(),
                    line: c.line,
                    text: c.before,
                }));
            }
            let listed = p.listed.clone();
            (p, dropped, listed)
        }
        (false, p) => {
            if p.as_ref().is_ok_and(|p| !p.is_empty()) {
                warnings.push(format!(
                    "the ssh config names the old key {} and is not changed (no \
                     --update-config); add the new key there by hand",
                    old_path.display()
                ));
            }
            (ConfigPlan::default(), Vec::new(), Vec::new())
        }
    };

    match env.passphrase {
        Passphrase::Empty => warnings.push(
            "the new key gets no passphrase (--no-passphrase); anyone who can read the file \
             can use it"
                .into(),
        ),
        Passphrase::Terminal => warnings.push(format!(
            "ssh-keygen asks for the new passphrase. If you set one, the checks need the \
             key in the ssh agent: ssh-add {}",
            new_path.display()
        )),
    }
    if locations
        .iter()
        .all(|l| !matches!(l.outcome, Outcome::Rotate(_)))
    {
        warnings.push("no location can be rotated; start will refuse".into());
    }

    let retired = env.ssh_dir.join(RETIRED_DIR);
    let retire = [old_path.clone(), pub_path(&old_path)]
        .into_iter()
        .filter_map(|p| file_name(&p).ok().map(|n| (p, retired.join(n))))
        .collect();

    Ok(Plan {
        keygen: keygen_text(env, req.key_type, &new_path),
        old_fingerprint: old_fpr,
        old_path,
        new_path,
        key_type: req.key_type,
        update_config: req.update_config,
        locations,
        config,
        config_at_retire,
        config_listed,
        retire,
        retire_blocked,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        assert_eq!(civil_date(0), "19700101");
        assert_eq!(civil_date(11_016), "20000229");
        assert_eq!(civil_date(20_769), "20261112");
    }
}
