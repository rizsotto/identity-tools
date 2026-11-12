//! Rotation journal (FR-5, SPEC 7.2): one row per rotation, the locations it
//! covers, and one row per step event.
//!
//! S-8: only fingerprints, paths, location settings, phases and short text.
//! All free text goes through [`scrub_detail`] before it is stored.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use identity_core::Fingerprint;
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};

use crate::location::{LocationId, LocationKind, NewLocation, Purpose, SshHost, Status, Target};
use crate::store::{
    Result, Store, StoreError, add_location, fingerprint_columns, from_unix, remove_location,
    set_status_in, to_unix,
};

pub type RotationId = i64;

/// Longest `detail` or `reason` text kept, in chars.
pub const MAX_DETAIL: usize = 300;

/// Key types a rotation can make (`ssh-keygen -t`).
pub const NEW_KEY_TYPES: &[&str] = &["ed25519", "ecdsa", "rsa"];

/// A rotation step (plan.md, "Steps and their journal entries").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    Generate,
    Install,
    Verify,
    RemoveOld,
    Rollback,
    Config,
    Retire,
    /// The user skipped a location (one `done` entry, no action).
    Skip,
}

impl Step {
    pub const ALL: [Step; 8] = [
        Step::Generate,
        Step::Install,
        Step::Verify,
        Step::RemoveOld,
        Step::Rollback,
        Step::Config,
        Step::Retire,
        Step::Skip,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Step::Generate => "generate",
            Step::Install => "install",
            Step::Verify => "verify",
            Step::RemoveOld => "remove_old",
            Step::Rollback => "rollback",
            Step::Config => "config",
            Step::Retire => "retire",
            Step::Skip => "skip",
        }
    }

    pub fn parse(s: &str) -> Option<Step> {
        Step::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Event {
    Start,
    Done,
    Failed,
}

impl Event {
    pub fn as_str(self) -> &'static str {
        match self {
            Event::Start => "start",
            Event::Done => "done",
            Event::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Event> {
        [Event::Start, Event::Done, Event::Failed]
            .into_iter()
            .find(|v| v.as_str() == s)
    }
}

/// Phase of one location in a rotation (plan.md, "States").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    Pending,
    Installed,
    Verified,
    OldRemoved,
    Skipped,
    RolledBack,
}

impl Phase {
    pub const ALL: [Phase; 6] = [
        Phase::Pending,
        Phase::Installed,
        Phase::Verified,
        Phase::OldRemoved,
        Phase::Skipped,
        Phase::RolledBack,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Pending => "pending",
            Phase::Installed => "installed",
            Phase::Verified => "verified",
            Phase::OldRemoved => "old_removed",
            Phase::Skipped => "skipped",
            Phase::RolledBack => "rolled_back",
        }
    }

    pub fn parse(s: &str) -> Option<Phase> {
        Phase::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// A rotation to create. The locations are ids of the old key's stored
/// locations; their site columns are copied into the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRotation {
    pub old_fingerprint: Fingerprint,
    pub old_key_path: PathBuf,
    pub new_key_path: PathBuf,
    pub new_key_type: String,
    pub update_config: bool,
    /// Make the new key without a passphrase (`ssh-keygen -N ''`).
    pub no_passphrase: bool,
    /// The new key's comment; `None`: ssh-keygen's default.
    pub new_key_comment: Option<String>,
    /// Initial state text, owned by the `rotation` crate.
    pub state: String,
    pub locations: Vec<LocationId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    pub id: RotationId,
    pub created_at: SystemTime,
    pub old_fingerprint: Fingerprint,
    pub old_key_path: PathBuf,
    pub new_key_path: PathBuf,
    pub new_key_type: String,
    pub new_fingerprint: Option<Fingerprint>,
    pub update_config: bool,
    pub no_passphrase: bool,
    pub new_key_comment: Option<String>,
    pub state: String,
    pub finished_at: Option<SystemTime>,
}

/// One location of a rotation. The site is a copy, so it stays readable
/// after the old location row is deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationLocation {
    pub rotation_id: RotationId,
    pub location_id: LocationId,
    pub kind: LocationKind,
    pub target: Target,
    pub purpose: Purpose,
    pub phase: Phase,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepEntry {
    pub id: i64,
    pub rotation_id: RotationId,
    pub location_id: Option<LocationId>,
    pub step: Step,
    pub event: Event,
    pub detail: Option<String>,
    pub at: SystemTime,
}

const ROTATION_COLUMNS: &str = "id, created_at, old_fingerprint, old_key_path, new_key_path, \
                                new_key_type, new_fingerprint, update_config, state, finished_at, \
                                no_passphrase, new_comment";

impl Store {
    /// Creates a rotation and its locations in one transaction. Refused
    /// with [`StoreError::RotationOpen`] while another rotation is open.
    pub fn start_rotation(&mut self, new: &NewRotation) -> Result<RotationId> {
        if !NEW_KEY_TYPES.contains(&new.new_key_type.as_str()) {
            return Err(StoreError::Invalid(format!(
                "new key type {:?}; known: {}",
                new.new_key_type,
                NEW_KEY_TYPES.join(", ")
            )));
        }
        let tx = self.conn.transaction()?;
        if let Some(open) = open_rotation_id(&tx)? {
            return Err(StoreError::RotationOpen(open));
        }
        let (_, old_fpr) = fingerprint_columns(&new.old_fingerprint);
        tx.execute(
            "INSERT INTO rotations (created_at, old_fingerprint, old_key_path, new_key_path, \
             new_key_type, update_config, state, no_passphrase, new_comment) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                to_unix(SystemTime::now()),
                old_fpr,
                path_text(&new.old_key_path)?,
                path_text(&new.new_key_path)?,
                new.new_key_type,
                new.update_config,
                new.state,
                new.no_passphrase,
                new.new_key_comment
            ],
        )?;
        let id = tx.last_insert_rowid();
        for loc in &new.locations {
            let n = tx.execute(
                "INSERT INTO rotation_locations (rotation_id, location_id, kind, ssh_alias, \
                 base_url, account, purpose, phase) \
                 SELECT ?1, id, kind, ssh_alias, base_url, account, purpose, ?2 \
                 FROM locations WHERE id = ?3",
                params![id, Phase::Pending.as_str(), loc],
            )?;
            if n != 1 {
                return Err(StoreError::NotFound {
                    what: "location",
                    id: *loc,
                });
            }
        }
        tx.commit()?;
        Ok(id)
    }

    /// The rotation that is not finished, if any.
    pub fn open_rotation(&self) -> Result<Option<Rotation>> {
        match open_rotation_id(&self.conn)? {
            Some(id) => self.rotation(id),
            None => Ok(None),
        }
    }

    pub fn rotation(&self, id: RotationId) -> Result<Option<Rotation>> {
        self.conn
            .query_row(
                &format!("SELECT {ROTATION_COLUMNS} FROM rotations WHERE id = ?1"),
                [id],
                read_rotation,
            )
            .optional()?
            .transpose()
    }

    pub fn rotation_locations(&self, id: RotationId) -> Result<Vec<RotationLocation>> {
        let mut stmt = self.conn.prepare(
            "SELECT rotation_id, location_id, kind, ssh_alias, base_url, account, purpose, \
             phase, reason FROM rotation_locations WHERE rotation_id = ?1 ORDER BY location_id",
        )?;
        let rows = stmt.query_map([id], read_rotation_location)?;
        rows.map(|r| r?).collect()
    }

    /// Every step entry of a rotation, in the order written.
    pub fn steps(&self, id: RotationId) -> Result<Vec<StepEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, rotation_id, location_id, step, event, detail, at FROM rotation_steps \
             WHERE rotation_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map([id], read_step)?;
        rows.map(|r| r?).collect()
    }

    /// Writes one step entry and commits it.
    pub fn journal(
        &mut self,
        rotation: RotationId,
        location: Option<LocationId>,
        step: Step,
        event: Event,
        detail: Option<&str>,
    ) -> Result<i64> {
        let mut tx = self.journal_tx()?;
        let id = tx.step(rotation, location, step, event, detail)?;
        tx.commit()?;
        Ok(id)
    }

    /// Starts a transaction for a step entry plus the changes that belong
    /// with it (phase, location rows). Nothing is stored until
    /// [`JournalTx::commit`].
    pub fn journal_tx(&mut self) -> Result<JournalTx<'_>> {
        Ok(JournalTx {
            tx: self.conn.transaction()?,
            secrets: &self.secrets,
        })
    }

    /// Registers a secret that journal text must never hold: a token, or a
    /// public key blob (base64). [`scrub_detail`] removes it exactly, also
    /// split by whitespace or in pieces. Kept in memory only.
    pub fn add_secret(&mut self, secret: &str) {
        if !secret.is_empty() && !self.secrets.iter().any(|s| s == secret) {
            self.secrets.push(secret.to_string());
        }
    }
}

/// A journal transaction. Dropped without commit, it writes nothing.
pub struct JournalTx<'a> {
    tx: Transaction<'a>,
    secrets: &'a [String],
}

impl JournalTx<'_> {
    pub fn step(
        &mut self,
        rotation: RotationId,
        location: Option<LocationId>,
        step: Step,
        event: Event,
        detail: Option<&str>,
    ) -> Result<i64> {
        self.tx.execute(
            "INSERT INTO rotation_steps (rotation_id, location_id, step, event, detail, at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                rotation,
                location,
                step.as_str(),
                event.as_str(),
                detail.map(|d| self.scrub(d)),
                to_unix(SystemTime::now())
            ],
        )?;
        Ok(self.tx.last_insert_rowid())
    }

    pub fn set_phase(
        &mut self,
        rotation: RotationId,
        location: LocationId,
        phase: Phase,
        reason: Option<&str>,
    ) -> Result<()> {
        let n = self.tx.execute(
            "UPDATE rotation_locations SET phase = ?1, reason = ?2 \
             WHERE rotation_id = ?3 AND location_id = ?4",
            params![
                phase.as_str(),
                reason.map(|r| self.scrub(r)),
                rotation,
                location
            ],
        )?;
        if n != 1 {
            return Err(StoreError::NotFound {
                what: "rotation location",
                id: location,
            });
        }
        Ok(())
    }

    pub fn set_state(&mut self, rotation: RotationId, state: &str) -> Result<()> {
        self.update_rotation(rotation, "state = ?1", &state)
    }

    pub fn set_new_fingerprint(&mut self, rotation: RotationId, fpr: &Fingerprint) -> Result<()> {
        let (_, f) = fingerprint_columns(fpr);
        self.update_rotation(rotation, "new_fingerprint = ?1", &f)
    }

    /// Marks the rotation finished (done or aborted). A new one may start.
    pub fn finish(&mut self, rotation: RotationId) -> Result<()> {
        self.update_rotation(rotation, "finished_at = ?1", &to_unix(SystemTime::now()))
    }

    /// Adds a location (or finds the same one) and sets its status.
    pub fn add_location(
        &mut self,
        loc: &NewLocation,
        status: &Status,
        checked: SystemTime,
    ) -> Result<LocationId> {
        let id = add_location(&self.tx, loc)?.id();
        let status = match status {
            Status::Error(r) => Status::Error(self.scrub(r)),
            s => s.clone(),
        };
        set_status_in(&self.tx, id, &status, checked)?;
        Ok(id)
    }

    /// Deletes a location row. Returns false if it was already gone.
    pub fn remove_location(&mut self, id: LocationId) -> Result<bool> {
        remove_location(&self.tx, id)
    }

    fn scrub(&self, text: &str) -> String {
        let secrets: Vec<&str> = self.secrets.iter().map(String::as_str).collect();
        scrub_detail(text, &secrets)
    }

    pub fn commit(self) -> Result<()> {
        Ok(self.tx.commit()?)
    }

    fn update_rotation(
        &mut self,
        rotation: RotationId,
        set: &str,
        value: &dyn rusqlite::ToSql,
    ) -> Result<()> {
        let n = self.tx.execute(
            &format!("UPDATE rotations SET {set} WHERE id = ?2"),
            params![value, rotation],
        )?;
        if n != 1 {
            return Err(StoreError::NotFound {
                what: "rotation",
                id: rotation,
            });
        }
        Ok(())
    }
}

fn open_rotation_id(conn: &Connection) -> Result<Option<RotationId>> {
    Ok(conn
        .query_row(
            "SELECT id FROM rotations WHERE finished_at IS NULL",
            [],
            |r| r.get(0),
        )
        .optional()?)
}

fn path_text(p: &Path) -> Result<&str> {
    p.to_str()
        .ok_or_else(|| StoreError::Corrupt(format!("path is not UTF-8: {}", p.display())))
}

fn read_rotation(r: &Row<'_>) -> rusqlite::Result<Result<Rotation>> {
    let created: i64 = r.get("created_at")?;
    let old: String = r.get("old_fingerprint")?;
    let old_path: String = r.get("old_key_path")?;
    let new_path: String = r.get("new_key_path")?;
    let finished: Option<i64> = r.get("finished_at")?;
    let new_fpr: Option<String> = r.get("new_fingerprint")?;
    Ok(Ok(Rotation {
        id: r.get("id")?,
        created_at: from_unix(created),
        old_fingerprint: Fingerprint::Ssh(old),
        old_key_path: PathBuf::from(old_path),
        new_key_path: PathBuf::from(new_path),
        new_key_type: r.get("new_key_type")?,
        new_fingerprint: new_fpr.map(Fingerprint::Ssh),
        update_config: r.get("update_config")?,
        no_passphrase: r.get("no_passphrase")?,
        new_key_comment: r.get("new_comment")?,
        state: r.get("state")?,
        finished_at: finished.map(from_unix),
    }))
}

fn read_rotation_location(r: &Row<'_>) -> rusqlite::Result<Result<RotationLocation>> {
    let rotation_id: RotationId = r.get("rotation_id")?;
    let location_id: LocationId = r.get("location_id")?;
    let kind: String = r.get("kind")?;
    let alias: Option<String> = r.get("ssh_alias")?;
    let base_url: Option<String> = r.get("base_url")?;
    let account: Option<String> = r.get("account")?;
    let purpose: String = r.get("purpose")?;
    let phase: String = r.get("phase")?;
    let reason: Option<String> = r.get("reason")?;
    let corrupt = |what: &str, v: &str| {
        StoreError::Corrupt(format!(
            "rotation {rotation_id} location {location_id}: {what} {v:?}"
        ))
    };
    let build = || -> Result<RotationLocation> {
        let kind = LocationKind::parse(&kind).ok_or_else(|| corrupt("kind", &kind))?;
        let target = match (alias, base_url, account) {
            (Some(alias), None, None) => Target::Ssh(SshHost::new(alias)),
            (None, Some(base_url), Some(account)) => Target::Account { base_url, account },
            _ => return Err(corrupt("target", "")),
        };
        Ok(RotationLocation {
            rotation_id,
            location_id,
            kind,
            target,
            purpose: Purpose::parse(&purpose).ok_or_else(|| corrupt("purpose", &purpose))?,
            phase: Phase::parse(&phase).ok_or_else(|| corrupt("phase", &phase))?,
            reason,
        })
    };
    Ok(build())
}

fn read_step(r: &Row<'_>) -> rusqlite::Result<Result<StepEntry>> {
    let id: i64 = r.get("id")?;
    let step: String = r.get("step")?;
    let event: String = r.get("event")?;
    let at: i64 = r.get("at")?;
    let corrupt = |what: &str, v: &str| StoreError::Corrupt(format!("step {id}: {what} {v:?}"));
    let build = || -> Result<StepEntry> {
        Ok(StepEntry {
            id,
            rotation_id: r.get("rotation_id")?,
            location_id: r.get("location_id")?,
            step: Step::parse(&step).ok_or_else(|| corrupt("step", &step))?,
            event: Event::parse(&event).ok_or_else(|| corrupt("event", &event))?,
            detail: r.get("detail")?,
            at: from_unix(at),
        })
    };
    Ok(build())
}

/// Makes free text safe to store (S-8, S-4), in two passes:
///
/// 1. Every known secret in `secrets` (tokens, public key blobs) is cut
///    out: the exact text, the text with its whitespace changed (split
///    into groups or lines), and any piece of it of [`MIN_SECRET_PIECE`]
///    chars or more.
/// 2. A heuristic net for what the caller did not know: PEM or armored
///    blocks and their bare body lines, key blobs (`AAAA...`), tokens by
///    prefix or after `token=`, `Bearer` and similar, and other long
///    opaque strings.
///
/// Then control chars become spaces and the length is capped at
/// [`MAX_DETAIL`] chars. It errs on the side of dropping too much. SSH
/// fingerprints (`SHA256:<43 chars>`) are kept.
pub fn scrub_detail(text: &str, secrets: &[&str]) -> String {
    let text: String = text.chars().take(MAX_SCRUB_INPUT).collect();
    let text = cut_secrets(&text, secrets);
    let text = match text.find("-----BEGIN") {
        Some(i) => format!("{}[key removed]", &text[..i]),
        None => text,
    };
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let mut prev = String::new();
    let flush = |run: &mut String, out: &mut String, prev: &mut String| {
        if !run.is_empty() {
            let kept = scrub_run(run, out, prev);
            out.push_str(kept);
            *prev = run.to_ascii_lowercase();
            run.clear();
        }
    };
    for c in text.chars() {
        if is_run_char(c) {
            run.push(c);
            continue;
        }
        flush(&mut run, &mut out, &mut prev);
        if c == ':' {
            prev.push(':');
        }
        out.push(if c.is_control() { ' ' } else { c });
    }
    flush(&mut run, &mut out, &mut prev);
    if out.chars().count() > MAX_DETAIL {
        out = out.chars().take(MAX_DETAIL - 3).collect();
        out.push_str("...");
    }
    out
}

/// Pass 1 of [`scrub_detail`] alone: cuts every known secret out of
/// `text` (exact, re-spaced, or a long piece), keeps the rest as it is,
/// with no length cap. For logs that must stay readable.
pub fn cut_known_secrets(text: &str, secrets: &[&str]) -> String {
    cut_secrets(text, secrets)
}

/// Input past this many chars is dropped before scrubbing.
const MAX_SCRUB_INPUT: usize = 4096;

/// Shortest piece of a known secret that is cut out on its own.
pub const MIN_SECRET_PIECE: usize = 12;

/// Pass 1 of [`scrub_detail`]. Whitespace in the text is ignored while
/// matching, so a secret split into groups or lines is still found.
fn cut_secrets(text: &str, secrets: &[&str]) -> String {
    let chars: Vec<char> = text.chars().collect();
    let idx: Vec<usize> = (0..chars.len())
        .filter(|&i| !chars[i].is_whitespace())
        .collect();
    let norm: Vec<char> = idx.iter().map(|&i| chars[i]).collect();
    let mut hit = vec![false; norm.len()];
    for secret in secrets {
        let s: Vec<char> = secret.chars().filter(|c| !c.is_whitespace()).collect();
        if s.is_empty() {
            continue;
        }
        let min = MIN_SECRET_PIECE.min(s.len());
        for i in 0..norm.len() {
            let longest = (0..s.len())
                .map(|j| {
                    norm[i..]
                        .iter()
                        .zip(&s[j..])
                        .take_while(|(a, b)| a == b)
                        .count()
                })
                .max()
                .unwrap_or(0);
            if longest >= min {
                hit[i..i + longest].iter_mut().for_each(|h| *h = true);
            }
        }
    }
    if !hit.contains(&true) {
        return text.to_string();
    }
    let mut cut = vec![false; chars.len()];
    for (k, &i) in idx.iter().enumerate() {
        if hit[k] {
            cut[i] = true;
            // Whitespace between two cut chars goes too.
            if k + 1 < idx.len() && hit[k + 1] {
                cut[i..idx[k + 1]].iter_mut().for_each(|c| *c = true);
            }
        }
    }
    let mut out = String::with_capacity(text.len());
    for (i, &c) in chars.iter().enumerate() {
        if !cut[i] {
            out.push(c);
        } else if i == 0 || !cut[i - 1] {
            out.push_str("[secret removed]");
        }
    }
    out
}

const TOKEN_PREFIXES: &[&str] = &[
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "gloas-",
    "glptt-",
    "gldt-",
    "glrt-",
    "glsoat-",
    "glcbt-",
    "glft-",
];

/// Names after which a value is a credential: `token=x`, `Bearer x`,
/// `PRIVATE-TOKEN: x`.
const SECRET_NAMES: &[&str] = &[
    "token",
    "private_token",
    "private-token",
    "access_token",
    "secret",
    "password",
    "passwd",
    "bearer",
    "basic",
    "authorization",
];

/// Longest piece of a run, between `/`, `.` and `=`, that is kept.
const MAX_OPAQUE: usize = 31;

/// A run of base64 chars this long, with upper, lower and digits, looks
/// like a key or PEM body line.
const MAX_BASE64_RUN: usize = 23;

fn is_run_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "+/=_-.".contains(c)
}

fn scrub_run<'a>(run: &'a str, before: &str, prev: &str) -> &'a str {
    let is_b64 = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
    };
    if before.ends_with("SHA256:") && run.len() == 43 && is_b64(run) {
        return run;
    }
    if run.contains("AAAA") && run.len() >= 20 {
        return "[key removed]";
    }
    let lower = run.to_ascii_lowercase();
    let jwt = run.starts_with("eyJ") && run.contains('.');
    let named = SECRET_NAMES.iter().any(|n| {
        lower.contains(&format!("{n}="))
            || prev.trim_end_matches(':').ends_with(n) && run.len() >= 8
    });
    if jwt || named || TOKEN_PREFIXES.iter().any(|p| run.contains(p)) {
        return "[token removed]";
    }
    if run.split(['/', '.', '=']).any(|s| s.len() > MAX_OPAQUE) {
        return "[removed]";
    }
    let base64_like = run
        .split(|c: char| !(c.is_ascii_alphanumeric() || "+/=".contains(c)))
        .any(|s| {
            s.len() > MAX_BASE64_RUN
                && s.contains(|c: char| c.is_ascii_uppercase())
                && s.contains(|c: char| c.is_ascii_lowercase())
                && s.contains(|c: char| c.is_ascii_digit())
        });
    if base64_like {
        return "[removed]";
    }
    run
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const ED_PUB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq9t2bY8/lTn2ZQz6jY1Ns6r5Sx0c+Nk2D5ExampleK me@host";
    const ED_FPR: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

    fn new_location(alias: &str, fpr: &str) -> NewLocation {
        NewLocation {
            kind: LocationKind::SshServer,
            target: Target::Ssh(SshHost::new(alias)),
            key: Fingerprint::Ssh(fpr.into()),
            purpose: Purpose::SshAuth,
        }
    }

    fn forge_location(fpr: &str) -> NewLocation {
        NewLocation {
            kind: LocationKind::GitLab,
            target: Target::Account {
                base_url: "https://gitlab.example.org".into(),
                account: "me".into(),
            },
            key: Fingerprint::Ssh(fpr.into()),
            purpose: Purpose::SshSigning,
        }
    }

    fn new_rotation(locations: Vec<LocationId>) -> NewRotation {
        NewRotation {
            old_fingerprint: Fingerprint::Ssh(ED_FPR.into()),
            old_key_path: "/h/.ssh/id_ed25519".into(),
            new_key_path: "/h/.ssh/id_ed25519-20261112".into(),
            new_key_type: "ed25519".into(),
            update_config: true,
            no_passphrase: false,
            new_key_comment: Some("me@laptop".into()),
            state: "planned".into(),
            locations,
        }
    }

    fn private_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    #[test]
    fn migration_2_applies() {
        let dir = private_dir();
        let path = dir.path().join("inventory.sqlite");

        // A database made by M1 (schema 1) with one location.
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(crate::store::MIGRATIONS[0]).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        drop(conn);
        let mut store = Store::open(&path).unwrap();
        assert_eq!(
            store.schema_version().unwrap(),
            crate::store::MIGRATIONS.len() as u32
        );

        let id = store.add(&new_location("build", ED_FPR)).unwrap().id();
        let mut tables: Vec<String> = store
            .conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type IN ('table', 'index') ORDER BY name",
            )
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        tables.retain(|t| !t.starts_with("sqlite_"));
        for t in [
            "locations",
            "one_open_rotation",
            "rotation_locations",
            "rotation_steps",
            "rotations",
        ] {
            assert!(tables.iter().any(|x| x == t), "{t} missing in {tables:?}");
        }
        let rot = store.start_rotation(&new_rotation(vec![id])).unwrap();
        assert_eq!(store.rotation_locations(rot).unwrap().len(), 1);
    }

    #[test]
    fn second_open_rotation_refused() {
        let mut store = Store::open_in_memory().unwrap();
        let id = store.add(&new_location("build", ED_FPR)).unwrap().id();
        let first = store.start_rotation(&new_rotation(vec![id])).unwrap();
        let err = store.start_rotation(&new_rotation(vec![id])).unwrap_err();
        assert!(
            matches!(err, StoreError::RotationOpen(r) if r == first),
            "{err}"
        );

        // The index refuses it too, even past the API.
        let raw = store.conn.execute(
            "INSERT INTO rotations (created_at, old_fingerprint, old_key_path, new_key_path, \
             new_key_type, update_config, state) VALUES (0, 'x', 'a', 'b', 'ed25519', 0, 's')",
            [],
        );
        assert!(raw.unwrap_err().to_string().contains("UNIQUE"));

        // A failed start leaves nothing behind.
        let mut tx = store.journal_tx().unwrap();
        tx.finish(first).unwrap();
        tx.commit().unwrap();
        let err = store
            .start_rotation(&new_rotation(vec![id, 999]))
            .unwrap_err();
        assert!(matches!(err, StoreError::NotFound { id: 999, .. }), "{err}");
        assert!(store.open_rotation().unwrap().is_none());

        let second = store.start_rotation(&new_rotation(vec![id])).unwrap();
        assert_eq!(store.open_rotation().unwrap().unwrap().id, second);
    }

    #[test]
    fn journal_roundtrip() {
        let dir = private_dir();
        let path = dir.path().join("inventory.sqlite");
        let mut store = Store::open(&path).unwrap();
        let ssh = store.add(&new_location("build", ED_FPR)).unwrap().id();
        let forge = store.add(&forge_location(ED_FPR)).unwrap().id();
        let rot = store
            .start_rotation(&new_rotation(vec![ssh, forge]))
            .unwrap();
        let row = store.rotation(rot).unwrap().unwrap();
        assert!(!row.no_passphrase);
        assert_eq!(row.new_key_comment.as_deref(), Some("me@laptop"));

        store
            .journal(rot, None, Step::Generate, Event::Start, None)
            .unwrap();
        let new_fpr = Fingerprint::Ssh("SHA256:nEwKeYnEwKeYnEwKeYnEwKeYnEwKeYnEwKeYnEwKeYa".into());
        let mut tx = store.journal_tx().unwrap();
        tx.step(rot, None, Step::Generate, Event::Done, Some("made"))
            .unwrap();
        tx.set_new_fingerprint(rot, &new_fpr).unwrap();
        tx.set_state(rot, "new_key_generated").unwrap();
        tx.commit().unwrap();

        // Verify passing adds the new key's location in the same transaction.
        let mut tx = store.journal_tx().unwrap();
        tx.step(rot, Some(ssh), Step::Verify, Event::Done, None)
            .unwrap();
        tx.set_phase(rot, ssh, Phase::Verified, None).unwrap();
        let mut loc = new_location("build", new_fpr.as_str());
        loc.key = new_fpr.clone();
        let new_loc = tx
            .add_location(&loc, &Status::Verified, SystemTime::now())
            .unwrap();
        tx.commit().unwrap();

        // A transaction dropped without commit writes nothing.
        let mut tx = store.journal_tx().unwrap();
        tx.step(rot, Some(forge), Step::Install, Event::Start, None)
            .unwrap();
        tx.remove_location(forge).unwrap();
        drop(tx);

        // remove_old done deletes the old row; the journal keeps the site.
        let mut tx = store.journal_tx().unwrap();
        tx.step(rot, Some(ssh), Step::RemoveOld, Event::Done, None)
            .unwrap();
        tx.set_phase(rot, ssh, Phase::OldRemoved, None).unwrap();
        assert!(tx.remove_location(ssh).unwrap());
        tx.commit().unwrap();
        store
            .journal(
                rot,
                Some(forge),
                Step::Install,
                Event::Failed,
                Some("HTTP 403"),
            )
            .unwrap();
        let mut tx = store.journal_tx().unwrap();
        tx.set_phase(rot, forge, Phase::Skipped, Some("user skipped"))
            .unwrap();
        tx.commit().unwrap();
        drop(store);

        // It all survives a restart.
        let mut store = Store::open(&path).unwrap();
        let r = store.open_rotation().unwrap().unwrap();
        assert_eq!(r.id, rot);
        assert_eq!(r.old_fingerprint, Fingerprint::Ssh(ED_FPR.into()));
        assert_eq!(r.old_key_path, Path::new("/h/.ssh/id_ed25519"));
        assert_eq!(r.new_key_path, Path::new("/h/.ssh/id_ed25519-20261112"));
        assert_eq!(r.new_key_type, "ed25519");
        assert_eq!(r.new_fingerprint, Some(new_fpr.clone()));
        assert!(r.update_config);
        assert_eq!(r.state, "new_key_generated");
        assert_eq!(r.finished_at, None);

        let steps = store.steps(rot).unwrap();
        let got: Vec<_> = steps
            .iter()
            .map(|s| (s.location_id, s.step, s.event, s.detail.as_deref()))
            .collect();
        assert_eq!(
            got,
            vec![
                (None, Step::Generate, Event::Start, None),
                (None, Step::Generate, Event::Done, Some("made")),
                (Some(ssh), Step::Verify, Event::Done, None),
                (Some(ssh), Step::RemoveOld, Event::Done, None),
                (Some(forge), Step::Install, Event::Failed, Some("HTTP 403")),
            ]
        );

        let locs = store.rotation_locations(rot).unwrap();
        assert_eq!(locs.len(), 2);
        assert_eq!(locs[0].location_id, ssh);
        assert_eq!(locs[0].target, Target::Ssh(SshHost::new("build")));
        assert_eq!(locs[0].phase, Phase::OldRemoved);
        assert_eq!(locs[1].kind, LocationKind::GitLab);
        assert_eq!(locs[1].purpose, Purpose::SshSigning);
        assert_eq!(locs[1].phase, Phase::Skipped);
        assert_eq!(locs[1].reason.as_deref(), Some("user skipped"));

        assert!(store.get(ssh).unwrap().is_none());
        assert!(store.get(forge).unwrap().is_some());
        let n = store.get(new_loc).unwrap().unwrap();
        assert_eq!((n.key, n.status), (new_fpr, Status::Verified));

        let mut tx = store.journal_tx().unwrap();
        tx.finish(rot).unwrap();
        tx.commit().unwrap();
        assert!(store.open_rotation().unwrap().is_none());
        assert!(store.rotation(rot).unwrap().unwrap().finished_at.is_some());
        assert!(!store.remove(ssh).unwrap());
        assert!(store.remove(forge).unwrap());
    }

    #[test]
    fn detail_drops_key_blobs() {
        let rsa_blob = format!("AAAAB3NzaC1yc2EAAAADAQABAAABAQ{}", "x".repeat(300));
        let cases = [
            ED_PUB.to_string(),
            format!("ssh-rsa {rsa_blob} rsa@host"),
            "key=AAAAC3NzaC1lZDI1NTE5AAAAIGq9t2bY8".into(),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END".into(),
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZ".into(),
            "Authorization: token ghp_abcdefghijklmnopqrstuvwxyz0123456789".into(),
            "github_pat_11ABCDEFG0123456789_abcdefghij".into(),
            "glpat-abcdefghij0123456789.01.abc".into(),
            "token=0123456789abcdef0123456789abcdef01234567 failed".into(),
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig".into(),
        ];
        let secrets = [
            "AAAA",
            "b3BlbnNz",
            "mDMEZ",
            "ghp_",
            "abcdefghijklmnopqrstuvwxyz",
            "github_pat_",
            "glpat-",
            "0123456789abcdef0123456789abcdef",
            "eyJhbGciOiJIUzI1NiJ9",
        ];
        for case in &cases {
            let s = scrub_detail(case, &[]);
            for bad in secrets {
                assert!(!s.contains(bad), "{case:?} -> {s:?} still has {bad:?}");
            }
        }

        // Useful text stays.
        let keep = format!("verified {ED_FPR} at build, moved /h/.ssh/id_ed25519 to retired/");
        assert_eq!(scrub_detail(&keep, &[]), keep);
        assert_eq!(
            scrub_detail("HTTP 403: line1\nline2", &[]),
            "HTTP 403: line1 line2"
        );
        let long = "word ".repeat(200);
        let capped = scrub_detail(&long, &[]);
        assert_eq!(capped.chars().count(), MAX_DETAIL);
        assert!(capped.ends_with("..."));
        let wide = "é".repeat(MAX_DETAIL + 5);
        assert_eq!(scrub_detail(&wide, &[]).chars().count(), MAX_DETAIL);

        // The journal applies it to details and reasons, and the database
        // file never holds the key or the token.
        let dir = private_dir();
        let path = dir.path().join("inventory.sqlite");
        let mut store = Store::open(&path).unwrap();
        let id = store.add(&new_location("build", ED_FPR)).unwrap().id();
        let rot = store.start_rotation(&new_rotation(vec![id])).unwrap();
        store
            .journal(rot, Some(id), Step::Install, Event::Failed, Some(&cases[0]))
            .unwrap();
        let mut tx = store.journal_tx().unwrap();
        tx.set_phase(rot, id, Phase::Installed, Some(&cases[5]))
            .unwrap();
        tx.commit().unwrap();
        let steps = store.steps(rot).unwrap();
        assert_eq!(
            steps[0].detail.as_deref(),
            Some("ssh-ed25519 [key removed] me@host")
        );
        drop(store);
        let bytes = fs::read(&path).unwrap();
        let hay = String::from_utf8_lossy(&bytes);
        assert!(!hay.contains("AAAAC3NzaC1lZDI1NTE5"));
        assert!(!hay.contains("ghp_"));
    }

    fn keygen(dir: &Path, name: &str, args: &[&str]) -> (String, String) {
        let path = dir.join(name);
        let out = std::process::Command::new("ssh-keygen")
            .args(["-q", "-N", "", "-C", "", "-f"])
            .arg(&path)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let private = fs::read_to_string(&path).unwrap();
        let public = fs::read_to_string(dir.join(format!("{name}.pub"))).unwrap();
        (private, public)
    }

    #[test]
    fn detail_drops_known_secrets_in_split_forms() {
        let dir = private_dir();
        let (_, public) = keygen(dir.path(), "k", &["-t", "ed25519"]);
        let blob = public.split_whitespace().nth(1).unwrap().to_string();
        let token = "Xq7rT2mK9pLw4ZsN8vBc";
        let secrets = [blob.as_str(), token];

        let groups: Vec<String> = blob
            .as_bytes()
            .chunks(16)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect();
        let cases = [
            groups.join(" "),
            groups.join("\n"),
            format!("piece {} only", &blob[30..50]),
            format!("x{token}y"),
            format!("t = {} {}", &token[..10], &token[10..]),
        ];
        for case in &cases {
            let s = scrub_detail(case, &secrets);
            for g in &groups[1..] {
                assert!(!s.contains(g.as_str()), "{case:?} -> {s:?}");
            }
            assert!(!s.contains(&blob[30..50]), "{case:?} -> {s:?}");
            assert!(!s.contains(&token[..10]), "{case:?} -> {s:?}");
            assert!(!s.contains(&token[10..]), "{case:?} -> {s:?}");
        }
        assert_eq!(
            scrub_detail(&format!("a {token} b"), &secrets),
            "a [secret removed] b"
        );
        // Other text is kept.
        let keep = format!("verified {ED_FPR} at build");
        assert_eq!(scrub_detail(&keep, &secrets), keep);

        // The store applies registered secrets to journal text.
        let mut store = Store::open_in_memory().unwrap();
        store.add_secret(token);
        store.add_secret(&blob);
        let id = store.add(&new_location("build", ED_FPR)).unwrap().id();
        let rot = store.start_rotation(&new_rotation(vec![id])).unwrap();
        store
            .journal(rot, Some(id), Step::Install, Event::Failed, Some(&cases[0]))
            .unwrap();
        let mut tx = store.journal_tx().unwrap();
        tx.set_phase(rot, id, Phase::Installed, Some(&cases[4]))
            .unwrap();
        tx.commit().unwrap();
        let d = store.steps(rot).unwrap()[0].detail.clone().unwrap();
        assert!(!d.contains(&groups[2]), "{d}");
        let r = store.rotation_locations(rot).unwrap()[0]
            .reason
            .clone()
            .unwrap();
        assert!(!r.contains(&token[10..]), "{r}");
    }

    #[test]
    fn detail_drops_headerless_pem_body() {
        let dir = private_dir();
        let mut keys = Vec::new();
        for i in 0..3 {
            keys.push(keygen(dir.path(), &format!("rsa{i}"), &["-t", "rsa", "-b", "3072"]).0);
            keys.push(keygen(dir.path(), &format!("ed{i}"), &["-t", "ed25519"]).0);
        }
        let mut checked = 0;
        for private in &keys {
            let body: Vec<&str> = private
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect();
            let joined = body.join("\n");
            let whole = scrub_detail(&joined, &[]);
            for line in body.iter().filter(|l| l.len() > MAX_BASE64_RUN) {
                let s = scrub_detail(line, &[]);
                assert!(!s.contains(line), "body line kept: {line:?} -> {s:?}");
                assert!(!whole.contains(line), "body line kept in block: {line:?}");
                checked += 1;
            }
        }
        assert!(checked > 50, "{checked}");
    }

    #[test]
    fn detail_drops_short_token_values() {
        let cases = [
            "GET /api/v4/user?private_token=AbCdEfGhIj0123456789 failed",
            "PRIVATE-TOKEN: AbCdEfGhIj0123456789",
            "Authorization: token abcdefghij0123456789",
            "Authorization: Bearer abcdefghij0123456789",
            "access_token=abcdefghij0123456789&x=1",
        ];
        for case in cases {
            let s = scrub_detail(case, &[]);
            assert!(
                !s.to_lowercase().contains("abcdefghij"),
                "{case:?} -> {s:?}"
            );
        }
    }

    #[test]
    fn add_location_scrubs_error_reason_and_key_type_is_checked() {
        let mut store = Store::open_in_memory().unwrap();
        store.add_secret("Xq7rT2mK9pLw4ZsN8vBc");
        let mut tx = store.journal_tx().unwrap();
        let id = tx
            .add_location(
                &new_location("b", ED_FPR),
                &Status::Error(format!("bad: {ED_PUB} Xq7rT2mK9pLw4ZsN8vBc")),
                SystemTime::now(),
            )
            .unwrap();
        tx.commit().unwrap();
        let Status::Error(r) = store.get(id).unwrap().unwrap().status else {
            panic!("expected an error status");
        };
        assert!(!r.contains("AAAA") && !r.contains("Xq7rT2mK9pLw"), "{r}");

        let mut bad = new_rotation(vec![id]);
        bad.new_key_type = "dsa".into();
        let err = store.start_rotation(&bad).unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)), "{err}");
        assert!(store.open_rotation().unwrap().is_none());
    }
}
