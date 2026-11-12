//! ssh config `IdentityFile` update (plan.md, "Config update").
//!
//! [`plan_config_update`] is the read-only part: it finds `IdentityFile`
//! lines whose value, after `~`, `%d` and `%%` expansion (the M1 import
//! rules), equals the old key path, and builds the new text with only the
//! value replaced. Lines with other `%` tokens are listed, not changed.
//! [`apply_config_update`] writes it: backup first, then a temp file in
//! the same dir and `rename`, mode kept. [`restore_config`] puts the
//! backups back (abort with rollback after the config step).
//!
//! Backups are named `<file>.keysteward-<stamp>`. The caller picks one
//! stamp per rotation, so a resumed run finds the same backups.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use inventory::{Resolved, expand_identity};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{path}: {reason}")]
    Io { path: PathBuf, reason: String },
    #[error("{0} changed since the plan was made; nothing was written to it")]
    Changed(PathBuf),
    #[error("bad backup stamp {0:?}: use letters, digits, '-' and '_' only")]
    BadStamp(String),
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> ConfigError + '_ {
    move |e| ConfigError::Io {
        path: path.to_path_buf(),
        reason: e.to_string(),
    }
}

/// One changed line. `line` counts from 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineChange {
    pub line: usize,
    pub before: String,
    pub after: String,
}

/// A line that names a key through `%` tokens we do not expand here. It
/// is shown to the user and left alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedLine {
    pub path: PathBuf,
    pub line: usize,
    pub text: String,
}

/// The pure result for one file's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextUpdate {
    pub updated: String,
    pub changes: Vec<LineChange>,
    /// Line numbers (from 1) of `IdentityFile` lines with other tokens.
    pub listed: Vec<usize>,
}

/// Rewrites the `IdentityFile` lines of `text` that name `old_path`.
/// Every other byte stays as it is, line endings included.
pub fn update_text(text: &str, old_path: &Path, new_path: &Path, home: &Path) -> TextUpdate {
    let mut out = TextUpdate {
        updated: String::with_capacity(text.len()),
        changes: Vec::new(),
        listed: Vec::new(),
    };
    for (i, line) in text.split_inclusive('\n').enumerate() {
        let Some((start, end, quoted)) = identity_value(line) else {
            out.updated.push_str(line);
            continue;
        };
        let value = &line[start..end];
        match expand_identity(value, home, &Resolved::default()) {
            Some(p) if p == old_path => {
                let new_value = render_path(new_path, home, value.starts_with("~/"), quoted);
                let new_line = format!("{}{}{}", &line[..start], new_value, &line[end..]);
                out.changes.push(LineChange {
                    line: i + 1,
                    before: trim_eol(line).to_string(),
                    after: trim_eol(&new_line).to_string(),
                });
                out.updated.push_str(&new_line);
            }
            None if value.contains('%') => {
                out.listed.push(i + 1);
                out.updated.push_str(line);
            }
            _ => out.updated.push_str(line),
        }
    }
    out
}

/// The byte range of the value of an `IdentityFile` line, and whether it
/// is in double quotes. `IdentityFile x`, `IdentityFile=x`, any case.
fn identity_value(line: &str) -> Option<(usize, usize, bool)> {
    let body = trim_eol(line);
    let lead = body.len() - body.trim_start().len();
    let rest = &body[lead..];
    const KW: &str = "identityfile";
    if rest.len() < KW.len() || !rest[..KW.len()].eq_ignore_ascii_case(KW) {
        return None;
    }
    let mut pos = lead + KW.len();
    let after = &body[pos..];
    if !after.starts_with(|c: char| c.is_whitespace() || c == '=') {
        return None;
    }
    pos += after.len() - after.trim_start().len();
    if body[pos..].starts_with('=') {
        pos += 1;
        let a = &body[pos..];
        pos += a.len() - a.trim_start().len();
    }
    let v = &body[pos..];
    if let Some(inner) = v.strip_prefix('"') {
        let close = inner.find('"')?;
        return Some((pos + 1, pos + 1 + close, true));
    }
    if v.is_empty() || v.starts_with('#') {
        return None;
    }
    let len = v.find(char::is_whitespace).unwrap_or(v.len());
    Some((pos, pos + len, false))
}

fn trim_eol(line: &str) -> &str {
    let l = line.strip_suffix('\n').unwrap_or(line);
    l.strip_suffix('\r').unwrap_or(l)
}

/// The new value: `~/...` if the old one used `~/` and the path is under
/// home, else the full path; quoted if it has spaces and was not quoted.
fn render_path(new_path: &Path, home: &Path, tilde: bool, quoted: bool) -> String {
    let full = new_path.display().to_string();
    let text = match new_path.strip_prefix(home) {
        Ok(rel) if tilde => format!("~/{}", rel.display()),
        _ => full,
    };
    if !quoted && text.contains(char::is_whitespace) {
        format!("\"{text}\"")
    } else {
        text
    }
}

/// The planned change of one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileUpdate {
    /// The real file (symlinks followed, so a linked config stays linked).
    pub path: PathBuf,
    /// The text before the update: the backup if one exists for this
    /// stamp (a resumed run), else the file now.
    pub original: String,
    pub updated: String,
    pub changes: Vec<LineChange>,
    pub mode: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigPlan {
    /// Only files with at least one change.
    pub files: Vec<FileUpdate>,
    pub listed: Vec<ListedLine>,
}

impl ConfigPlan {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// A short diff for the dry-run: per file, `-` old line, `+` new line.
    pub fn diff(&self) -> String {
        let mut s = String::new();
        for f in &self.files {
            s.push_str(&format!(
                "--- {}\n+++ {}\n",
                f.path.display(),
                f.path.display()
            ));
            for c in &f.changes {
                s.push_str(&format!(
                    "@@ line {} @@\n-{}\n+{}\n",
                    c.line, c.before, c.after
                ));
            }
        }
        s
    }
}

/// `<file>.keysteward-<stamp>`.
pub fn backup_path(file: &Path, stamp: &str) -> PathBuf {
    let mut s = file.as_os_str().to_owned();
    s.push(format!(".keysteward-{stamp}"));
    PathBuf::from(s)
}

/// Builds the plan for `files` (the user's config and its includes, from
/// `inventory::scan_config`). Reads only. Missing files are skipped.
pub fn plan_config_update(
    files: &[PathBuf],
    old_path: &Path,
    new_path: &Path,
    home: &Path,
    stamp: &str,
) -> Result<ConfigPlan, ConfigError> {
    check_stamp(stamp)?;
    let mut plan = ConfigPlan::default();
    let mut seen: Vec<PathBuf> = Vec::new();
    for file in files {
        let real = match fs::canonicalize(file) {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_err(file)(e)),
        };
        if seen.contains(&real) {
            continue;
        }
        seen.push(real.clone());
        let backup = backup_path(&real, stamp);
        let original = match fs::read_to_string(&backup) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::read_to_string(&real).map_err(io_err(&real))?
            }
            Err(e) => return Err(io_err(&backup)(e)),
        };
        let u = update_text(&original, old_path, new_path, home);
        let lines: Vec<&str> = original.split_inclusive('\n').collect();
        for n in u.listed {
            plan.listed.push(ListedLine {
                path: real.clone(),
                line: n,
                text: trim_eol(lines[n - 1]).to_string(),
            });
        }
        if u.changes.is_empty() {
            continue;
        }
        let mode = fs::metadata(&real)
            .map_err(io_err(&real))?
            .permissions()
            .mode()
            & 0o7777;
        plan.files.push(FileUpdate {
            path: real,
            original,
            updated: u.updated,
            changes: u.changes,
            mode,
        });
    }
    Ok(plan)
}

/// Writes the plan. Per file: already updated (resumed run): skip.
/// Otherwise the file must still hold the planned original, else
/// [`ConfigError::Changed`] and nothing is written to it. The backup is
/// written first, then the new text through a temp file and `rename`.
/// Returns the files written.
pub fn apply_config_update(plan: &ConfigPlan, stamp: &str) -> Result<Vec<PathBuf>, ConfigError> {
    check_stamp(stamp)?;
    let mut written = Vec::new();
    for f in &plan.files {
        let now = fs::read_to_string(&f.path).map_err(io_err(&f.path))?;
        if now == f.updated {
            continue;
        }
        if now != f.original {
            return Err(ConfigError::Changed(f.path.clone()));
        }
        let backup = backup_path(&f.path, stamp);
        match fs::read_to_string(&backup) {
            Ok(b) if b == f.original => {}
            Ok(_) => return Err(ConfigError::Changed(backup)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                write_new(&backup, &f.original, 0o600)?;
            }
            Err(e) => return Err(io_err(&backup)(e)),
        }
        replace(&f.path, &f.updated, f.mode)?;
        written.push(f.path.clone());
    }
    Ok(written)
}

/// Puts the backups of `stamp` back, for each of `files` that has one.
/// A file that holds the updated text gets the backup text again; a file
/// that already holds the backup text is left alone; a file that holds
/// anything else is not touched ([`ConfigError::Changed`]). Backups are
/// kept. Returns the files restored.
pub fn restore_config(
    files: &[PathBuf],
    old_path: &Path,
    new_path: &Path,
    home: &Path,
    stamp: &str,
) -> Result<Vec<PathBuf>, ConfigError> {
    let plan = plan_config_update(files, old_path, new_path, home, stamp)?;
    let mut restored = Vec::new();
    for f in &plan.files {
        if fs::symlink_metadata(backup_path(&f.path, stamp)).is_err() {
            continue;
        }
        let now = fs::read_to_string(&f.path).map_err(io_err(&f.path))?;
        if now == f.original {
            continue;
        }
        if now != f.updated {
            return Err(ConfigError::Changed(f.path.clone()));
        }
        replace(&f.path, &f.original, f.mode)?;
        restored.push(f.path.clone());
    }
    Ok(restored)
}

fn check_stamp(stamp: &str) -> Result<(), ConfigError> {
    let ok = !stamp.is_empty()
        && stamp
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(ConfigError::BadStamp(stamp.to_string()))
    }
}

/// Creates `path` (fails if it exists) with `mode` and writes `text`.
fn write_new(path: &Path, text: &str, mode: u32) -> Result<(), ConfigError> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(io_err(path))?;
    f.write_all(text.as_bytes()).map_err(io_err(path))?;
    f.sync_all().map_err(io_err(path))?;
    // The umask may have dropped bits; set the mode we want.
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io_err(path))
}

/// Replaces `path` with `text` through a temp file in the same dir.
fn replace(path: &Path, text: &str, mode: u32) -> Result<(), ConfigError> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".keysteward-tmp-{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    if fs::symlink_metadata(&tmp).is_ok() {
        // Our own leftover from a crashed run of this process id.
        fs::remove_file(&tmp).map_err(io_err(&tmp))?;
    }
    write_new(&tmp, text, mode)?;
    fs::rename(&tmp, path).map_err(io_err(path))
}
