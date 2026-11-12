//! Safety checks over a rotation at any moment, for crash tests (T13,
//! T15). They read the journal, the location store, the key files and,
//! through [`KeyPresence`], the real state of each location.

use std::fs;
use std::path::{Path, PathBuf};

use identity_core::Fingerprint;
use inventory::{
    Event, LocationKind, Phase, Resolved, RotationId, RotationLocation, Step, StepEntry, Store,
    StoreError, expand_identity,
};

use crate::engine::EngineEnv;

/// Where the keys really are: server files, fake forge state, mocks.
pub trait KeyPresence {
    /// Whether `key` serves the location's purpose at its site.
    fn has_key(&self, loc: &RotationLocation, key: &Fingerprint) -> bool;
}

/// Checks the invariants of rotation `id`. Returns one line per broken
/// rule; empty means all hold.
///
/// - S-3: each location holds the old key, or the new key and a `verify`
///   `done` for it there. Pending, installed, skipped and rolled back
///   locations hold the old key.
/// - Every `remove_old` `done` comes after a `verify` `done` at the same
///   location; a rolled back location had no `remove_old` `done`.
/// - An `OldRemoved` location has no row for the old key.
/// - `config` started only before any `remove_old` started.
/// - `retire` `done` only if every location is `OldRemoved`.
/// - The new private key file exists once `generate` is done.
/// - S-2: the old private key file exists, at its path or in
///   `<ssh_dir>/retired/`.
/// - With the config update on: each SSH host whose `Host` block names
///   the old or the new key names at least one that the host accepts.
pub fn check_invariants(
    store: &Store,
    id: RotationId,
    env: &EngineEnv,
    presence: &dyn KeyPresence,
) -> Result<Vec<String>, StoreError> {
    let ssh_dir = env.ssh_dir.as_path();
    let mut bad = Vec::new();
    let Some(rot) = store.rotation(id)? else {
        return Ok(vec![format!("no rotation {id}")]);
    };
    let steps = store.steps(id)?;
    let locations = store.rotation_locations(id)?;
    let pos = |step: Step, l: Option<i64>, ev: Event| -> Option<usize> {
        steps
            .iter()
            .position(|e| e.step == step && e.location_id == l && e.event == ev)
    };
    let all =
        |step: Step, l: Option<i64>, ev: Event| -> Vec<usize> { positions(&steps, step, l, ev) };

    for loc in &locations {
        let l = Some(loc.location_id);
        let label = format!("{} ({})", loc.target.label(), loc.purpose.as_str());
        let old = presence.has_key(loc, &rot.old_fingerprint);
        let verified = pos(Step::Verify, l, Event::Done).is_some();
        let new = rot
            .new_fingerprint
            .as_ref()
            .is_some_and(|f| presence.has_key(loc, f));
        if !old && !(new && verified) {
            bad.push(format!(
                "{label}: neither the old key nor a verified new key is there"
            ));
        }
        let keeps_old = matches!(
            loc.phase,
            Phase::Pending | Phase::Installed | Phase::Skipped | Phase::RolledBack
        );
        if keeps_old && !old {
            bad.push(format!(
                "{label}: {} but the old key is gone",
                loc.phase.as_str()
            ));
        }
        let first_verify = pos(Step::Verify, l, Event::Done);
        for r in all(Step::RemoveOld, l, Event::Done) {
            if first_verify.is_none_or(|v| v > r) {
                bad.push(format!("{label}: old key removed before a verify"));
            }
        }
        if pos(Step::Rollback, l, Event::Done).is_some()
            && pos(Step::RemoveOld, l, Event::Done).is_some()
        {
            bad.push(format!(
                "{label}: rolled back after the old key was removed"
            ));
        }
        if rot.update_config
            && loc.kind == LocationKind::SshServer
            && let inventory::Target::Ssh(host) = &loc.target
        {
            let named: Vec<PathBuf> = env
                .config_files
                .iter()
                .filter_map(|f| fs::read_to_string(f).ok())
                .flat_map(|t| host_keys(&t, &host.alias, &env.home))
                .filter(|p| p == &rot.old_key_path || p == &rot.new_key_path)
                .collect();
            let works = named
                .iter()
                .any(|p| if p == &rot.old_key_path { old } else { new });
            if !named.is_empty() && !works {
                bad.push(format!(
                    "{label}: the ssh config names only keys the host does not accept"
                ));
            }
        }
        if loc.phase == Phase::OldRemoved && store.get(loc.location_id)?.is_some() {
            bad.push(format!(
                "{label}: old key removed but its location row is still there"
            ));
        }
    }

    let first_remove = steps
        .iter()
        .position(|e| e.step == Step::RemoveOld && e.event == Event::Start);
    if let (Some(c), Some(r)) = (pos(Step::Config, None, Event::Start), first_remove)
        && c > r
    {
        bad.push("config updated after a removal started".into());
    }
    if pos(Step::Retire, None, Event::Done).is_some()
        && locations.iter().any(|l| l.phase != Phase::OldRemoved)
    {
        bad.push("old key retired while a location still holds it".into());
    }
    if rot.new_fingerprint.is_some() && fs::symlink_metadata(&rot.new_key_path).is_err() {
        bad.push(format!(
            "new private key {} is gone",
            rot.new_key_path.display()
        ));
    }
    if fs::symlink_metadata(&rot.old_key_path).is_err() && !in_retired(ssh_dir, &rot.old_key_path) {
        bad.push(format!(
            "old private key {} is gone and not in retired/",
            rot.old_key_path.display()
        ));
    }
    Ok(bad)
}

fn positions(steps: &[StepEntry], step: Step, l: Option<i64>, ev: Event) -> Vec<usize> {
    steps
        .iter()
        .enumerate()
        .filter(|(_, e)| e.step == step && e.location_id == l && e.event == ev)
        .map(|(i, _)| i)
        .collect()
}

/// A file `<name>` or `<name>-N` in `<ssh_dir>/retired/`.
fn in_retired(ssh_dir: &Path, old: &Path) -> bool {
    let Some(name) = old.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Ok(dir) = fs::read_dir(ssh_dir.join(crate::files::RETIRED_DIR)) else {
        return false;
    };
    dir.filter_map(|e| e.ok()).any(|e| {
        let n = e.file_name();
        let n = n.to_string_lossy();
        n == name
            || n.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('-'))
                .is_some_and(|num| num.chars().all(|c| c.is_ascii_digit()) && !num.is_empty())
    })
}

/// `IdentityFile` paths that apply to `alias`: lines before any `Host`,
/// and in `Host` blocks with `alias` or `*` among their patterns. `Match`
/// blocks are not followed. Good enough for test configs.
fn host_keys(text: &str, alias: &str, home: &Path) -> Vec<PathBuf> {
    let sep = |c: char| c.is_whitespace() || c == '=';
    let mut active = true;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(i) = line.find(sep) else {
            continue;
        };
        let (kw, rest) = (&line[..i], line[i..].trim_start_matches(sep));
        if kw.eq_ignore_ascii_case("host") {
            active = rest.split_whitespace().any(|p| p == alias || p == "*");
        } else if kw.eq_ignore_ascii_case("match") {
            active = false;
        } else if active && kw.eq_ignore_ascii_case("identityfile") {
            let value = match rest.strip_prefix('"') {
                Some(r) => r.split('"').next().unwrap_or(""),
                None => rest.split_whitespace().next().unwrap_or(""),
            };
            if let Some(p) = expand_identity(value, home, &Resolved::default()) {
                out.push(p);
            }
        }
    }
    out
}
