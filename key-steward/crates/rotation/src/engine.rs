//! The rotation engine (SPEC 7.2, plan.md "Rotation model").
//!
//! Each step writes a `start` entry (committed), runs its action, then
//! writes `done` or `failed` together with the changes that belong to it:
//! the location phase, the location rows, the new fingerprint. Nothing
//! else changes state. Order: generate, every install, every verify, the
//! config update, every removal, retire.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::SystemTime;

use identity_core::{Fingerprint, PublicKey};
use inventory::{
    Event, LocationId, NewLocation, NewRotation, Phase, Rotation, RotationId, RotationLocation,
    Status, Step, StepEntry, Store, StoreError, Target,
};
use providers::{AddOpts, Provider, VerifyStatus};

use crate::config::{apply_config_update, plan_config_update};
use crate::files::{pub_path, retire};
use crate::gate::{may_remove_old, new_ref, old_ref, remove_old, status_text};
use crate::hooks::{Confirm, Crash, Hooks, JournalPoint, Point};
use crate::keygen::{KeyType, KeygenRequest, Passphrase, generate, read_public};
use crate::sites::Providers;

/// Shown for a location whose `authorized_keys` still trusts the old key
/// as a CA. It blocks retire.
pub const CA_REASON: &str = "old key still trusted as a certificate authority";

/// Local settings of a run. Not stored: they come from the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineEnv {
    /// `~/.ssh`. Retired files go to `<ssh_dir>/retired/`.
    pub ssh_dir: PathBuf,
    /// The home dir, for `~` in the ssh config.
    pub home: PathBuf,
    /// The user's ssh config and the files it includes
    /// (`inventory::scan_config`), for the config update.
    pub config_files: Vec<PathBuf>,
    pub keygen_program: PathBuf,
    pub passphrase: Passphrase,
    pub comment: Option<String>,
}

impl EngineEnv {
    pub fn new(ssh_dir: impl Into<PathBuf>, home: impl Into<PathBuf>) -> Self {
        EngineEnv {
            ssh_dir: ssh_dir.into(),
            home: home.into(),
            config_files: Vec::new(),
            keygen_program: PathBuf::from("ssh-keygen"),
            passphrase: Passphrase::Terminal,
            comment: None,
        }
    }
}

/// What the engine works with.
pub struct Ctx<'a> {
    pub providers: &'a dyn Providers,
    pub hooks: &'a dyn Hooks,
    pub confirm: &'a dyn Confirm,
    pub env: &'a EngineEnv,
}

/// Rotation state (SPEC 7.2), kept in `rotations.state` as a cache of the
/// journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationState {
    Planned,
    NewKeyGenerated,
    Installing,
    Verifying,
    ConfigUpdated,
    RemovingOld,
    Retired,
    Done,
    /// A step failed; Retry, Skip location or Abort.
    Stopped,
}

impl RotationState {
    pub fn as_str(self) -> &'static str {
        match self {
            RotationState::Planned => "planned",
            RotationState::NewKeyGenerated => "new_key_generated",
            RotationState::Installing => "installing",
            RotationState::Verifying => "verifying",
            RotationState::ConfigUpdated => "config_updated",
            RotationState::RemovingOld => "removing_old",
            RotationState::Retired => "retired",
            RotationState::Done => "done",
            RotationState::Stopped => "stopped",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A test hook stopped the engine.
    #[error("stopped at a test point")]
    Crashed,
    #[error("no rotation with id {0}")]
    NoRotation(RotationId),
    #[error("rotation {0} is finished")]
    Finished(RotationId),
    #[error("{0}")]
    Refused(String),
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// Nothing is left to do. The rotation is finished.
    Done,
    /// A step failed. The rotation stays open: Retry, Skip or Abort.
    Stopped,
}

/// A step whose last entry is `failed`: the user decides what next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub step: Step,
    pub location: Option<LocationId>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub rotation: RotationId,
    pub ending: Ending,
    pub locations: Vec<RotationLocation>,
    pub failures: Vec<Failure>,
    /// Why the config update or retire was skipped, and other warnings.
    pub notes: Vec<String>,
}

/// The journal entries of one rotation, oldest first.
pub(crate) struct Journal(pub(crate) Vec<StepEntry>);

impl Journal {
    fn last_at(&self, loc: Option<LocationId>) -> Option<&StepEntry> {
        self.0.iter().rev().find(|e| e.location_id == loc)
    }

    pub(crate) fn has(&self, step: Step, loc: Option<LocationId>, event: Event) -> bool {
        self.0
            .iter()
            .any(|e| e.step == step && e.location_id == loc && e.event == event)
    }

    fn started_anywhere(&self, step: Step) -> bool {
        self.0
            .iter()
            .any(|e| e.step == step && e.event == Event::Start)
    }
}

/// What a step's end entry changes, in the same transaction.
#[derive(Default)]
struct End {
    failed: bool,
    detail: Option<String>,
    phase: Option<Phase>,
    reason: Option<String>,
    new_fpr: Option<Fingerprint>,
    add_row: Option<NewLocation>,
    remove_row: Option<LocationId>,
    state: Option<RotationState>,
}

impl End {
    fn done() -> Self {
        End::default()
    }

    fn failed(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        End {
            failed: true,
            detail: Some(reason.clone()),
            reason: Some(reason),
            ..End::default()
        }
    }

    fn phase(mut self, phase: Phase) -> Self {
        self.phase = Some(phase);
        self
    }
}

pub struct Engine<'a> {
    store: &'a mut Store,
    ctx: Ctx<'a>,
    rot: Rotation,
    new_key: Option<PublicKey>,
    /// Locations (or `None`, the rotation itself) whose last failure the
    /// user asked to retry. Cleared when their next step starts.
    retry: HashSet<Option<LocationId>>,
    retire_declined: bool,
}

impl<'a> Engine<'a> {
    /// Creates the rotation (refused while another one is open) and opens
    /// it. The caller has shown the dry-run and the user confirmed (S-7).
    pub fn start(
        store: &'a mut Store,
        new: &NewRotation,
        ctx: Ctx<'a>,
    ) -> Result<Engine<'a>, EngineError> {
        if new.locations.is_empty() {
            return Err(EngineError::Refused(
                "the rotation has no locations; there is nothing to rotate".into(),
            ));
        }
        let mut new = new.clone();
        new.state = RotationState::Planned.as_str().into();
        let id = store.start_rotation(&new)?;
        Engine::open(store, id, ctx)
    }

    /// Opens an unfinished rotation, to run or resume it.
    pub fn open(
        store: &'a mut Store,
        id: RotationId,
        ctx: Ctx<'a>,
    ) -> Result<Engine<'a>, EngineError> {
        let rot = store.rotation(id)?.ok_or(EngineError::NoRotation(id))?;
        if rot.finished_at.is_some() {
            return Err(EngineError::Finished(id));
        }
        // Key blobs never reach the journal (S-8). Only the `.pub` files
        // are read (S-1).
        if let Ok(old) = read_public(&rot.old_key_path, &pub_path(&rot.old_key_path)) {
            register(store, &old.public_key);
        }
        let mut engine = Engine {
            store,
            ctx,
            rot,
            new_key: None,
            retry: HashSet::new(),
            retire_declined: false,
        };
        if engine.rot.new_fingerprint.is_some() {
            engine.load_new_key()?;
        }
        Ok(engine)
    }

    pub fn id(&self) -> RotationId {
        self.rot.id
    }

    /// Runs every step that is left, in order. A failed step stops its
    /// location, not the others.
    pub async fn run(&mut self) -> Result<Summary, EngineError> {
        self.refresh()?;
        if self.rot.new_fingerprint.is_none() {
            if !self.flagged(&self.journal()?, None) {
                self.generate().await?;
            }
            if self.rot.new_fingerprint.is_none() {
                return self.stop();
            }
        }

        for loc in self.locations()? {
            if loc.phase == Phase::Pending && !self.flagged(&self.journal()?, Some(loc.location_id))
            {
                self.install(&loc).await?;
            }
        }
        for loc in self.locations()? {
            if loc.phase == Phase::Installed
                && !self.flagged(&self.journal()?, Some(loc.location_id))
            {
                self.verify(&loc).await?;
            }
        }

        match self.config_gate()? {
            ConfigGate::Run => {
                self.config().await?;
                if !self.journal()?.has(Step::Config, None, Event::Done) {
                    return self.stop();
                }
            }
            ConfigGate::Hold => return self.stop(),
            ConfigGate::Pass => {}
        }

        for loc in self.locations()? {
            if loc.phase == Phase::Verified
                && !self.flagged(&self.journal()?, Some(loc.location_id))
            {
                self.remove_old(&loc).await?;
            }
        }

        let j = self.journal()?;
        if self.retire_wanted(&j)? && !self.flagged(&j, None) {
            let files = vec![
                self.rot.old_key_path.clone(),
                pub_path(&self.rot.old_key_path),
            ];
            if self.ctx.confirm.retire(&files) {
                self.retire().await?;
            } else {
                self.retire_declined = true;
            }
        }
        self.finish_or_stop()
    }

    /// The user's answer to a failed step: run it again. Clears the
    /// failure of `location` (`None`: the rotation's own step, such as
    /// generate or config), then runs.
    pub async fn retry(&mut self, location: Option<LocationId>) -> Result<Summary, EngineError> {
        self.retry.insert(location);
        self.run().await
    }

    fn refresh(&mut self) -> Result<(), EngineError> {
        self.rot = self
            .store
            .rotation(self.rot.id)?
            .ok_or(EngineError::NoRotation(self.rot.id))?;
        if self.rot.finished_at.is_some() {
            return Err(EngineError::Finished(self.rot.id));
        }
        Ok(())
    }

    fn journal(&self) -> Result<Journal, EngineError> {
        Ok(Journal(self.store.steps(self.rot.id)?))
    }

    fn locations(&self) -> Result<Vec<RotationLocation>, EngineError> {
        Ok(self.store.rotation_locations(self.rot.id)?)
    }

    /// The last entry for this location (or the rotation itself) is a
    /// failure, and the user has not asked to retry it.
    fn flagged(&self, j: &Journal, loc: Option<LocationId>) -> bool {
        !self.retry.contains(&loc) && j.last_at(loc).is_some_and(|e| e.event == Event::Failed)
    }

    fn load_new_key(&mut self) -> Result<(), EngineError> {
        let g = read_public(&self.rot.new_key_path, &pub_path(&self.rot.new_key_path))
            .map_err(|e| EngineError::Refused(format!("cannot read the new public key: {e}")))?;
        if Some(&g.fingerprint) != self.rot.new_fingerprint.as_ref() {
            return Err(EngineError::Refused(format!(
                "{} is not the key this rotation made; check it by hand",
                g.public_path.display()
            )));
        }
        register(self.store, &g.public_key);
        self.new_key = Some(g.public_key);
        Ok(())
    }

    fn hook(
        &self,
        point: Point,
        step: Step,
        location: Option<LocationId>,
    ) -> Result<(), EngineError> {
        self.ctx
            .hooks
            .at(&JournalPoint {
                point,
                step,
                location,
            })
            .map_err(|Crash| EngineError::Crashed)
    }

    /// Writes the `start` entry.
    fn begin(
        &mut self,
        step: Step,
        loc: Option<LocationId>,
        state: RotationState,
    ) -> Result<(), EngineError> {
        self.hook(Point::BeforeStart, step, loc)?;
        let mut tx = self.store.journal_tx()?;
        tx.step(self.rot.id, loc, step, Event::Start, None)?;
        tx.set_state(self.rot.id, state.as_str())?;
        tx.commit()?;
        self.retry.remove(&loc);
        self.hook(Point::AfterStart, step, loc)
    }

    /// Writes the `done` or `failed` entry with its changes.
    fn end(&mut self, step: Step, loc: Option<LocationId>, end: End) -> Result<(), EngineError> {
        self.hook(Point::AfterAction, step, loc)?;
        let id = self.rot.id;
        let event = if end.failed {
            Event::Failed
        } else {
            Event::Done
        };
        let mut tx = self.store.journal_tx()?;
        tx.step(id, loc, step, event, end.detail.as_deref())?;
        if let (Some(l), Some(phase)) = (loc, end.phase) {
            tx.set_phase(id, l, phase, end.reason.as_deref())?;
        }
        if let Some(f) = &end.new_fpr {
            tx.set_new_fingerprint(id, f)?;
        }
        if let Some(row) = &end.add_row {
            tx.add_location(row, &Status::Verified, SystemTime::now())?;
        }
        if let Some(row) = end.remove_row {
            tx.remove_location(row)?;
        }
        if let Some(s) = end.state {
            tx.set_state(id, s.as_str())?;
        }
        tx.commit()?;
        self.refresh()?;
        self.hook(Point::AfterDone, step, loc)
    }

    fn keygen_request(&self) -> Result<KeygenRequest, String> {
        let key_type = match self.rot.new_key_type.as_str() {
            "ed25519" => KeyType::Ed25519,
            "ecdsa" => KeyType::Ecdsa,
            "rsa" => KeyType::Rsa,
            t => return Err(format!("unknown key type {t:?}")),
        };
        let env = self.ctx.env;
        let mut req = KeygenRequest::new(&env.ssh_dir, &self.rot.new_key_path);
        req.key_type = key_type;
        req.comment = env.comment.clone();
        req.passphrase = env.passphrase;
        req.program = env.keygen_program.clone();
        Ok(req)
    }

    async fn generate(&mut self) -> Result<(), EngineError> {
        self.begin(Step::Generate, None, RotationState::Planned)?;
        let end = match self
            .keygen_request()
            .and_then(|r| generate(&r).map_err(|e| e.to_string()))
        {
            Ok(g) if g.fingerprint == self.rot.old_fingerprint => {
                End::failed("the new key has the same fingerprint as the old key")
            }
            Ok(g) => {
                register(self.store, &g.public_key);
                self.new_key = Some(g.public_key);
                End {
                    detail: Some(g.fingerprint.to_string()),
                    new_fpr: Some(g.fingerprint),
                    state: Some(RotationState::NewKeyGenerated),
                    ..End::done()
                }
            }
            Err(e) => End::failed(e),
        };
        self.end(Step::Generate, None, end)
    }

    fn provider(&self, loc: &RotationLocation) -> Result<&'a dyn Provider, String> {
        let providers: &'a dyn Providers = self.ctx.providers;
        providers
            .provider(loc.kind)
            .ok_or_else(|| format!("no provider for {}", loc.kind))
    }

    async fn install(&mut self, loc: &RotationLocation) -> Result<(), EngineError> {
        let l = Some(loc.location_id);
        self.begin(Step::Install, l, RotationState::Installing)?;
        let end = match (self.provider(loc), &self.new_key) {
            (Err(e), _) => End::failed(e),
            (_, None) => End::failed("the new public key is not loaded"),
            (Ok(p), Some(key)) => {
                let opts = AddOpts {
                    purpose: loc.purpose,
                    title: None,
                    like: Some(old_ref(&self.rot, loc.purpose)),
                };
                match p.add(&loc.target, key, &opts).await {
                    Ok(()) => End::done().phase(Phase::Installed),
                    Err(e) => End::failed(e.to_string()),
                }
            }
        };
        let end = if end.failed {
            end.phase(loc.phase)
        } else {
            end
        };
        self.end(Step::Install, l, end)
    }

    async fn verify(&mut self, loc: &RotationLocation) -> Result<(), EngineError> {
        let l = Some(loc.location_id);
        self.begin(Step::Verify, l, RotationState::Verifying)?;
        let key = new_ref(&self.rot, loc.purpose);
        let end = match (self.provider(loc), key) {
            (Err(e), _) => End::failed(e),
            (_, None) => End::failed("the new key has not been made yet"),
            (Ok(p), Some(key)) => match p.verify(&loc.target, &key).await {
                Ok(VerifyStatus::Verified) => End {
                    add_row: Some(NewLocation {
                        kind: loc.kind,
                        target: self.full_target(loc)?,
                        key: key.fingerprint,
                        purpose: loc.purpose,
                    }),
                    ..End::done().phase(Phase::Verified)
                },
                Ok(v) => End::failed(format!("the new key does not log in: {}", status_text(&v))),
                Err(e) => End::failed(e.to_string()),
            },
        };
        let end = if end.failed {
            end.phase(loc.phase)
        } else {
            end
        };
        self.end(Step::Verify, l, end)
    }

    /// The stored target of the old key's location row (with the host
    /// details `ssh -G` gave), else the journal's copy.
    fn full_target(&self, loc: &RotationLocation) -> Result<Target, EngineError> {
        Ok(match self.store.get(loc.location_id)? {
            Some(row) => row.target,
            None => loc.target.clone(),
        })
    }

    fn config_gate(&self) -> Result<ConfigGate, EngineError> {
        let j = self.journal()?;
        if !self.rot.update_config || j.has(Step::Config, None, Event::Done) {
            return Ok(ConfigGate::Pass);
        }
        if self.config_skip_reason(&j)?.is_some() {
            return Ok(ConfigGate::Pass);
        }
        if self.flagged(&j, None) {
            return Ok(ConfigGate::Hold);
        }
        Ok(ConfigGate::Run)
    }

    /// Why the config update does not run, if it does not: it runs only
    /// before any removal, and only if every location is verified.
    fn config_skip_reason(&self, j: &Journal) -> Result<Option<String>, EngineError> {
        let open: Vec<String> = self
            .locations()?
            .iter()
            .filter(|l| !matches!(l.phase, Phase::Verified | Phase::OldRemoved))
            .map(|l| format!("{} ({})", l.target.label(), l.phase.as_str()))
            .collect();
        if !open.is_empty() {
            return Ok(Some(format!(
                "ssh config not updated: the new key is not verified at {}; the old key \
                 still works there",
                open.join(", ")
            )));
        }
        if j.started_anywhere(Step::RemoveOld) {
            return Ok(Some(
                "ssh config not updated: removals started before every location was verified"
                    .into(),
            ));
        }
        Ok(None)
    }

    fn stamp(&self) -> String {
        format!("rotation-{}", self.rot.id)
    }

    async fn config(&mut self) -> Result<(), EngineError> {
        self.begin(Step::Config, None, RotationState::ConfigUpdated)?;
        let env = self.ctx.env;
        let stamp = self.stamp();
        let result = plan_config_update(
            &env.config_files,
            &self.rot.old_key_path,
            &self.rot.new_key_path,
            &env.home,
            &stamp,
        )
        .and_then(|plan| apply_config_update(&plan, &stamp));
        let end = match result {
            Ok(written) => End {
                detail: Some(format!("{} files updated", written.len())),
                state: Some(RotationState::ConfigUpdated),
                ..End::done()
            },
            Err(e) => End::failed(e.to_string()),
        };
        self.end(Step::Config, None, end)
    }

    async fn remove_old(&mut self, loc: &RotationLocation) -> Result<(), EngineError> {
        let l = Some(loc.location_id);
        self.begin(Step::RemoveOld, l, RotationState::RemovingOld)?;
        let end = match self.provider(loc) {
            Err(e) => End::failed(e),
            Ok(p) => match may_remove_old(p, &self.rot, loc).await {
                Err(reason) => End::failed(reason),
                Ok(permit) => match remove_old(self.ctx.providers, permit, &self.rot, loc).await {
                    Err(e) => End::failed(e.to_string()),
                    Ok(r) if r.ca_lines_with_old_key.is_empty() => End {
                        remove_row: Some(loc.location_id),
                        ..End::done().phase(Phase::OldRemoved)
                    },
                    Ok(r) => {
                        let lines: Vec<String> = r
                            .ca_lines_with_old_key
                            .iter()
                            .map(|n| n.to_string())
                            .collect();
                        End {
                            detail: Some(format!("cert-authority lines {}", lines.join(","))),
                            reason: Some(CA_REASON.into()),
                            remove_row: Some(loc.location_id),
                            ..End::done().phase(Phase::OldRemoved)
                        }
                    }
                },
            },
        };
        let end = if end.failed {
            end.phase(loc.phase)
        } else {
            end
        };
        self.end(Step::RemoveOld, l, end)
    }

    /// Retire runs once, when the old key is gone from every location and
    /// no location trusts it as a CA.
    fn retire_wanted(&self, j: &Journal) -> Result<bool, EngineError> {
        Ok(!j.has(Step::Retire, None, Event::Done) && self.retire_skip_reason()?.is_none())
    }

    fn retire_skip_reason(&self) -> Result<Option<String>, EngineError> {
        let held: Vec<String> = self
            .locations()?
            .iter()
            .filter(|l| l.phase != Phase::OldRemoved || l.reason.is_some())
            .map(|l| {
                let why = match (&l.phase, &l.reason) {
                    (Phase::OldRemoved, Some(r)) => r.clone(),
                    (p, _) => p.as_str().to_string(),
                };
                format!("{} ({why})", l.target.label())
            })
            .collect();
        if held.is_empty() {
            return Ok(None);
        }
        Ok(Some(format!(
            "old key files kept: the old key is still at {}",
            held.join(", ")
        )))
    }

    async fn retire(&mut self) -> Result<(), EngineError> {
        self.begin(Step::Retire, None, RotationState::Retired)?;
        let end = match retire(&self.ctx.env.ssh_dir, &self.rot.old_key_path) {
            Ok(moved) => End {
                detail: Some(format!("{} files moved", moved.len())),
                state: Some(RotationState::Retired),
                ..End::done()
            },
            Err(e) => End::failed(e.to_string()),
        };
        self.end(Step::Retire, None, end)
    }

    fn failures(&self, j: &Journal) -> Result<Vec<Failure>, EngineError> {
        let mut keys: Vec<Option<LocationId>> = vec![None];
        keys.extend(self.locations()?.iter().map(|l| Some(l.location_id)));
        Ok(keys
            .into_iter()
            .filter(|k| self.flagged(j, *k))
            .filter_map(|k| j.last_at(k))
            .map(|e| Failure {
                step: e.step,
                location: e.location_id,
                reason: e.detail.clone().unwrap_or_default(),
            })
            .collect())
    }

    fn notes(&self, j: &Journal) -> Result<Vec<String>, EngineError> {
        let mut notes = Vec::new();
        if self.rot.update_config
            && !j.has(Step::Config, None, Event::Done)
            && let Some(r) = self.config_skip_reason(j)?
        {
            notes.push(r);
        }
        for l in self.locations()? {
            if l.reason.as_deref() == Some(CA_REASON) {
                notes.push(format!("{}: {CA_REASON}", l.target.label()));
            }
        }
        if !j.has(Step::Retire, None, Event::Done) {
            if let Some(r) = self.retire_skip_reason()? {
                notes.push(r);
            } else if self.retire_declined {
                notes.push("old key files kept: not confirmed".into());
            }
        }
        Ok(notes)
    }

    fn summary(&self, ending: Ending) -> Result<Summary, EngineError> {
        let j = self.journal()?;
        Ok(Summary {
            rotation: self.rot.id,
            ending,
            locations: self.locations()?,
            failures: self.failures(&j)?,
            notes: self.notes(&j)?,
        })
    }

    fn stop(&mut self) -> Result<Summary, EngineError> {
        let mut tx = self.store.journal_tx()?;
        tx.set_state(self.rot.id, RotationState::Stopped.as_str())?;
        tx.commit()?;
        self.retry.clear();
        self.summary(Ending::Stopped)
    }

    fn finish_or_stop(&mut self) -> Result<Summary, EngineError> {
        let j = self.journal()?;
        if !self.failures(&j)?.is_empty() {
            return self.stop();
        }
        let summary = self.summary(Ending::Done)?;
        let mut tx = self.store.journal_tx()?;
        tx.set_state(self.rot.id, RotationState::Done.as_str())?;
        tx.finish(self.rot.id)?;
        tx.commit()?;
        self.retry.clear();
        Ok(summary)
    }
}

enum ConfigGate {
    Run,
    /// The config step failed: no removal until it is retried.
    Hold,
    /// Not wanted, done, or skipped.
    Pass,
}

fn register(store: &mut Store, key: &PublicKey) {
    if let PublicKey::Ssh(k) = key {
        store.add_secret(&k.encoded);
        if let Some(blob) = k.encoded.split_whitespace().nth(1) {
            store.add_secret(blob);
        }
    }
}
