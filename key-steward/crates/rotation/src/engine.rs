//! The rotation engine (SPEC 7.2, plan.md "Rotation model").
//!
//! Each step writes a `start` entry (committed), runs its action, then
//! writes `done` or `failed` together with the changes that belong to it:
//! the location phase, the location rows, the new fingerprint. Nothing
//! else changes state. Order: generate, every install, every verify, the
//! config update, every removal, retire.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::SystemTime;

use identity_core::{Fingerprint, PublicKey};
use inventory::{
    Event, LocationId, LocationKind, NewLocation, NewRotation, Phase, Rotation, RotationId,
    RotationLocation, Status, Step, StepEntry, Store, StoreError, Target,
};
use providers::{AddOpts, Provider, VerifyStatus};

use crate::config::{ConfigMode, plan_config_change, restore_config_change};
use crate::gate::{listed, may_roll_back, roll_back};
use crate::keygen::{Recovered, recover};
use crate::lock::RotationLock;

use crate::config::apply_config_update;
use crate::files::{pub_path, retire};
use crate::gate::{may_remove_old, new_ref, old_ref, remove_old, status_text};
use crate::hooks::{Confirm, Crash, Hooks, JournalPoint, Point};
use crate::keygen::{KeyType, KeygenRequest, Passphrase, generate, read_public};
use crate::sites::Providers;
use providers::OldKeyCheck;

/// Shown for a location whose `authorized_keys` still trusts the old key
/// as a CA. It blocks retire.
pub const CA_REASON: &str = "old key still trusted as a certificate authority";

/// Shown for an SSH location where the old key still logs in after its
/// removal. It blocks retire.
pub const STILL_ACCEPTED: &str = "old key still logs in here after its removal";

/// Shown for an SSH location where a check that the old key is refused
/// gave no answer. It blocks retire.
pub const UNCHECKED: &str = "cannot check that the old key is refused";

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
    /// Proof that this process holds the rotation lock.
    pub lock: &'a RotationLock,
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
    /// Abort with rollback asked; rollbacks still to run. A resume goes
    /// on with the abort, never forward.
    Aborting,
    Aborted,
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
            RotationState::Aborting => "aborting",
            RotationState::Aborted => "aborted",
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
    /// Aborted. The rotation is finished.
    Aborted,
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
    fn last(&self, step: Step, loc: Option<LocationId>) -> Option<&StepEntry> {
        self.0
            .iter()
            .rev()
            .find(|e| e.step == step && e.location_id == loc)
    }

    /// Steps whose last entry is `start`: they began and have no end.
    fn open_starts(&self) -> Vec<(Step, Option<LocationId>)> {
        let mut seen = Vec::new();
        let mut out = Vec::new();
        for e in self.0.iter().rev() {
            let k = (e.step, e.location_id);
            if seen.contains(&k) {
                continue;
            }
            seen.push(k);
            if e.event == Event::Start {
                out.push(k);
            }
        }
        out.reverse();
        out
    }

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
    /// Steps found with a `start` and no end that could not be settled in
    /// this run (the location could not be listed). Not written: the next
    /// run tries again.
    unsettled: HashMap<Option<LocationId>, String>,
    retire_declined: bool,
}

/// What settling a `start` with no end found.
enum Settled {
    /// The action took effect: write its `done` entry.
    Done(End),
    /// It did not, or running it again is safe: the run does it again.
    RunAgain,
    /// The location could not be looked at.
    Unsettled(String),
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
            unsettled: HashMap::new(),
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
        self.settle_all().await?;
        if self.aborting() {
            return self.continue_abort().await;
        }
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
            // A `start` with no end: the user said yes before the restart.
            if j.has(Step::Retire, None, Event::Start) || self.ctx.confirm.retire(&files) {
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
        !self.retry.contains(&loc)
            && (self.unsettled.contains_key(&loc)
                || j.last_at(loc).is_some_and(|e| e.event == Event::Failed))
    }

    /// Like [`Engine::flagged`], for one step only (abort mode).
    fn flagged_step(&self, j: &Journal, step: Step, loc: Option<LocationId>) -> bool {
        !self.retry.contains(&loc)
            && (self.unsettled.contains_key(&loc)
                || j.last(step, loc).is_some_and(|e| e.event == Event::Failed))
    }

    fn aborting(&self) -> bool {
        self.rot.state == RotationState::Aborting.as_str()
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
        self.write_end(step, loc, end)?;
        self.hook(Point::AfterDone, step, loc)
    }

    fn write_end(
        &mut self,
        step: Step,
        loc: Option<LocationId>,
        end: End,
    ) -> Result<(), EngineError> {
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
        self.refresh()
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

    /// Why the config step does not run, if it does not. It runs before
    /// any removal; it does not wait for every location, since the old
    /// key stays in the config below the new one until retire.
    fn config_skip_reason(&self, j: &Journal) -> Result<Option<String>, EngineError> {
        Ok(j.started_anywhere(Step::RemoveOld)
            .then(|| "ssh config not updated: removals started before the config step".to_string()))
    }

    fn stamp(&self) -> String {
        format!("rotation-{}", self.rot.id)
    }

    async fn config(&mut self) -> Result<(), EngineError> {
        self.begin(Step::Config, None, RotationState::ConfigUpdated)?;
        let env = self.ctx.env;
        let stamp = self.stamp();
        let result = plan_config_change(
            &env.config_files,
            &self.rot.old_key_path,
            &self.rot.new_key_path,
            &env.home,
            &stamp,
            ConfigMode::InsertAbove,
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
            Ok(p) => match may_remove_old(self.ctx.providers, p, &self.rot, loc).await {
                Err(reason) => End::failed(reason),
                Ok(permit) => match remove_old(self.ctx.providers, permit, &self.rot, loc).await {
                    Err(e) => End::failed(e.to_string()),
                    Ok(r) => {
                        let mut flags = Vec::new();
                        let mut detail = None;
                        if !r.ca_lines_with_old_key.is_empty() {
                            let lines: Vec<String> = r
                                .ca_lines_with_old_key
                                .iter()
                                .map(|n| n.to_string())
                                .collect();
                            detail = Some(format!("cert-authority lines {}", lines.join(",")));
                            flags.push(CA_REASON.to_string());
                        }
                        if loc.kind == LocationKind::SshServer {
                            flags.extend(self.old_key_flag(loc).await);
                        }
                        End {
                            detail,
                            reason: (!flags.is_empty()).then(|| flags.join("; ")),
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

    /// SSH: does the old key still log in after its removal? Only
    /// `Refused` clears; anything else flags the location and blocks
    /// retire.
    async fn old_key_flag(&self, loc: &RotationLocation) -> Option<String> {
        let old = old_ref(&self.rot, loc.purpose);
        match self
            .ctx
            .providers
            .check_old_key(loc.kind, &loc.target, &old)
            .await
        {
            Ok(OldKeyCheck::Refused) => None,
            Ok(OldKeyCheck::StillAccepted) => Some(STILL_ACCEPTED.into()),
            Ok(OldKeyCheck::Unknown(why)) => Some(format!("{UNCHECKED}: {why}")),
            Err(e) => Some(format!("{UNCHECKED}: {e}")),
        }
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
        // First the old `IdentityFile` lines the config step paired with
        // new ones, then the files they name.
        let env = self.ctx.env;
        let lines = if self.journal()?.has(Step::Config, None, Event::Done) {
            let stamp = format!("{}-retire", self.stamp());
            plan_config_change(
                &env.config_files,
                &self.rot.old_key_path,
                &self.rot.new_key_path,
                &env.home,
                &stamp,
                ConfigMode::RemovePaired,
            )
            .and_then(|plan| apply_config_update(&plan, &stamp))
            .map(|w| w.len())
            .map_err(|e| e.to_string())
        } else {
            Ok(0)
        };
        let moved = lines.and_then(|n| {
            retire(&env.ssh_dir, &self.rot.old_key_path)
                .map(|m| (n, m.len()))
                .map_err(|e| e.to_string())
        });
        let end = match moved {
            Ok((n, moved)) => End {
                detail: Some(format!("{n} config files updated, {moved} files moved")),
                state: Some(RotationState::Retired),
                ..End::done()
            },
            Err(e) => End::failed(e),
        };
        self.end(Step::Retire, None, end)
    }

    /// Settles every step that has a `start` and no end (a crash or a
    /// kill). The entry is not trusted: the location is looked at.
    async fn settle_all(&mut self) -> Result<(), EngineError> {
        self.unsettled.clear();
        for (step, loc) in self.journal()?.open_starts() {
            match self.settle(step, loc).await? {
                Settled::Done(end) => {
                    let end = End {
                        detail: Some(match end.detail {
                            Some(d) => format!("settled after a restart: {d}"),
                            None => "settled after a restart".into(),
                        }),
                        ..end
                    };
                    self.write_end(step, loc, end)?;
                    if step == Step::Generate && self.rot.new_fingerprint.is_some() {
                        self.load_new_key()?;
                    }
                }
                Settled::RunAgain => {}
                Settled::Unsettled(reason) => {
                    let reason = format!("cannot check what happened before the restart: {reason}");
                    self.unsettled.insert(loc, reason);
                }
            }
        }
        Ok(())
    }

    async fn settle(
        &mut self,
        step: Step,
        loc: Option<LocationId>,
    ) -> Result<Settled, EngineError> {
        let rl = match loc {
            Some(l) => match self.locations()?.into_iter().find(|r| r.location_id == l) {
                Some(r) => Some(r),
                None => return Ok(Settled::Unsettled(format!("no rotation location {l}"))),
            },
            None => None,
        };
        Ok(match (step, rl) {
            (Step::Generate, _) => {
                let req = match self.keygen_request() {
                    Ok(r) => r,
                    Err(e) => return Ok(Settled::Unsettled(e)),
                };
                match recover(&req) {
                    Ok(Recovered::Done(g)) if g.fingerprint == self.rot.old_fingerprint => {
                        Settled::Done(End::failed(
                            "the new key has the same fingerprint as the old key",
                        ))
                    }
                    Ok(Recovered::Done(g)) => Settled::Done(End {
                        detail: Some(g.fingerprint.to_string()),
                        new_fpr: Some(g.fingerprint),
                        state: Some(RotationState::NewKeyGenerated),
                        ..End::done()
                    }),
                    Ok(Recovered::RunAgain { .. }) => Settled::RunAgain,
                    Err(e) => Settled::Unsettled(e.to_string()),
                }
            }
            (Step::Install, Some(rl)) => {
                let Some(new) = self.rot.new_fingerprint.clone() else {
                    return Ok(Settled::RunAgain);
                };
                match self.list(&rl, false).await {
                    Err(e) => Settled::Unsettled(e),
                    Ok(keys) if listed(&keys, &new, rl.purpose) => {
                        Settled::Done(End::done().phase(Phase::Installed))
                    }
                    Ok(_) => Settled::RunAgain,
                }
            }
            (Step::RemoveOld, Some(rl)) => match self.list(&rl, true).await {
                Err(e) => Settled::Unsettled(e),
                Ok(keys) if listed(&keys, &self.rot.old_fingerprint, rl.purpose) => {
                    Settled::RunAgain
                }
                // SSH: run the gated removal again (it changes nothing
                // now) to learn about `cert-authority` lines.
                Ok(_) if rl.kind == LocationKind::SshServer && !self.aborting() => {
                    Settled::RunAgain
                }
                Ok(_) => Settled::Done(End {
                    reason: (rl.kind == LocationKind::SshServer).then(|| {
                        "old key removed before a restart; cert-authority lines not checked".into()
                    }),
                    remove_row: Some(rl.location_id),
                    ..End::done().phase(Phase::OldRemoved)
                }),
            },
            (Step::Rollback, Some(rl)) => {
                let Some(new) = self.rot.new_fingerprint.clone() else {
                    return Ok(Settled::RunAgain);
                };
                match self.list(&rl, false).await {
                    Err(e) => Settled::Unsettled(e),
                    Ok(keys) if listed(&keys, &new, rl.purpose) => Settled::RunAgain,
                    Ok(_) => Settled::Done(End {
                        remove_row: self.new_row(&rl)?,
                        ..End::done().phase(Phase::RolledBack)
                    }),
                }
            }
            // Verify only reads. Config, the config restore and retire
            // skip what is already done when run again.
            _ => Settled::RunAgain,
        })
    }

    /// Lists `loc`, logging in with the old key or, with `as_new`, the new
    /// key (SSH).
    async fn list(
        &self,
        loc: &RotationLocation,
        as_new: bool,
    ) -> Result<Vec<providers::PublicKeyRef>, String> {
        let login = match new_ref(&self.rot, loc.purpose) {
            Some(new) if as_new => new,
            _ => old_ref(&self.rot, loc.purpose),
        };
        self.ctx
            .providers
            .list_as(loc.kind, &loc.target, &login)
            .await
            .map_err(|e| format!("cannot list the keys at {}: {e}", loc.target.label()))
    }

    /// The location row of the new key that `verify` added for `loc`.
    fn new_row(&self, loc: &RotationLocation) -> Result<Option<LocationId>, EngineError> {
        let Some(new) = &self.rot.new_fingerprint else {
            return Ok(None);
        };
        Ok(self
            .store
            .list_for_key(new)?
            .into_iter()
            .find(|r| {
                r.kind == loc.kind
                    && r.purpose == loc.purpose
                    && r.target.label() == loc.target.label()
            })
            .map(|r| r.id))
    }

    /// The user's answer to a failed location: leave it. The old key stays
    /// there and keeps its location row, so the old key is not retired.
    pub async fn skip(&mut self, location: LocationId) -> Result<Summary, EngineError> {
        self.refresh()?;
        if self.aborting() {
            return Err(EngineError::Refused("the rotation is being aborted".into()));
        }
        self.settle_all().await?;
        let Some(loc) = self
            .locations()?
            .into_iter()
            .find(|l| l.location_id == location)
        else {
            return Err(EngineError::Refused(format!(
                "no location {location} in this rotation"
            )));
        };
        let j = self.journal()?;
        let open = j
            .last_at(Some(location))
            .is_some_and(|e| e.event == Event::Start);
        if open || self.unsettled.contains_key(&Some(location)) {
            return Err(EngineError::Refused(format!(
                "the last step at location {location} did not finish; resume first"
            )));
        }
        if !matches!(
            loc.phase,
            Phase::Pending | Phase::Installed | Phase::Verified
        ) {
            return Err(EngineError::Refused(format!(
                "location {location} is {}; it cannot be skipped",
                loc.phase.as_str()
            )));
        }
        let mut tx = self.store.journal_tx()?;
        let why = "skipped by the user";
        tx.step(
            self.rot.id,
            Some(location),
            Step::Skip,
            Event::Done,
            Some(why),
        )?;
        tx.set_phase(self.rot.id, location, Phase::Skipped, Some(why))?;
        tx.commit()?;
        self.run().await
    }

    /// Stops the rotation. Without `rollback`, or before any install, it
    /// ends here: the new key stays where it was added and its files stay.
    /// With `rollback`: first the ssh config goes back to its backup (if
    /// the config step ran), then the new key is removed wherever the old
    /// key is still listed and still logs in. Locations in `OldRemoved`
    /// keep the new key.
    pub async fn abort(&mut self, rollback: bool) -> Result<Summary, EngineError> {
        self.refresh()?;
        if rollback && self.journal()?.started_anywhere(Step::Install) {
            let mut tx = self.store.journal_tx()?;
            tx.set_state(self.rot.id, RotationState::Aborting.as_str())?;
            tx.commit()?;
            self.refresh()?;
            // Settle in abort mode: an SSH removal that took effect is
            // marked done instead of run again.
            self.settle_all().await?;
            return self.continue_abort().await;
        }
        self.settle_all().await?;
        self.finish_aborted()
    }

    /// Abort: looks again at every location where a removal of the old
    /// key began and is not marked done (a crash, or a lost answer). If
    /// the old key is gone there, the removal is marked done. Returns
    /// whether some location could not be looked at.
    async fn settle_removals(&mut self) -> Result<bool, EngineError> {
        let mut unclear = false;
        let j = self.journal()?;
        for loc in self.locations()? {
            let l = Some(loc.location_id);
            if matches!(loc.phase, Phase::OldRemoved | Phase::RolledBack)
                || !j.has(Step::RemoveOld, l, Event::Start)
            {
                continue;
            }
            match self.list(&loc, true).await {
                Err(_) => unclear = true,
                Ok(keys) if listed(&keys, &self.rot.old_fingerprint, loc.purpose) => {}
                Ok(_) => {
                    let end = End {
                        detail: Some("settled during abort: the old key is gone".into()),
                        reason: (loc.kind == LocationKind::SshServer)
                            .then(|| "old key removed; cert-authority lines not checked".into()),
                        remove_row: Some(loc.location_id),
                        ..End::done().phase(Phase::OldRemoved)
                    };
                    self.write_end(Step::RemoveOld, l, end)?;
                }
            }
        }
        Ok(unclear)
    }

    /// Locations whose new key a rollback removes: an install began there
    /// and the old key was not removed.
    fn rollback_candidates(&self, j: &Journal) -> Result<Vec<RotationLocation>, EngineError> {
        Ok(self
            .locations()?
            .into_iter()
            .filter(|l| {
                matches!(
                    l.phase,
                    Phase::Pending | Phase::Installed | Phase::Verified | Phase::Skipped
                ) && j.has(Step::Install, Some(l.location_id), Event::Start)
            })
            .collect())
    }

    async fn continue_abort(&mut self) -> Result<Summary, EngineError> {
        let unclear = self.settle_removals().await?;
        let j = self.journal()?;
        // The config first, so it never names a key no location accepts.
        // If the old key is gone somewhere, or may be, those hosts need
        // the new line: both lines stay.
        let old_removed = self
            .locations()?
            .iter()
            .any(|l| l.phase == Phase::OldRemoved);
        if j.has(Step::Config, None, Event::Start)
            && !old_removed
            && !unclear
            && !j.has(Step::Rollback, None, Event::Done)
        {
            if !self.flagged_step(&j, Step::Rollback, None) {
                self.restore_config().await?;
            }
            if !self.journal()?.has(Step::Rollback, None, Event::Done) {
                return self.stop();
            }
        }
        for loc in self.rollback_candidates(&self.journal()?)? {
            if !self.flagged_step(&self.journal()?, Step::Rollback, Some(loc.location_id)) {
                self.rollback(&loc).await?;
            }
        }
        if !self.rollback_candidates(&self.journal()?)?.is_empty() {
            return self.stop();
        }
        self.finish_aborted()
    }

    async fn restore_config(&mut self) -> Result<(), EngineError> {
        self.begin(Step::Rollback, None, RotationState::Aborting)?;
        let env = self.ctx.env;
        let end = match restore_config_change(
            &env.config_files,
            &self.rot.old_key_path,
            &self.rot.new_key_path,
            &env.home,
            &self.stamp(),
            ConfigMode::InsertAbove,
        ) {
            Ok(files) => End {
                detail: Some(format!("{} config files restored", files.len())),
                ..End::done()
            },
            Err(e) => End::failed(e.to_string()),
        };
        self.end(Step::Rollback, None, end)
    }

    async fn rollback(&mut self, loc: &RotationLocation) -> Result<(), EngineError> {
        let l = Some(loc.location_id);
        self.begin(Step::Rollback, l, RotationState::Aborting)?;
        let end = match self.provider(loc) {
            Err(e) => End::failed(e),
            Ok(p) => match may_roll_back(self.ctx.providers, p, &self.rot, loc).await {
                Err(reason) => End::failed(reason),
                Ok(permit) => match roll_back(self.ctx.providers, permit, &self.rot, loc).await {
                    Err(e) => End::failed(e.to_string()),
                    Ok(_) => End {
                        remove_row: self.new_row(loc)?,
                        ..End::done().phase(Phase::RolledBack)
                    },
                },
            },
        };
        let end = if end.failed {
            end.phase(loc.phase)
        } else {
            end
        };
        self.end(Step::Rollback, l, end)
    }

    fn finish_aborted(&mut self) -> Result<Summary, EngineError> {
        let mut summary = self.summary(Ending::Aborted)?;
        let kept: Vec<String> = summary
            .locations
            .iter()
            .filter(|l| l.phase == Phase::OldRemoved)
            .map(|l| l.target.label())
            .collect();
        if !kept.is_empty() {
            summary.notes.push(format!(
                "the new key stays at {}: the old key is already gone there",
                kept.join(", ")
            ));
            if self.journal()?.has(Step::Config, None, Event::Done) {
                summary.notes.push(
                    "the ssh config keeps both IdentityFile lines, the new key first; \
                     remove the old one by hand once it is no longer needed"
                        .into(),
                );
            }
        }
        let mut tx = self.store.journal_tx()?;
        tx.set_state(self.rot.id, RotationState::Aborted.as_str())?;
        tx.finish(self.rot.id)?;
        tx.commit()?;
        self.retry.clear();
        Ok(summary)
    }

    fn failures(&self, j: &Journal) -> Result<Vec<Failure>, EngineError> {
        // A skipped, rolled back or finished location is no failure.
        let open = |p: Phase| match p {
            Phase::Pending | Phase::Installed | Phase::Verified => true,
            Phase::Skipped => self.aborting(),
            Phase::OldRemoved | Phase::RolledBack => false,
        };
        let mut keys: Vec<Option<LocationId>> = vec![None];
        keys.extend(
            self.locations()?
                .iter()
                .filter(|l| open(l.phase))
                .map(|l| Some(l.location_id)),
        );
        Ok(keys
            .into_iter()
            .filter(|k| {
                if self.aborting() {
                    self.flagged_step(j, Step::Rollback, *k)
                } else {
                    self.flagged(j, *k)
                }
            })
            .filter_map(|k| j.last_at(k).map(|e| (k, e)))
            .map(|(k, e)| Failure {
                step: e.step,
                location: e.location_id,
                reason: match self.unsettled.get(&k) {
                    Some(r) => r.clone(),
                    None => e.detail.clone().unwrap_or_default(),
                },
            })
            .collect())
    }

    fn notes(&self, j: &Journal) -> Result<Vec<String>, EngineError> {
        let mut notes = Vec::new();
        if !self.rot.update_config {
            let env = self.ctx.env;
            let named = plan_config_change(
                &env.config_files,
                &self.rot.old_key_path,
                &self.rot.new_key_path,
                &env.home,
                &self.stamp(),
                ConfigMode::InsertAbove,
            )
            .is_ok_and(|p| !p.is_empty());
            if named {
                notes.push(format!(
                    "ssh config not changed (not asked for): it still names the old key {}; \
                     add the new key {} by hand",
                    self.rot.old_key_path.display(),
                    self.rot.new_key_path.display()
                ));
            }
        }
        if self.rot.update_config
            && !j.has(Step::Config, None, Event::Done)
            && let Some(r) = self.config_skip_reason(j)?
        {
            notes.push(r);
        }
        for l in self.locations()? {
            if let (Phase::OldRemoved, Some(r)) = (l.phase, &l.reason) {
                notes.push(format!("{}: {r}", l.target.label()));
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
        let state = if self.aborting() {
            RotationState::Aborting
        } else {
            RotationState::Stopped
        };
        let mut tx = self.store.journal_tx()?;
        tx.set_state(self.rot.id, state.as_str())?;
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
