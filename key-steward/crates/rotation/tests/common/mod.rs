//! Mock providers and a fixture for engine tests. The mock world keeps
//! its state across engine "restarts", like real servers and forges.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use identity_core::{Fingerprint, PublicKey};
use inventory::{
    LocationId, LocationKind, NewLocation, NewRotation, Purpose, RotationId, SshHost, Store, Target,
};
use providers::{AddOpts, KeyRef, Provider, ProviderError, PublicKeyRef, RemoveOpts, VerifyStatus};
use rotation::{
    Confirm, Crash, Ctx, Engine, EngineEnv, EngineError, Hooks, JournalPoint, KeyPresence,
    OldKeyCheck, Passphrase, Providers, Removed, RotationLock, Summary,
};
use test_support::TempHome;

pub const BASE: &str = env!("CARGO_TARGET_TMPDIR");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    List,
    Add,
    Remove,
    Verify,
}

/// One provider call, with the engine "process" it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub epoch: u32,
    pub op: Op,
    pub site: String,
    pub key: String,
    pub purpose: Purpose,
    pub ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Obj {
    key: Fingerprint,
    purposes: Vec<Purpose>,
    id: u64,
}

/// Fault switches, by site label.
#[derive(Debug, Default)]
pub struct Faults {
    /// Verify of this key fingerprint at this site says `Missing`.
    pub verify_missing: HashSet<(String, String)>,
    /// The next N verifies of the new key at this site say `Missing`.
    pub verify_missing_next: HashMap<String, usize>,
    pub add_fails: HashSet<String>,
    pub remove_fails: HashSet<String>,
    pub list_fails: HashSet<String>,
    /// GitLab adds the new key for the one purpose asked, not like the
    /// old key's object.
    pub gitlab_add_one_purpose: bool,
    /// What `check_old_key` says at an SSH site. Default: `Refused` if
    /// the old key is gone, else `StillAccepted`.
    pub old_key_check: HashMap<String, OldKeyCheck>,
}

#[derive(Default)]
struct State {
    sites: HashMap<String, Vec<Obj>>,
    /// SSH sites: `cert-authority` lines holding the old key.
    ca_lines: HashMap<String, Vec<usize>>,
    epoch: u32,
    calls: Vec<Call>,
    next_id: u64,
}

#[derive(Default)]
pub struct World {
    state: Mutex<State>,
    pub faults: Mutex<Faults>,
    /// The old key; `verify_missing_next` hits every other key.
    pub old_key: Mutex<Option<Fingerprint>>,
}

impl World {
    pub fn seed(&self, site: &str, key: &Fingerprint, purposes: &[Purpose]) {
        let mut s = self.state.lock().unwrap();
        s.next_id += 1;
        let id = s.next_id;
        s.sites.entry(site.into()).or_default().push(Obj {
            key: key.clone(),
            purposes: purposes.to_vec(),
            id,
        });
    }

    pub fn set_ca_lines(&self, site: &str, lines: Vec<usize>) {
        self.state
            .lock()
            .unwrap()
            .ca_lines
            .insert(site.into(), lines);
    }

    /// Whether `key` serves `purpose` at `site`.
    pub fn has(&self, site: &str, key: &Fingerprint, purpose: Purpose) -> bool {
        let s = self.state.lock().unwrap();
        s.sites.get(site).is_some_and(|objs| {
            objs.iter()
                .any(|o| &o.key == key && o.purposes.contains(&purpose))
        })
    }

    /// Site, key and purposes of every object, sorted.
    pub fn snapshot(&self) -> Vec<(String, String, Vec<&'static str>)> {
        let s = self.state.lock().unwrap();
        let mut v: Vec<_> = s
            .sites
            .iter()
            .flat_map(|(site, objs)| {
                objs.iter().map(move |o| {
                    (
                        site.clone(),
                        o.key.to_string(),
                        o.purposes.iter().map(|p| p.as_str()).collect(),
                    )
                })
            })
            .collect();
        v.sort();
        v
    }

    pub fn calls(&self) -> Vec<Call> {
        self.state.lock().unwrap().calls.clone()
    }

    /// A new engine process starts.
    pub fn restart(&self) {
        self.state.lock().unwrap().epoch += 1;
    }

    fn record(&self, op: Op, site: &str, key: &Fingerprint, purpose: Purpose, ok: bool) {
        let mut s = self.state.lock().unwrap();
        let epoch = s.epoch;
        s.calls.push(Call {
            epoch,
            op,
            site: site.into(),
            key: key.to_string(),
            purpose,
            ok,
        });
    }
}

pub struct MockProvider {
    kind: LocationKind,
    world: Arc<World>,
}

fn fail(what: &str) -> ProviderError {
    ProviderError::Http(format!("mock fault: {what}"))
}

#[async_trait]
impl Provider for MockProvider {
    fn kind(&self) -> LocationKind {
        self.kind
    }

    async fn list(&self, target: &Target) -> Result<Vec<PublicKeyRef>, ProviderError> {
        let site = target.label();
        let none = Fingerprint::Ssh(String::new());
        if self.world.faults.lock().unwrap().list_fails.contains(&site) {
            self.world
                .record(Op::List, &site, &none, Purpose::SshAuth, false);
            return Err(fail("list"));
        }
        self.world
            .record(Op::List, &site, &none, Purpose::SshAuth, true);
        let s = self.world.state.lock().unwrap();
        Ok(s.sites
            .get(&site)
            .into_iter()
            .flatten()
            .flat_map(|o| {
                o.purposes.iter().map(|p| PublicKeyRef {
                    fingerprint: o.key.clone(),
                    purpose: *p,
                    title: None,
                    remote_id: Some(o.id.to_string()),
                })
            })
            .collect())
    }

    async fn add(
        &self,
        target: &Target,
        key: &PublicKey,
        opts: &AddOpts,
    ) -> Result<(), ProviderError> {
        let site = target.label();
        let fpr = key.fingerprint();
        let faults = self.world.faults.lock().unwrap();
        let one_purpose = faults.gitlab_add_one_purpose;
        if faults.add_fails.contains(&site) {
            drop(faults);
            self.world.record(Op::Add, &site, &fpr, opts.purpose, false);
            return Err(fail("add"));
        }
        drop(faults);
        let mut s = self.world.state.lock().unwrap();
        let objs = s.sites.entry(site.clone()).or_default();
        if objs
            .iter()
            .any(|o| o.key == fpr && o.purposes.contains(&opts.purpose))
        {
            drop(s);
            self.world.record(Op::Add, &site, &fpr, opts.purpose, true);
            return Ok(());
        }
        let like = opts.like.as_ref().and_then(|l| {
            objs.iter()
                .find(|o| o.key == l.fingerprint && o.purposes.contains(&l.purpose))
        });
        if self.kind == LocationKind::SshServer && like.is_none() {
            drop(s);
            self.world.record(Op::Add, &site, &fpr, opts.purpose, false);
            return Err(fail("the old key is not in authorized_keys"));
        }
        let purposes = match self.kind {
            LocationKind::GitLab if !one_purpose => like
                .map(|o| o.purposes.clone())
                .unwrap_or(vec![opts.purpose]),
            LocationKind::Forgejo => vec![Purpose::SshAuth, Purpose::SshSigning],
            _ => vec![opts.purpose],
        };
        s.next_id += 1;
        let id = s.next_id;
        s.sites.get_mut(&site).unwrap().push(Obj {
            key: fpr.clone(),
            purposes,
            id,
        });
        drop(s);
        self.world.record(Op::Add, &site, &fpr, opts.purpose, true);
        Ok(())
    }

    async fn remove(
        &self,
        target: &Target,
        key: &Fingerprint,
        opts: &RemoveOpts,
    ) -> Result<(), ProviderError> {
        let site = target.label();
        if self
            .world
            .faults
            .lock()
            .unwrap()
            .remove_fails
            .contains(&site)
        {
            self.world
                .record(Op::Remove, &site, key, opts.purpose, false);
            return Err(fail("remove"));
        }
        let mut s = self.world.state.lock().unwrap();
        let objs = s.sites.entry(site.clone()).or_default();
        if self.kind == LocationKind::SshServer {
            let keep_ok = opts
                .keep
                .as_ref()
                .is_some_and(|k| objs.iter().any(|o| o.key == k.fingerprint && &o.key != key));
            if !keep_ok {
                drop(s);
                self.world
                    .record(Op::Remove, &site, key, opts.purpose, false);
                return Err(fail("the kept key would not remain"));
            }
        }
        objs.retain(|o| !(&o.key == key && o.purposes.contains(&opts.purpose)));
        drop(s);
        self.world
            .record(Op::Remove, &site, key, opts.purpose, true);
        Ok(())
    }

    async fn verify(&self, target: &Target, key: &KeyRef) -> Result<VerifyStatus, ProviderError> {
        let site = target.label();
        let fpr = &key.fingerprint;
        let mut missing = {
            let f = self.world.faults.lock().unwrap();
            f.verify_missing.contains(&(site.clone(), fpr.to_string()))
        };
        if !missing && self.world.old_key.lock().unwrap().as_ref() != Some(fpr) {
            let mut f = self.world.faults.lock().unwrap();
            if let Some(n) = f.verify_missing_next.get_mut(&site).filter(|n| **n > 0) {
                *n -= 1;
                missing = true;
            }
        }
        let ok = !missing && self.world.has(&site, fpr, key.purpose);
        self.world.record(Op::Verify, &site, fpr, key.purpose, ok);
        Ok(if ok {
            VerifyStatus::Verified
        } else {
            VerifyStatus::Missing
        })
    }
}

pub struct MockProviders {
    world: Arc<World>,
    map: HashMap<LocationKind, MockProvider>,
}

impl MockProviders {
    pub fn new(world: &Arc<World>) -> Self {
        let map = [
            LocationKind::SshServer,
            LocationKind::GitHub,
            LocationKind::GitLab,
            LocationKind::Forgejo,
        ]
        .into_iter()
        .map(|kind| {
            (
                kind,
                MockProvider {
                    kind,
                    world: world.clone(),
                },
            )
        })
        .collect();
        MockProviders {
            world: world.clone(),
            map,
        }
    }
}

#[async_trait]
impl Providers for MockProviders {
    fn provider(&self, kind: LocationKind) -> Option<&dyn Provider> {
        self.map.get(&kind).map(|p| p as &dyn Provider)
    }

    async fn list_as(
        &self,
        kind: LocationKind,
        target: &Target,
        login: &KeyRef,
    ) -> Result<Vec<PublicKeyRef>, ProviderError> {
        let site = target.label();
        if kind == LocationKind::SshServer
            && !self.world.has(&site, &login.fingerprint, Purpose::SshAuth)
        {
            return Err(fail("the login key is not accepted"));
        }
        self.map[&kind].list(target).await
    }

    async fn check_old_key(
        &self,
        _kind: LocationKind,
        target: &Target,
        old: &KeyRef,
    ) -> Result<OldKeyCheck, ProviderError> {
        let site = target.label();
        if let Some(c) = self.world.faults.lock().unwrap().old_key_check.get(&site) {
            return Ok(c.clone());
        }
        Ok(if self.world.has(&site, &old.fingerprint, old.purpose) {
            OldKeyCheck::StillAccepted
        } else {
            OldKeyCheck::Refused
        })
    }

    async fn remove_key(
        &self,
        kind: LocationKind,
        target: &Target,
        key: &Fingerprint,
        opts: &RemoveOpts,
    ) -> Result<Removed, ProviderError> {
        self.map[&kind].remove(target, key, opts).await?;
        let s = self.world.state.lock().unwrap();
        let ca = match kind {
            LocationKind::SshServer => s.ca_lines.get(&target.label()).cloned(),
            _ => None,
        };
        Ok(Removed {
            ca_lines_with_old_key: ca.unwrap_or_default(),
        })
    }
}

pub struct Answer(pub bool);

impl Confirm for Answer {
    fn retire(&self, _: &[PathBuf]) -> bool {
        self.0
    }
}

/// Records every journal point; crashes at point number `crash_at`.
#[derive(Default)]
pub struct Recorder {
    pub points: Mutex<Vec<JournalPoint>>,
    pub crash_at: Option<usize>,
    count: AtomicUsize,
}

impl Recorder {
    pub fn crash_at(n: usize) -> Self {
        Recorder {
            crash_at: Some(n),
            ..Recorder::default()
        }
    }

    pub fn points(&self) -> Vec<JournalPoint> {
        self.points.lock().unwrap().clone()
    }
}

impl Hooks for Recorder {
    fn at(&self, point: &JournalPoint) -> Result<(), Crash> {
        let n = self.count.fetch_add(1, Ordering::SeqCst);
        self.points.lock().unwrap().push(*point);
        if self.crash_at == Some(n) {
            return Err(Crash);
        }
        Ok(())
    }
}

/// Sites of the standard fixture: label, kind, purpose, old key purposes
/// of the remote object.
pub fn sites() -> Vec<(Target, LocationKind, Purpose, Vec<Purpose>)> {
    let acct = |base: &str| Target::Account {
        base_url: base.into(),
        account: "alice".into(),
    };
    use Purpose::{SshAuth, SshSigning};
    vec![
        (
            Target::Ssh(SshHost::new("srv-a")),
            LocationKind::SshServer,
            SshAuth,
            vec![SshAuth],
        ),
        (
            Target::Ssh(SshHost::new("srv-b")),
            LocationKind::SshServer,
            SshAuth,
            vec![SshAuth],
        ),
        (
            acct("https://github.test"),
            LocationKind::GitHub,
            SshAuth,
            vec![SshAuth],
        ),
        (
            acct("https://github.test"),
            LocationKind::GitHub,
            SshSigning,
            vec![SshSigning],
        ),
        (
            acct("https://gitlab.test"),
            LocationKind::GitLab,
            SshAuth,
            vec![SshAuth, SshSigning],
        ),
        (
            acct("https://forgejo.test"),
            LocationKind::Forgejo,
            SshAuth,
            vec![SshAuth, SshSigning],
        ),
    ]
}

pub fn keygen(path: &Path) {
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "old@test", "-f"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

pub fn fingerprint(pub_path: &Path) -> Fingerprint {
    let bytes = fs::read(pub_path).unwrap();
    identity_core::parse_public_keys(&bytes).unwrap()[0]
        .key
        .as_ref()
        .unwrap()
        .fingerprint()
}

pub const CONFIG: &str =
    "Host srv-a\n    IdentityFile ~/.ssh/id_old\nHost srv-b\n    IdentityFile ~/.ssh/id_old\n";

/// [`CONFIG`] after the config step: the new key above the old one.
pub const CONFIG_BOTH: &str = "Host srv-a\n    IdentityFile ~/.ssh/id_new\n    IdentityFile ~/.ssh/id_old\n\
                               Host srv-b\n    IdentityFile ~/.ssh/id_new\n    IdentityFile ~/.ssh/id_old\n";

/// [`CONFIG`] after retire: only the new key.
pub const CONFIG_NEW: &str =
    "Host srv-a\n    IdentityFile ~/.ssh/id_new\nHost srv-b\n    IdentityFile ~/.ssh/id_new\n";

/// A temp home with an old key, a database with its locations, a mock
/// world holding the old key, and an ssh config naming it.
pub struct Fixture {
    pub home: TempHome,
    pub world: Arc<World>,
    pub db: PathBuf,
    pub env: EngineEnv,
    pub old_fpr: Fingerprint,
    pub old_path: PathBuf,
    pub new_path: PathBuf,
    pub locations: Vec<LocationId>,
    pub update_config: bool,
}

impl Fixture {
    pub fn new() -> Self {
        Self::with_sites(sites())
    }

    pub fn with_sites(sites: Vec<(Target, LocationKind, Purpose, Vec<Purpose>)>) -> Self {
        let home = TempHome::new(BASE);
        let ssh = home.ssh_dir();
        let old_path = ssh.join("id_old");
        keygen(&old_path);
        let old_fpr = fingerprint(&ssh.join("id_old.pub"));
        let config = ssh.join("config");
        fs::write(&config, CONFIG).unwrap();
        let db = home.path().join("data").join("ks.db");
        let mut store = Store::open(&db).unwrap();
        let world = Arc::new(World::default());
        *world.old_key.lock().unwrap() = Some(old_fpr.clone());
        let mut locations = Vec::new();
        let mut seeded: HashSet<(String, Vec<Purpose>)> = HashSet::new();
        for (target, kind, purpose, purposes) in sites {
            let id = store
                .add(&NewLocation {
                    kind,
                    target: target.clone(),
                    key: old_fpr.clone(),
                    purpose,
                })
                .unwrap()
                .id();
            locations.push(id);
            if seeded.insert((target.label(), purposes.clone())) {
                world.seed(&target.label(), &old_fpr, &purposes);
            }
        }
        let mut env = EngineEnv::new(&ssh, home.path());
        env.config_files = vec![config];
        env.passphrase = Passphrase::Empty;
        env.comment = Some("new@test".into());
        Fixture {
            new_path: ssh.join("id_new"),
            home,
            world,
            db,
            env,
            old_fpr,
            old_path,
            locations,
            update_config: true,
        }
    }

    pub fn new_rotation(&self) -> NewRotation {
        NewRotation {
            old_fingerprint: self.old_fpr.clone(),
            old_key_path: self.old_path.clone(),
            new_key_path: self.new_path.clone(),
            new_key_type: "ed25519".into(),
            update_config: self.update_config,
            state: String::new(),
            locations: self.locations.clone(),
        }
    }

    pub fn lock_path(&self) -> PathBuf {
        self.db.with_file_name("rotation.lock")
    }

    pub fn store(&self) -> Store {
        Store::open(&self.db).unwrap()
    }

    pub fn new_fpr(&self) -> Option<Fingerprint> {
        let p = self.new_path.with_file_name("id_new.pub");
        p.exists().then(|| fingerprint(&p))
    }

    /// Starts the rotation in a fresh "process" and runs it.
    pub async fn start(&self, hooks: &dyn Hooks, confirm: bool) -> Result<Summary, EngineError> {
        self.world.restart();
        let providers = MockProviders::new(&self.world);
        let mut store = self.store();
        let lock = RotationLock::acquire(&self.lock_path()).unwrap();
        let ctx = Ctx {
            providers: &providers,
            hooks,
            confirm: &Answer(confirm),
            env: &self.env,
            lock: &lock,
        };
        let mut engine = Engine::start(&mut store, &self.new_rotation(), ctx)?;
        engine.run().await
    }

    /// Opens rotation `id` in a fresh "process" and calls `f` on it.
    pub async fn with_engine<T>(
        &self,
        id: RotationId,
        hooks: &dyn Hooks,
        confirm: bool,
        f: impl AsyncFnOnce(&mut Engine<'_>) -> Result<T, EngineError>,
    ) -> Result<T, EngineError> {
        self.world.restart();
        let providers = MockProviders::new(&self.world);
        let mut store = self.store();
        let lock = RotationLock::acquire(&self.lock_path()).unwrap();
        let ctx = Ctx {
            providers: &providers,
            hooks,
            confirm: &Answer(confirm),
            env: &self.env,
            lock: &lock,
        };
        let mut engine = Engine::open(&mut store, id, ctx)?;
        f(&mut engine).await
    }
}

impl KeyPresence for World {
    fn has_key(&self, loc: &inventory::RotationLocation, key: &Fingerprint) -> bool {
        self.has(&loc.target.label(), key, loc.purpose)
    }
}

/// Every removal of the old key comes right after a verify of the new key
/// at that site and purpose that said `Verified`, in the same process, and
/// after the verify step of that location.
pub fn assert_removals_after_fresh_verify(calls: &[Call], old: &str) {
    for (i, c) in calls.iter().enumerate() {
        if c.op != Op::Remove || c.key != old {
            continue;
        }
        let fresh = calls[..i]
            .iter()
            .rev()
            .take_while(|p| p.epoch == c.epoch)
            .any(|p| {
                p.op == Op::Verify
                    && p.ok
                    && p.site == c.site
                    && p.purpose == c.purpose
                    && p.key != old
            });
        assert!(
            fresh,
            "removal {i} {c:?} without a fresh verify in the same process"
        );
    }
}
