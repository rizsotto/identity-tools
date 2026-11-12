//! Crash at every journal point, then resume (T13). Mock providers keep
//! their state across the "restart"; the database is opened again.
//!
//! For each point of a clean run: a fresh fixture runs to that point and
//! stops there with no more writes. The invariants must hold right then
//! and at every point of the resumed run, and the resumed run must end in
//! the same state as the clean run.

mod common;

use std::fs;
use std::path::Path;

use common::{Fixture, Recorder, assert_removals_after_fresh_verify};
use inventory::{RotationId, Step, Store};
use rotation::{
    Crash, Ending, EngineError, Hooks, JournalPoint, NoHooks, Summary, check_invariants,
};

/// The first rotation in a fresh database.
const ID: RotationId = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    /// The full rotation.
    Forward,
    /// Every removal fails, then abort with rollback: config restore,
    /// then a rollback at every location.
    Abort,
}

fn fixture(s: Scenario) -> Fixture {
    let f = Fixture::new();
    if s == Scenario::Abort {
        let mut faults = f.world.faults.lock().unwrap();
        for (target, ..) in common::sites() {
            faults.remove_fails.insert(target.label());
        }
        drop(faults);
    }
    f
}

/// Runs the scenario; `hooks` sees the part whose points are counted.
async fn first_run(f: &Fixture, s: Scenario, hooks: &dyn Hooks) -> Result<Summary, EngineError> {
    match s {
        Scenario::Forward => f.start(hooks, true).await,
        Scenario::Abort => {
            let stopped = f.start(&NoHooks, true).await.unwrap();
            assert_eq!(stopped.ending, Ending::Stopped, "{stopped:?}");
            f.world.faults.lock().unwrap().remove_fails.clear();
            f.with_engine(ID, hooks, true, async |e| e.abort(true).await)
                .await
        }
    }
}

fn want_ending(s: Scenario) -> Ending {
    match s {
        Scenario::Forward => Ending::Done,
        Scenario::Abort => Ending::Aborted,
    }
}

fn check(f: &Fixture, at: &str) {
    let store = Store::open(&f.db).unwrap();
    let bad = check_invariants(&store, ID, &f.home.ssh_dir(), f.world.as_ref()).unwrap();
    assert!(bad.is_empty(), "{at}: {bad:#?}");
}

/// Checks the invariants at every point.
struct Checker<'f>(&'f Fixture);

impl Hooks for Checker<'_> {
    fn at(&self, point: &JournalPoint) -> Result<(), Crash> {
        check(self.0, &format!("{point:?}"));
        Ok(())
    }
}

/// The state a run ends in, with fingerprints and paths made comparable
/// across fixtures.
#[derive(Debug, PartialEq, Eq)]
struct EndState {
    phases: Vec<(i64, String, Option<String>)>,
    world: Vec<(String, String, Vec<&'static str>)>,
    rows: Vec<(String, String, String, String)>,
    files: Vec<String>,
    config: String,
    state: String,
    finished: bool,
}

fn files(dir: &Path, prefix: &str, out: &mut Vec<String>) {
    for e in fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let name = format!("{prefix}{}", e.file_name().to_string_lossy());
        if e.file_type().unwrap().is_dir() {
            files(&e.path(), &format!("{name}/"), out);
        } else {
            out.push(name);
        }
    }
}

fn end_state(f: &Fixture) -> EndState {
    let old = f.old_fpr.to_string();
    let new = f.new_fpr().map(|k| k.to_string()).unwrap_or_default();
    let norm = |k: &str| {
        if k == old {
            "old".to_string()
        } else if k == new {
            "new".to_string()
        } else {
            k.to_string()
        }
    };
    let store = f.store();
    let rot = store.rotation(ID).unwrap().unwrap();
    let mut file_list = Vec::new();
    files(&f.home.ssh_dir(), "", &mut file_list);
    file_list.sort();
    EndState {
        phases: store
            .rotation_locations(ID)
            .unwrap()
            .into_iter()
            .map(|l| (l.location_id, l.phase.as_str().to_string(), l.reason))
            .collect(),
        world: f
            .world
            .snapshot()
            .into_iter()
            .map(|(s, k, p)| (s, norm(&k), p))
            .collect(),
        rows: store
            .list()
            .unwrap()
            .into_iter()
            .map(|l| {
                (
                    l.kind.to_string(),
                    l.target.label(),
                    l.purpose.as_str().to_string(),
                    norm(l.key.as_str()),
                )
            })
            .collect(),
        files: file_list,
        config: fs::read_to_string(f.home.ssh_dir().join("config")).unwrap(),
        state: rot.state,
        finished: rot.finished_at.is_some(),
    }
}

fn assert_no_key_blobs(f: &Fixture) {
    let db = fs::read(&f.db).unwrap();
    let mut pubs = Vec::new();
    files(&f.home.ssh_dir(), "", &mut pubs);
    for p in pubs.iter().filter(|p| p.ends_with(".pub")) {
        let text = fs::read_to_string(f.home.ssh_dir().join(p)).unwrap();
        let blob = text.split_whitespace().nth(1).unwrap();
        assert!(
            !db.windows(blob.len()).any(|w| w == blob.as_bytes()),
            "{p} blob in the database"
        );
    }
}

async fn crash_resume_at_every_point(s: Scenario, step: Step) {
    let clean = fixture(s);
    let rec = Recorder::default();
    let summary = first_run(&clean, s, &rec).await.unwrap();
    assert_eq!(summary.ending, want_ending(s), "{summary:?}");
    let want = end_state(&clean);
    let points = rec.points();
    let picked: Vec<usize> = (0..points.len())
        .filter(|&i| points[i].step == step)
        .collect();
    assert!(!picked.is_empty(), "no {step:?} points in {s:?}");

    for i in picked {
        let at = format!("{s:?} crash at {i} {:?}", points[i]);
        let f = fixture(s);
        let r = first_run(&f, s, &Recorder::crash_at(i)).await;
        assert!(matches!(r, Err(EngineError::Crashed)), "{at}: {r:?}");
        check(&f, &at);

        let checker = Checker(&f);
        let resumed = f
            .with_engine(ID, &checker, true, async |e| e.run().await)
            .await
            .unwrap();
        assert_eq!(resumed.ending, want_ending(s), "{at}: {resumed:?}");
        check(&f, &at);
        assert_eq!(end_state(&f), want, "{at}");
        assert_removals_after_fresh_verify(&f.world.calls(), f.old_fpr.as_str());
        assert_no_key_blobs(&f);
    }
}

#[tokio::test]
async fn crash_resume_at_every_point_mocks_generate() {
    crash_resume_at_every_point(Scenario::Forward, Step::Generate).await;
}

#[tokio::test]
async fn crash_resume_at_every_point_mocks_install() {
    crash_resume_at_every_point(Scenario::Forward, Step::Install).await;
}

#[tokio::test]
async fn crash_resume_at_every_point_mocks_verify() {
    crash_resume_at_every_point(Scenario::Forward, Step::Verify).await;
}

#[tokio::test]
async fn crash_resume_at_every_point_mocks_config() {
    crash_resume_at_every_point(Scenario::Forward, Step::Config).await;
}

#[tokio::test]
async fn crash_resume_at_every_point_mocks_remove_old() {
    crash_resume_at_every_point(Scenario::Forward, Step::RemoveOld).await;
}

#[tokio::test]
async fn crash_resume_at_every_point_mocks_retire() {
    crash_resume_at_every_point(Scenario::Forward, Step::Retire).await;
}

#[tokio::test]
async fn crash_resume_at_every_point_mocks_rollback() {
    crash_resume_at_every_point(Scenario::Abort, Step::Rollback).await;
}

#[tokio::test]
async fn invariants_hold_at_every_point_of_clean_runs() {
    for s in [Scenario::Forward, Scenario::Abort] {
        let f = fixture(s);
        let checker = Checker(&f);
        let summary = first_run(&f, s, &checker).await.unwrap();
        assert_eq!(summary.ending, want_ending(s));
        check(&f, "end");
    }
}
