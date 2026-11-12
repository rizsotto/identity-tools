//! Retry, skip, abort, rollback and the lock (T13).

mod common;

use std::fs;
use std::process::Command;

use common::{CONFIG, CONFIG_BOTH, Fixture, Op, Recorder};
use inventory::{Event, Phase, Purpose, RotationId, Step, StoreError};
use rotation::{Ending, EngineError, LockError, NoHooks, RotationLock, check_invariants};

const ID: RotationId = 1;

fn config(f: &Fixture) -> String {
    fs::read_to_string(f.home.ssh_dir().join("config")).unwrap()
}

#[tokio::test]
async fn rollback_never_touches_old_removed_location() {
    let f = Fixture::new();
    f.world
        .faults
        .lock()
        .unwrap()
        .remove_fails
        .insert("srv-b".into());
    let s = f.start(&NoHooks, true).await.unwrap();
    assert_eq!(s.ending, Ending::Stopped);
    assert!(
        config(&f).contains("id_new"),
        "config updated before removals"
    );
    f.world.faults.lock().unwrap().remove_fails.clear();
    let new = f.new_fpr().unwrap();
    let calls_before = f.world.calls().len();

    let s = f
        .with_engine(ID, &NoHooks, true, async |e| e.abort(true).await)
        .await
        .unwrap();
    assert_eq!(s.ending, Ending::Aborted, "{s:?}");
    for l in &s.locations {
        let site = l.target.label();
        if site == "srv-b" {
            assert_eq!(l.phase, Phase::RolledBack);
            assert!(f.world.has(&site, &f.old_fpr, l.purpose));
            assert!(!f.world.has(&site, &new, l.purpose));
        } else {
            assert_eq!(l.phase, Phase::OldRemoved);
            assert!(
                f.world.has(&site, &new, l.purpose),
                "{site} keeps the new key"
            );
        }
    }
    // The abort removed the new key only at srv-b.
    let removes: Vec<_> = f.world.calls()[calls_before..]
        .iter()
        .filter(|c| c.op == Op::Remove)
        .cloned()
        .collect();
    assert_eq!(removes.len(), 1, "{removes:?}");
    assert_eq!(removes[0].site, "srv-b");
    assert_eq!(removes[0].key, new.to_string());

    // Hosts without the old key need the new line: both lines stay.
    assert_eq!(config(&f), CONFIG_BOTH);
    let steps = f.store().steps(ID).unwrap();
    assert!(
        !steps
            .iter()
            .any(|e| e.step == Step::Rollback && e.location_id.is_none())
    );
    assert!(s.notes.iter().any(|n| n.contains("new key stays at")));
    assert!(
        s.notes
            .iter()
            .any(|n| n.contains("keeps both IdentityFile lines"))
    );
    assert!(f.old_path.exists(), "no retire on abort");
    // The new key's row at srv-b went with the rollback.
    let rows = f.store().list_for_key(&new).unwrap();
    assert!(rows.iter().all(|r| r.target.label() != "srv-b"));
}

#[tokio::test]
async fn failed_rollback_keeps_new_key_and_abort_without_rollback_finishes() {
    let f = Fixture::new();
    f.world
        .faults
        .lock()
        .unwrap()
        .verify_missing_next
        .insert("srv-b".into(), 1);
    let s = f.start(&NoHooks, true).await.unwrap();
    assert_eq!(s.ending, Ending::Stopped);
    let new = f.new_fpr().unwrap();
    // The old key no longer logs in at srv-b: the rollback gate refuses.
    f.world
        .faults
        .lock()
        .unwrap()
        .verify_missing
        .insert(("srv-b".into(), f.old_fpr.to_string()));
    let s = f
        .with_engine(ID, &NoHooks, true, async |e| e.abort(true).await)
        .await
        .unwrap();
    assert_eq!(s.ending, Ending::Stopped);
    assert_eq!(s.failures[0].step, Step::Rollback);
    assert!(
        s.failures[0].reason.contains("old key does not log in"),
        "{s:?}"
    );
    assert!(f.world.has("srv-b", &new, Purpose::SshAuth));
    assert_eq!(f.store().rotation(ID).unwrap().unwrap().state, "aborting");

    // A resume goes on with the abort, not forward.
    let s = f
        .with_engine(ID, &NoHooks, true, async |e| e.run().await)
        .await
        .unwrap();
    assert_eq!(s.ending, Ending::Stopped);
    assert!(f.world.has("srv-b", &f.old_fpr, Purpose::SshAuth));

    let s = f
        .with_engine(ID, &NoHooks, true, async |e| e.abort(false).await)
        .await
        .unwrap();
    assert_eq!(s.ending, Ending::Aborted);
    assert!(f.world.has("srv-b", &new, Purpose::SshAuth));
    assert!(f.world.has("srv-b", &f.old_fpr, Purpose::SshAuth));
}

#[tokio::test]
async fn skip_keeps_old_key_and_no_retire() {
    let f = Fixture::new();
    f.world
        .faults
        .lock()
        .unwrap()
        .verify_missing_next
        .insert("srv-b".into(), 100);
    let s = f.start(&NoHooks, true).await.unwrap();
    assert_eq!(s.ending, Ending::Stopped);
    let b = s.failures[0].location.unwrap();

    let s = f
        .with_engine(ID, &NoHooks, true, async |e| e.skip(b).await)
        .await
        .unwrap();
    assert_eq!(s.ending, Ending::Done, "{s:?}");
    let loc = s.locations.iter().find(|l| l.location_id == b).unwrap();
    assert_eq!(loc.phase, Phase::Skipped);
    let steps = f.store().steps(ID).unwrap();
    assert!(
        steps
            .iter()
            .any(|e| e.step == Step::Skip && e.location_id == Some(b) && e.event == Event::Done)
    );
    assert!(f.world.has("srv-b", &f.old_fpr, Purpose::SshAuth));
    assert!(f.store().get(b).unwrap().is_some(), "old key keeps its row");
    assert!(f.old_path.exists());
    assert!(!f.home.ssh_dir().join("retired/id_old").exists());
    assert!(
        s.notes
            .iter()
            .any(|n| n.starts_with("old key files kept") && n.contains("srv-b"))
    );
    assert_eq!(config(&f), CONFIG_BOTH);
}

#[tokio::test]
async fn second_process_is_refused() {
    let f = Fixture::new();
    let lock = RotationLock::for_database(&f.db).unwrap();
    assert!(matches!(
        RotationLock::for_database(&f.db),
        Err(LockError::Busy(_))
    ));
    let other = |path: &std::path::Path| {
        Command::new("flock")
            .args(["-n", "-E", "9"])
            .arg(path)
            .arg("true")
            .status()
            .unwrap()
            .code()
    };
    assert_eq!(
        other(&f.lock_path()),
        Some(9),
        "another process gets no lock"
    );
    drop(lock);
    assert_eq!(other(&f.lock_path()), Some(0), "released on drop");

    // One open rotation per database, also in the same process.
    let s = f.start(&NoHooks, true).await;
    assert!(s.is_ok());
    let f2 = Fixture::new();
    f2.world
        .faults
        .lock()
        .unwrap()
        .add_fails
        .insert("srv-a".into());
    assert_eq!(
        f2.start(&NoHooks, true).await.unwrap().ending,
        Ending::Stopped
    );
    assert!(matches!(
        f2.start(&NoHooks, true).await,
        Err(EngineError::Store(StoreError::RotationOpen(1)))
    ));
}

#[tokio::test]
async fn abort_before_install_keeps_new_key_files() {
    let f = Fixture::new();
    // Crash right after the generate step's "done" entry.
    let r = f.start(&Recorder::crash_at(3), true).await;
    assert!(matches!(r, Err(EngineError::Crashed)));
    let s = f
        .with_engine(ID, &NoHooks, true, async |e| e.abort(true).await)
        .await
        .unwrap();
    assert_eq!(s.ending, Ending::Aborted);
    assert!(f.new_path.exists() && f.new_path.with_file_name("id_new.pub").exists());
    assert!(f.old_path.exists());
    assert!(
        f.world
            .calls()
            .iter()
            .all(|c| c.op != Op::Add && c.op != Op::Remove)
    );
    assert!(s.locations.iter().all(|l| l.phase == Phase::Pending));
}

#[tokio::test]
async fn unsettled_step_flags_location_and_changes_nothing() {
    let f = Fixture::new();
    // Points: generate 0..4, install of location 1 is 4..8; 6 is its
    // AfterAction (key added, no "done").
    let r = f.start(&Recorder::crash_at(6), true).await;
    assert!(matches!(r, Err(EngineError::Crashed)));
    f.world
        .faults
        .lock()
        .unwrap()
        .list_fails
        .insert("srv-a".into());
    let before = f.world.calls().len();
    let s = f
        .with_engine(ID, &NoHooks, true, async |e| e.run().await)
        .await
        .unwrap();
    assert_eq!(s.ending, Ending::Stopped);
    let fail = &s.failures[0];
    assert_eq!((fail.step, fail.location), (Step::Install, Some(1)));
    assert!(
        fail.reason.contains("cannot check what happened"),
        "{fail:?}"
    );
    let at_a: Vec<_> = f.world.calls()[before..]
        .iter()
        .filter(|c| c.site == "srv-a" && c.op != Op::List)
        .cloned()
        .collect();
    assert!(at_a.is_empty(), "{at_a:?}");
    assert!(f.world.has("srv-a", &f.old_fpr, Purpose::SshAuth));

    // The location can be listed again: settled, then the rotation ends.
    f.world.faults.lock().unwrap().list_fails.clear();
    let s = f
        .with_engine(ID, &NoHooks, true, async |e| e.run().await)
        .await
        .unwrap();
    assert_eq!(s.ending, Ending::Done, "{s:?}");
    let steps = f.store().steps(ID).unwrap();
    let settled = steps
        .iter()
        .find(|e| e.step == Step::Install && e.location_id == Some(1) && e.event == Event::Done)
        .unwrap();
    assert!(
        settled
            .detail
            .as_deref()
            .unwrap()
            .contains("settled after a restart")
    );
}

#[tokio::test]
async fn abort_before_any_removal_restores_config() {
    let f = Fixture::new();
    // Points: generate 4, six installs 24, six verifies 24, config 4; 56
    // is the first removal's BeforeStart.
    let rec = Recorder::crash_at(56);
    let r = f.start(&rec, true).await;
    assert!(matches!(r, Err(EngineError::Crashed)));
    assert_eq!(rec.points()[56].step, Step::RemoveOld);
    assert_eq!(config(&f), CONFIG_BOTH);

    let s = f
        .with_engine(ID, &NoHooks, true, async |e| e.abort(true).await)
        .await
        .unwrap();
    assert_eq!(s.ending, Ending::Aborted, "{s:?}");
    assert!(s.locations.iter().all(|l| l.phase == Phase::RolledBack));
    assert_eq!(config(&f), CONFIG);
    // Config restored before any rollback removed the new key.
    let steps = f.store().steps(ID).unwrap();
    let restored = steps
        .iter()
        .position(|e| e.step == Step::Rollback && e.location_id.is_none() && e.event == Event::Done)
        .unwrap();
    let first_rollback = steps
        .iter()
        .position(|e| e.step == Step::Rollback && e.location_id.is_some())
        .unwrap();
    assert!(restored < first_rollback);
    let old = f.old_fpr.to_string();
    assert!(
        f.world
            .calls()
            .iter()
            .all(|c| c.op != Op::Remove || c.key != old)
    );
}

fn assert_invariants(f: &Fixture) {
    let bad = check_invariants(&f.store(), ID, &f.env, f.world.as_ref()).unwrap();
    assert!(bad.is_empty(), "{bad:#?}");
}

#[tokio::test]
async fn crash_after_ssh_removal_then_abort_keeps_both_config_lines() {
    let f = Fixture::new();
    // 56..60 is the first removal (srv-a); 58 its AfterAction: the old
    // key is gone, no "done" entry.
    let rec = Recorder::crash_at(58);
    assert!(matches!(
        f.start(&rec, true).await,
        Err(EngineError::Crashed)
    ));
    assert_eq!(rec.points()[58].step, Step::RemoveOld);
    assert!(!f.world.has("srv-a", &f.old_fpr, Purpose::SshAuth));

    let s = f
        .with_engine(ID, &NoHooks, true, async |e| e.abort(true).await)
        .await
        .unwrap();
    assert_eq!(s.ending, Ending::Aborted, "{s:?}");
    let a = s
        .locations
        .iter()
        .find(|l| l.target.label() == "srv-a")
        .unwrap();
    assert_eq!(a.phase, Phase::OldRemoved);
    assert_eq!(config(&f), CONFIG_BOTH, "srv-a needs the new line");
    assert!(
        s.locations
            .iter()
            .filter(|l| l.location_id != a.location_id)
            .all(|l| l.phase == Phase::RolledBack)
    );
    assert_invariants(&f);
}

#[tokio::test]
async fn lost_forge_removal_then_abort_keeps_both_config_lines() {
    let f = Fixture::new();
    {
        let mut faults = f.world.faults.lock().unwrap();
        for (target, ..) in common::sites() {
            if target.label() != "alice at https://gitlab.test" {
                faults.remove_fails.insert(target.label());
            }
        }
        faults
            .remove_lost
            .insert("alice at https://gitlab.test".into());
    }
    let s = f.start(&NoHooks, true).await.unwrap();
    assert_eq!(s.ending, Ending::Stopped);
    assert!(
        !f.world
            .has("alice at https://gitlab.test", &f.old_fpr, Purpose::SshAuth)
    );
    {
        let mut faults = f.world.faults.lock().unwrap();
        faults.remove_fails.clear();
        faults.remove_lost.clear();
    }
    let s = f
        .with_engine(ID, &NoHooks, true, async |e| e.abort(true).await)
        .await
        .unwrap();
    assert_eq!(s.ending, Ending::Aborted, "{s:?}");
    let gl = s
        .locations
        .iter()
        .find(|l| l.kind == inventory::LocationKind::GitLab)
        .unwrap();
    assert_eq!(gl.phase, Phase::OldRemoved);
    assert_eq!(config(&f), CONFIG_BOTH);
    assert_invariants(&f);
}

#[tokio::test]
async fn skip_refused_while_a_step_is_unfinished() {
    let f = Fixture::new();
    // 6 is the AfterAction of the install at srv-a.
    assert!(matches!(
        f.start(&Recorder::crash_at(6), true).await,
        Err(EngineError::Crashed)
    ));
    f.world
        .faults
        .lock()
        .unwrap()
        .list_fails
        .insert("srv-a".into());
    let r = f
        .with_engine(ID, &NoHooks, true, async |e| e.skip(1).await)
        .await;
    assert!(
        matches!(&r, Err(EngineError::Refused(m)) if m.contains("did not finish")),
        "{r:?}"
    );
    let steps = f.store().steps(ID).unwrap();
    assert!(!steps.iter().any(|e| e.step == Step::Skip));
}

#[tokio::test]
async fn skip_refused_after_a_failed_removal_that_took_effect() {
    let f = Fixture::new();
    let gl = "alice at https://gitlab.test";
    {
        let mut faults = f.world.faults.lock().unwrap();
        for (target, ..) in common::sites() {
            if target.label() != gl {
                faults.remove_fails.insert(target.label());
            }
        }
        faults.remove_lost.insert(gl.into());
    }
    let s = f.start(&NoHooks, true).await.unwrap();
    assert_eq!(s.ending, Ending::Stopped);
    let loc = s
        .locations
        .iter()
        .find(|l| l.target.label() == gl)
        .unwrap()
        .location_id;
    assert!(!f.world.has(gl, &f.old_fpr, Purpose::SshAuth));
    f.world.faults.lock().unwrap().remove_lost.clear();

    let r = f
        .with_engine(ID, &NoHooks, true, async |e| e.skip(loc).await)
        .await;
    assert!(
        matches!(&r, Err(EngineError::Refused(m)) if m.contains("already gone")),
        "{r:?}"
    );
    let steps = f.store().steps(ID).unwrap();
    assert!(!steps.iter().any(|e| e.step == Step::Skip));
    let l = f
        .store()
        .rotation_locations(ID)
        .unwrap()
        .into_iter()
        .find(|l| l.location_id == loc)
        .unwrap();
    assert_eq!(l.phase, Phase::OldRemoved);
    assert!(f.store().get(loc).unwrap().is_none(), "old row removed");
    assert_invariants(&f);
}
