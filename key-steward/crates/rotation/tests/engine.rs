//! Rotation engine with mock providers: happy path and the S-3 gate (T12).

mod common;

use std::fs;

use common::{Fixture, Op, Recorder, assert_removals_after_fresh_verify};
use inventory::{Event, LocationKind, Phase, Purpose, SshHost, Step, Target};
use rotation::{CA_REASON, Ending, NoHooks, OldKeyCheck, Point, STILL_ACCEPTED, UNCHECKED};

fn step_order(steps: &[inventory::StepEntry]) -> Vec<(Step, Event)> {
    steps.iter().map(|e| (e.step, e.event)).collect()
}

#[tokio::test]
async fn rotation_runs_all_steps_with_mocks() {
    let f = Fixture::new();
    let rec = Recorder::default();
    let s = f.start(&rec, true).await.unwrap();
    assert_eq!(s.ending, Ending::Done, "{s:?}");
    assert!(s.failures.is_empty() && s.notes.is_empty(), "{s:?}");
    let new = f.new_fpr().expect("new key made");
    assert_ne!(new, f.old_fpr);

    // Every location: old key gone, new key in, phase OldRemoved.
    for l in &s.locations {
        assert_eq!(l.phase, Phase::OldRemoved, "{l:?}");
        let site = l.target.label();
        assert!(!f.world.has(&site, &f.old_fpr, l.purpose), "{site}");
        assert!(f.world.has(&site, &new, l.purpose), "{site}");
    }
    // GitLab's new key serves both purposes, like the old one.
    assert!(
        f.world
            .has("alice at https://gitlab.test", &new, Purpose::SshSigning)
    );

    // Journal: start then done for each step, in the binding order.
    let store = f.store();
    let steps = store.steps(s.rotation).unwrap();
    let n = f.locations.len();
    let mut want = vec![
        (Step::Generate, Event::Start),
        (Step::Generate, Event::Done),
    ];
    for step in [Step::Install, Step::Verify] {
        for _ in 0..n {
            want.extend([(step, Event::Start), (step, Event::Done)]);
        }
    }
    want.extend([(Step::Config, Event::Start), (Step::Config, Event::Done)]);
    for _ in 0..n {
        want.extend([
            (Step::RemoveOld, Event::Start),
            (Step::RemoveOld, Event::Done),
        ]);
    }
    want.extend([(Step::Retire, Event::Start), (Step::Retire, Event::Done)]);
    assert_eq!(step_order(&steps), want);

    // Four hook points per step, in order.
    let points = rec.points();
    assert_eq!(points.len(), want.len() * 2);
    for chunk in points.chunks(4) {
        let kinds: Vec<Point> = chunk.iter().map(|p| p.point).collect();
        assert_eq!(
            kinds,
            [
                Point::BeforeStart,
                Point::AfterStart,
                Point::AfterAction,
                Point::AfterDone
            ]
        );
        assert!(
            chunk
                .iter()
                .all(|p| p.step == chunk[0].step && p.location == chunk[0].location)
        );
    }

    // Location rows follow the steps.
    assert!(store.list_for_key(&f.old_fpr).unwrap().is_empty());
    let rows = store.list_for_key(&new).unwrap();
    assert_eq!(rows.len(), n);
    assert!(rows.iter().all(|r| r.status == inventory::Status::Verified));

    // Config: new line added, then the paired old line dropped at retire.
    let config = fs::read_to_string(f.home.ssh_dir().join("config")).unwrap();
    assert_eq!(config, common::CONFIG_NEW);
    assert!(!f.old_path.exists());
    assert!(f.home.ssh_dir().join("retired/id_old").exists());
    assert!(f.home.ssh_dir().join("retired/id_old.pub").exists());
    assert!(f.new_path.exists());
    let rot = store.rotation(s.rotation).unwrap().unwrap();
    assert!(rot.finished_at.is_some());
    assert_eq!(rot.state, "done");

    // S-8: no key blob in the database file.
    drop(store);
    let db = fs::read(&f.db).unwrap();
    let retired = f.home.ssh_dir().join("retired/id_old.pub");
    for p in [retired, f.new_path.with_file_name("id_new.pub")] {
        let text = fs::read_to_string(p).unwrap();
        let blob = text.split_whitespace().nth(1).unwrap();
        assert!(!db.windows(blob.len()).any(|w| w == blob.as_bytes()));
    }
}

/// Small deterministic generator; no extra crate.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[tokio::test]
async fn remove_only_after_fresh_verify() {
    for seed in 1..=12u64 {
        let f = Fixture::new();
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let labels: Vec<String> = common::sites().iter().map(|s| s.0.label()).collect();
        {
            let mut faults = f.world.faults.lock().unwrap();
            for l in &labels {
                // Some verifies of the new key fail: at the verify step, or
                // inside the removal gate.
                let n = (rng.next() % 4) as usize;
                if n > 0 {
                    faults.verify_missing_next.insert(l.clone(), n);
                }
            }
        }
        let mut s = f.start(&NoHooks, true).await.unwrap();
        let mut rounds = 0;
        while s.ending == Ending::Stopped {
            rounds += 1;
            assert!(rounds < 20, "seed {seed}: no progress: {s:?}");
            let failed = s.failures[0].location;
            s = f
                .with_engine(s.rotation, &NoHooks, true, async |e| e.retry(failed).await)
                .await
                .unwrap();
        }
        assert!(
            s.locations.iter().all(|l| l.phase == Phase::OldRemoved),
            "seed {seed}"
        );
        assert_removals_after_fresh_verify(&f.world.calls(), f.old_fpr.as_str());
    }
}

#[tokio::test]
async fn gitlab_shared_key_waits_for_both_purposes() {
    let gitlab = Target::Account {
        base_url: "https://gitlab.test".into(),
        account: "alice".into(),
    };
    let site = gitlab.label();
    let only_auth = vec![(
        gitlab.clone(),
        LocationKind::GitLab,
        Purpose::SshAuth,
        vec![Purpose::SshAuth, Purpose::SshSigning],
    )];

    // The new key was added for auth only: the old `auth_and_signing`
    // object stays.
    let f = Fixture::with_sites(only_auth.clone());
    f.world.faults.lock().unwrap().gitlab_add_one_purpose = true;
    let s = f.start(&NoHooks, true).await.unwrap();
    assert_eq!(s.ending, Ending::Stopped);
    assert_eq!(s.locations[0].phase, Phase::Verified);
    assert_eq!(s.failures[0].step, Step::RemoveOld);
    assert!(
        s.failures[0].reason.contains("also serves ssh_signing"),
        "{s:?}"
    );
    assert!(f.world.has(&site, &f.old_fpr, Purpose::SshAuth));
    assert!(f.world.has(&site, &f.old_fpr, Purpose::SshSigning));
    assert!(f.old_path.exists(), "no retire while the old key is in use");

    // The new key serves both purposes, like the old one: removed.
    let f = Fixture::with_sites(only_auth);
    let s = f.start(&NoHooks, true).await.unwrap();
    assert_eq!(s.ending, Ending::Done, "{s:?}");
    assert!(!f.world.has(&site, &f.old_fpr, Purpose::SshSigning));
    let new = f.new_fpr().unwrap();
    assert!(f.world.has(&site, &new, Purpose::SshSigning));
}

#[tokio::test]
async fn failed_verify_keeps_old_key_and_config_has_both_lines() {
    let f = Fixture::new();
    let new_missing = "srv-b".to_string();
    f.world
        .faults
        .lock()
        .unwrap()
        .verify_missing_next
        .insert(new_missing.clone(), 1);
    let s = f.start(&NoHooks, true).await.unwrap();
    assert_eq!(s.ending, Ending::Stopped);
    let b = s
        .locations
        .iter()
        .find(|l| l.target.label() == "srv-b")
        .unwrap();
    assert_eq!(b.phase, Phase::Installed);
    assert!(
        b.reason.as_deref().unwrap().contains("does not log in"),
        "{b:?}"
    );
    assert!(f.world.has("srv-b", &f.old_fpr, Purpose::SshAuth));
    // The others went on to removal.
    let others = s.locations.iter().filter(|l| l.target.label() != "srv-b");
    assert!(others.clone().all(|l| l.phase == Phase::OldRemoved));
    // Config has both lines, the new key first: every host works.
    assert_eq!(
        fs::read_to_string(f.home.ssh_dir().join("config")).unwrap(),
        common::CONFIG_BOTH
    );
    assert!(
        s.notes
            .iter()
            .any(|n| n.starts_with("old key files kept") && n.contains("srv-b"))
    );
    assert!(f.old_path.exists());
    assert_eq!(s.failures.len(), 1);
    assert_eq!(s.failures[0].step, Step::Verify);

    // Retry: verified, old key removed, retire drops the old lines.
    let s = f
        .with_engine(s.rotation, &NoHooks, true, async |e| {
            e.retry(Some(b.location_id)).await
        })
        .await
        .unwrap();
    assert_eq!(s.ending, Ending::Done, "{s:?}");
    assert!(!f.world.has("srv-b", &f.old_fpr, Purpose::SshAuth));
    assert_eq!(
        fs::read_to_string(f.home.ssh_dir().join("config")).unwrap(),
        common::CONFIG_NEW
    );
    assert!(!f.old_path.exists());
}

#[tokio::test]
async fn ca_lines_with_old_key_block_retire() {
    let f = Fixture::with_sites(vec![(
        Target::Ssh(SshHost::new("srv-a")),
        LocationKind::SshServer,
        Purpose::SshAuth,
        vec![Purpose::SshAuth],
    )]);
    f.world.set_ca_lines("srv-a", vec![2, 5]);
    let s = f.start(&NoHooks, true).await.unwrap();
    assert_eq!(s.ending, Ending::Done, "{s:?}");
    assert_eq!(s.locations[0].phase, Phase::OldRemoved);
    assert_eq!(s.locations[0].reason.as_deref(), Some(CA_REASON));
    assert!(
        s.notes
            .iter()
            .any(|n| n.contains("old key still trusted as a certificate authority"))
    );
    assert!(s.notes.iter().any(|n| n.starts_with("old key files kept")));
    assert!(f.old_path.exists());
}

#[tokio::test]
async fn retire_needs_confirm() {
    let f = Fixture::new();
    let s = f.start(&NoHooks, false).await.unwrap();
    assert_eq!(s.ending, Ending::Done);
    assert!(f.old_path.exists());
    assert!(s.notes.iter().any(|n| n.contains("not confirmed")));
}

#[tokio::test]
async fn same_fingerprint_after_generate_is_refused() {
    let mut f = Fixture::new();
    // A "keygen" that copies the old key instead of making one.
    let script = f.home.path().join("fake-keygen.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -f ] && out=$2; shift; done\n\
             cp {old} \"$out\" && cp {old}.pub \"$out.pub\"\n",
            old = f.old_path.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    f.env.keygen_program = script;
    let s = f.start(&NoHooks, true).await.unwrap();
    assert_eq!(s.ending, Ending::Stopped);
    assert_eq!(s.failures[0].step, Step::Generate);
    assert!(s.failures[0].reason.contains("same fingerprint"));
    assert!(
        f.world
            .calls()
            .iter()
            .all(|c| c.op != Op::Add && c.op != Op::Remove)
    );
}

#[tokio::test]
async fn ssh_old_key_not_refused_blocks_retire() {
    for (check, want) in [
        (OldKeyCheck::StillAccepted, STILL_ACCEPTED.to_string()),
        (
            OldKeyCheck::Unknown("no answer".into()),
            format!("{UNCHECKED}: no answer"),
        ),
    ] {
        let f = Fixture::new();
        f.world
            .faults
            .lock()
            .unwrap()
            .old_key_check
            .insert("srv-a".into(), check);
        let s = f.start(&NoHooks, true).await.unwrap();
        assert_eq!(s.ending, Ending::Done, "{s:?}");
        let a = s
            .locations
            .iter()
            .find(|l| l.target.label() == "srv-a")
            .unwrap();
        assert_eq!(a.phase, Phase::OldRemoved);
        assert_eq!(a.reason.as_deref(), Some(want.as_str()));
        assert!(s.notes.iter().any(|n| n.contains(&want)));
        assert!(f.old_path.exists(), "no retire");
        assert_eq!(
            fs::read_to_string(f.home.ssh_dir().join("config")).unwrap(),
            common::CONFIG_BOTH
        );
    }
}

#[tokio::test]
async fn ssh_g_offers_new_key_before_old() {
    let f = Fixture::new();
    // Retire declined: both lines stay.
    let s = f.start(&NoHooks, false).await.unwrap();
    assert_eq!(s.ending, Ending::Done);
    let cfg = f.home.ssh_dir().join("config");
    assert_eq!(fs::read_to_string(&cfg).unwrap(), common::CONFIG_BOTH);
    let out = std::process::Command::new("ssh")
        .arg("-G")
        .arg("-F")
        .arg(&cfg)
        .arg("srv-a")
        .env("HOME", f.home.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let ids: Vec<String> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| l.strip_prefix("identityfile "))
        .map(str::to_string)
        .collect();
    let pos = |name: &str| ids.iter().position(|i| i.ends_with(name)).unwrap();
    assert!(pos("/id_new") < pos("/id_old"), "{ids:?}");
}
