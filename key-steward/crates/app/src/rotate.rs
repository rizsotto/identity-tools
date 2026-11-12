//! `key-steward rotate ...`: dry-run, run, resume and the answers to a
//! failed step (plan.md, "CLI shape").

use std::io::{self, BufRead, IsTerminal, Write};
use std::time::UNIX_EPOCH;

use inventory::{LocationKind, Phase, RotationId, Store, StoreError, Target};
use providers::NetLog;
use rotation::{
    Ctx, Ending, Engine, EngineError, KeyType, LockError, Passphrase, Plan, PlanError, PlanRequest,
    RotationLock, Summary, find_key,
};

use crate::cli::{NewKeyType, PlanArgs, RotateCmd};
use crate::setup::{self, Paths, RetireConfirm, RunHooks};
use crate::{Fail, STOPPED};

pub async fn run(paths: &Paths, cmd: RotateCmd) -> Result<u8, Fail> {
    match cmd {
        RotateCmd::Plan { args, json } => plan_cmd(paths, &args, json).await,
        RotateCmd::Start { args, yes } => start(paths, &args, yes).await,
        RotateCmd::Status { id } => status(paths, id),
        RotateCmd::Resume { id, yes } => answer(paths, id, yes, Answer::Resume).await,
        RotateCmd::Retry { id, location, yes } => {
            answer(paths, id, yes, Answer::Retry(location)).await
        }
        RotateCmd::Skip { id, location, yes } => {
            answer(paths, id, yes, Answer::Skip(location)).await
        }
        RotateCmd::Abort { id, rollback } => {
            answer(paths, id, false, Answer::Abort(rollback)).await
        }
        RotateCmd::Log { id } => log(paths, id),
    }
}

fn engine_fail(e: EngineError) -> Fail {
    match e {
        EngineError::Refused(m) => Fail::Refused(m),
        EngineError::Store(StoreError::RotationOpen(id)) => Fail::Refused(format!(
            "rotation {id} is still open; resume it or abort it first"
        )),
        e @ (EngineError::NoRotation(_) | EngineError::Finished(_)) => Fail::Refused(e.to_string()),
        e => Fail::error(e),
    }
}

fn lock(paths: &Paths) -> Result<RotationLock, Fail> {
    RotationLock::for_database(&paths.db).map_err(|e| match e {
        LockError::Busy(_) => Fail::Refused(e.to_string()),
        e => Fail::error(e),
    })
}

fn request(args: &PlanArgs) -> PlanRequest {
    PlanRequest {
        key: args.key.clone(),
        key_type: match args.key_type {
            NewKeyType::Ed25519 => KeyType::Ed25519,
            NewKeyType::Ecdsa => KeyType::Ecdsa,
            NewKeyType::Rsa => KeyType::Rsa,
        },
        new_path: args.new_path.clone(),
        skip: args.skip.clone(),
        update_config: args.update_config,
    }
}

fn passphrase(args: &PlanArgs) -> Passphrase {
    if args.no_passphrase {
        Passphrase::Empty
    } else {
        Passphrase::Terminal
    }
}

/// The dry-run, with the tokens it used (S-4: from the Secret Service,
/// only if a forge location is involved).
async fn make_plan(
    paths: &Paths,
    store: &Store,
    args: &PlanArgs,
    netlog: &NetLog,
) -> Result<(Plan, Vec<String>, rotation::ProviderMap), Fail> {
    let (_, fpr) = find_key(&paths.ssh_dir, &args.key).map_err(plan_fail)?;
    let targets: Vec<(LocationKind, Target)> = store
        .list_for_key(&fpr)
        .map_err(Fail::error)?
        .into_iter()
        .map(|l| (l.kind, l.target))
        .collect();
    let (tokens, secrets) = setup::tokens(&targets).await?;
    let providers = setup::providers(paths, netlog, tokens);
    let env = paths.env(passphrase(args), args.comment.clone())?;
    let plan = rotation::plan(store, &providers, &env, &request(args))
        .await
        .map_err(plan_fail)?;
    Ok((plan, secrets, providers))
}

fn plan_fail(e: PlanError) -> Fail {
    match e {
        PlanError::Refused(m) => Fail::Refused(m),
        e => Fail::error(e),
    }
}

async fn plan_cmd(paths: &Paths, args: &PlanArgs, json: bool) -> Result<u8, Fail> {
    let store = paths.existing_store()?;
    let netlog = NetLog::new();
    let (plan, _, _) = make_plan(paths, &store, args, &netlog).await?;
    if json {
        println!("{:#}", plan.to_json());
    } else {
        print!("{}", plan.render_text());
    }
    Ok(0)
}

/// The user types `yes` (S-7). No terminal: no.
fn confirm_start() -> bool {
    if !io::stdin().is_terminal() {
        return false;
    }
    eprint!("Type yes to start the rotation: ");
    let _ = io::stderr().flush();
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).is_ok() && line.trim() == "yes"
}

async fn start(paths: &Paths, args: &PlanArgs, yes: bool) -> Result<u8, Fail> {
    let mut store = paths.existing_store()?;
    let lock = lock(paths)?;
    if let Some(open) = store.open_rotation().map_err(Fail::error)? {
        return Err(Fail::Refused(format!(
            "rotation {} is still open; resume it or abort it first",
            open.id
        )));
    }
    let netlog = NetLog::new();
    let (plan, secrets, providers) = make_plan(paths, &store, args, &netlog).await?;
    print!("{}", plan.render_text());
    if plan.rotated().is_empty() {
        return Err(Fail::Refused("no location can be rotated".into()));
    }
    if !yes && !io::stdin().is_terminal() {
        return Err(Fail::Refused(
            "start changes servers and forges; pass --yes, or run it in a terminal to confirm"
                .into(),
        ));
    }
    if !yes && !confirm_start() {
        return Err(Fail::Refused("not confirmed; nothing was changed".into()));
    }
    // Tokens never reach the journal (S-4): known before its first entry.
    for s in &secrets {
        store.add_secret(s);
    }
    let env = paths.env(passphrase(args), args.comment.clone())?;
    let offer = (env.passphrase == Passphrase::Terminal).then(|| plan.new_path.clone());
    let hooks = RunHooks::new(&netlog, offer);
    let confirm = RetireConfirm { yes };
    let ctx = Ctx {
        providers: &providers,
        hooks: &hooks,
        confirm: &confirm,
        env: &env,
        lock: &lock,
    };
    let mut engine = Engine::start(&mut store, &plan.new_rotation(), ctx).map_err(engine_fail)?;
    let id = engine.id();
    hooks.set_file(paths.netlog_path(id));
    println!("\nRotation {id} started.");
    let summary = engine.run().await;
    hooks.flush();
    finish(summary)
}

enum Answer {
    Resume,
    Retry(Option<i64>),
    Skip(i64),
    Abort(bool),
}

async fn answer(paths: &Paths, id: RotationId, yes: bool, what: Answer) -> Result<u8, Fail> {
    let mut store = paths.existing_store()?;
    let lock = lock(paths)?;
    let rot = store
        .rotation(id)
        .map_err(Fail::error)?
        .ok_or_else(|| Fail::Refused(format!("no rotation with id {id}")))?;
    let targets: Vec<(LocationKind, Target)> = store
        .rotation_locations(id)
        .map_err(Fail::error)?
        .into_iter()
        .map(|l| (l.kind, l.target))
        .collect();
    let (tokens, secrets) = setup::tokens(&targets).await?;
    for s in &secrets {
        store.add_secret(s);
    }
    let netlog = NetLog::new();
    let providers = setup::providers(paths, &netlog, tokens);
    let env = paths.env(Passphrase::Terminal, None)?;
    let offer = rot
        .new_fingerprint
        .is_none()
        .then(|| rot.new_key_path.clone());
    let hooks = RunHooks::new(&netlog, offer);
    hooks.set_file(paths.netlog_path(id));
    let confirm = RetireConfirm { yes };
    let ctx = Ctx {
        providers: &providers,
        hooks: &hooks,
        confirm: &confirm,
        env: &env,
        lock: &lock,
    };
    let mut engine = Engine::open(&mut store, id, ctx).map_err(engine_fail)?;
    let summary = match what {
        Answer::Resume => engine.run().await,
        Answer::Retry(l) => engine.retry(l).await,
        Answer::Skip(l) => engine.skip(l).await,
        Answer::Abort(rollback) => engine.abort(rollback).await,
    };
    hooks.flush();
    finish(summary)
}

fn finish(summary: Result<Summary, EngineError>) -> Result<u8, Fail> {
    let s = summary.map_err(engine_fail)?;
    print!("{}", render_summary(&s));
    Ok(match s.ending {
        Ending::Stopped => STOPPED,
        Ending::Done | Ending::Aborted => 0,
    })
}

fn render_summary(s: &Summary) -> String {
    let mut out = String::new();
    let ending = match s.ending {
        Ending::Done => "finished",
        Ending::Stopped => "stopped: a step needs your answer",
        Ending::Aborted => "aborted",
    };
    out.push_str(&format!("\nRotation {}: {ending}\n", s.rotation));
    out.push_str("Locations:\n");
    for l in &s.locations {
        let mut line = format!(
            "  [{}] {} {} ({}): {}",
            l.location_id,
            l.kind.as_str(),
            l.target.label(),
            l.purpose.as_str(),
            l.phase.as_str()
        );
        match (l.phase, &l.reason) {
            (Phase::Skipped, _) => line.push_str(" (the old key stays here)"),
            (_, Some(r)) => line.push_str(&format!(" -- {r}")),
            _ => {}
        }
        out.push_str(&line);
        out.push('\n');
    }
    if !s.failures.is_empty() {
        out.push_str("Failed:\n");
        for f in &s.failures {
            let at = f
                .location
                .map(|l| format!(" at location {l}"))
                .unwrap_or_default();
            out.push_str(&format!("  {}{at}: {}\n", f.step.as_str(), f.reason));
            let loc = f
                .location
                .map(|l| format!(" --location {l}"))
                .unwrap_or_default();
            out.push_str(&format!(
                "  next: key-steward rotate retry {id}{loc}",
                id = s.rotation
            ));
            if f.location.is_some() {
                out.push_str(&format!(" | rotate skip {}{loc}", s.rotation));
            }
            out.push_str(&format!(" | rotate abort {} [--rollback]\n", s.rotation));
        }
    }
    if !s.notes.is_empty() {
        out.push_str("Notes:\n");
        for n in &s.notes {
            out.push_str(&format!("  {n}\n"));
        }
    }
    out
}

fn secs(t: std::time::SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn status(paths: &Paths, id: Option<RotationId>) -> Result<u8, Fail> {
    let store = paths.existing_store()?;
    let rot = match id {
        Some(id) => store.rotation(id).map_err(Fail::error)?,
        None => store.open_rotation().map_err(Fail::error)?,
    }
    .ok_or_else(|| {
        Fail::Refused(match id {
            Some(id) => format!("no rotation with id {id}"),
            None => "no open rotation; give a rotation id".into(),
        })
    })?;
    println!("Rotation {}: {}", rot.id, rot.state);
    println!(
        "  old key: {} ({})",
        rot.old_key_path.display(),
        rot.old_fingerprint
    );
    match &rot.new_fingerprint {
        Some(f) => println!("  new key: {} ({f})", rot.new_key_path.display()),
        None => println!("  new key: {} (not made yet)", rot.new_key_path.display()),
    }
    println!(
        "  ssh config update: {}",
        if rot.update_config { "yes" } else { "no" }
    );
    match rot.finished_at {
        Some(t) => println!("  finished at {}", secs(t)),
        None => println!("  open"),
    }
    let steps = store.steps(rot.id).map_err(Fail::error)?;
    println!("Locations:");
    for l in store.rotation_locations(rot.id).map_err(Fail::error)? {
        let last = steps
            .iter()
            .rev()
            .find(|e| e.location_id == Some(l.location_id))
            .map(|e| {
                let d = e
                    .detail
                    .as_deref()
                    .map(|d| format!(": {d}"))
                    .unwrap_or_default();
                format!(", last: {} {}{d}", e.step.as_str(), e.event.as_str())
            })
            .unwrap_or_default();
        let reason = l.reason.map(|r| format!(" -- {r}")).unwrap_or_default();
        println!(
            "  [{}] {} {} ({}): {}{reason}{last}",
            l.location_id,
            l.kind.as_str(),
            l.target.label(),
            l.purpose.as_str(),
            l.phase.as_str()
        );
    }
    Ok(0)
}

fn log(paths: &Paths, id: RotationId) -> Result<u8, Fail> {
    let store = paths.existing_store()?;
    if store.rotation(id).map_err(Fail::error)?.is_none() {
        return Err(Fail::Refused(format!("no rotation with id {id}")));
    }
    println!("Journal of rotation {id}:");
    for e in store.steps(id).map_err(Fail::error)? {
        let loc = e
            .location_id
            .map(|l| format!(" location {l}"))
            .unwrap_or_default();
        let detail = e.detail.map(|d| format!(": {d}")).unwrap_or_default();
        println!(
            "  {} {} {}{loc}{detail}",
            secs(e.at),
            e.step.as_str(),
            e.event.as_str()
        );
    }
    println!("Network log:");
    match setup::read_netlog(&paths.netlog_path(id)) {
        Some(t) => {
            for l in t.lines() {
                println!("  {l}");
            }
        }
        None => println!("  (none)"),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use inventory::{Purpose, RotationLocation, SshHost, Step};
    use rotation::{CA_REASON, Failure, STILL_ACCEPTED};

    fn loc(id: i64, alias: &str, phase: Phase, reason: Option<&str>) -> RotationLocation {
        RotationLocation {
            rotation_id: 4,
            location_id: id,
            kind: LocationKind::SshServer,
            target: Target::Ssh(SshHost::new(alias)),
            purpose: Purpose::SshAuth,
            phase,
            reason: reason.map(str::to_string),
        }
    }

    #[test]
    fn summary_shows_flags_skips_failures_and_notes() {
        let s = Summary {
            rotation: 4,
            ending: Ending::Stopped,
            locations: vec![
                loc(1, "ca-host", Phase::OldRemoved, Some(CA_REASON)),
                loc(2, "still", Phase::OldRemoved, Some(STILL_ACCEPTED)),
                loc(3, "left", Phase::Skipped, Some("skipped by the user")),
                loc(
                    5,
                    "broken",
                    Phase::Installed,
                    Some("the new key does not log in"),
                ),
            ],
            failures: vec![Failure {
                step: Step::Verify,
                location: Some(5),
                reason: "the new key does not log in: missing".into(),
            }],
            notes: vec![
                "ssh config not changed (not asked for): it still names the old key".into(),
                "old key files kept: the old key is still at left (skipped)".into(),
            ],
        };
        let text = render_summary(&s);
        for want in [
            "Rotation 4: stopped",
            "[1] ssh_server ca-host (ssh_auth): old_removed -- old key still trusted as a certificate authority",
            "[2] ssh_server still (ssh_auth): old_removed -- old key still logs in here",
            "[3] ssh_server left (ssh_auth): skipped (the old key stays here)",
            "verify at location 5: the new key does not log in: missing",
            "next: key-steward rotate retry 4 --location 5 | rotate skip 4 --location 5 | rotate abort 4 [--rollback]",
            "ssh config not changed",
            "old key files kept: the old key is still at left",
        ] {
            assert!(text.contains(want), "{want:?} not in\n{text}");
        }
    }
}
