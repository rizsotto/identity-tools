//! `key-steward locations ...`.

use std::sync::Arc;

use identity_core::scan_ssh_dir;
use inventory::{
    ImportOptions, KnownKey, LocationKind, NewLocation, Purpose, Target, import_ssh_config,
};
use providers::{CheckOutcome, CheckRunner, Forgejo, GitHub, GitLab, NetLog, OpenPgpReader};
use rotation::find_key;

use crate::Fail;
use crate::cli::{ForgeKind, KeyPurpose, LocationsCmd};
use crate::setup::{self, Paths};

pub async fn run(paths: &Paths, cmd: LocationsCmd) -> Result<u8, Fail> {
    match cmd {
        LocationsCmd::List { key } => list(paths, key.as_deref()),
        LocationsCmd::ImportSshConfig => import(paths),
        LocationsCmd::AddForge {
            kind,
            base_url,
            account,
            key,
            purpose,
        } => add_forge(paths, kind, base_url, account, &key, purpose),
        LocationsCmd::Check { key } => check(paths, &key).await,
    }
}

fn key(paths: &Paths, key: &str) -> Result<(std::path::PathBuf, identity_core::Fingerprint), Fail> {
    find_key(&paths.ssh_dir, key).map_err(|e| Fail::Refused(e.to_string()))
}

fn list(paths: &Paths, k: Option<&str>) -> Result<u8, Fail> {
    let store = paths.existing_store()?;
    let rows = match k {
        Some(k) => store.list_for_key(&key(paths, k)?.1),
        None => store.list(),
    }
    .map_err(Fail::error)?;
    for l in rows {
        println!(
            "[{}] {} {} ({}) {} {}",
            l.id,
            l.kind.as_str(),
            l.target.label(),
            l.purpose.as_str(),
            l.key,
            match &l.status {
                inventory::Status::Error(r) => format!("error: {r}"),
                s => s.as_str().to_string(),
            }
        );
    }
    Ok(0)
}

fn import(paths: &Paths) -> Result<u8, Fail> {
    let scan = scan_ssh_dir(&paths.ssh_dir).map_err(Fail::error)?;
    let keys: Vec<KnownKey> = scan
        .keys
        .iter()
        .filter_map(|f| {
            let k = f.key.as_ref().ok()?;
            Some(KnownKey {
                private_path: f.private_path.clone()?,
                fingerprint: k.fingerprint.clone(),
            })
        })
        .collect();
    let mut opts = ImportOptions::new(&paths.ssh_config, &paths.home);
    opts.ssh = paths.ssh_program.clone();
    opts.allow_commands = paths.allow_commands;
    let mut store = paths.store()?;
    let report = import_ssh_config(&mut store, &opts, &keys).map_err(|e| match e {
        inventory::ImportError::CommandsNeedConsent(_) => {
            Fail::Refused(format!("{e}; pass --allow-config-commands if you trust it"))
        }
        e => Fail::error(e),
    })?;
    println!(
        "{} added, {} already stored",
        report.added.len(),
        report.existing.len()
    );
    for a in &report.without_key {
        println!("no local key for host {a}");
    }
    for (a, why) in &report.failed {
        println!("cannot read host {a}: {why}");
    }
    Ok(0)
}

fn add_forge(
    paths: &Paths,
    kind: ForgeKind,
    base_url: String,
    account: String,
    k: &str,
    purpose: KeyPurpose,
) -> Result<u8, Fail> {
    let (_, fpr) = key(paths, k)?;
    let mut store = paths.store()?;
    let added = store
        .add(&NewLocation {
            kind: match kind {
                ForgeKind::Github => LocationKind::GitHub,
                ForgeKind::Gitlab => LocationKind::GitLab,
                ForgeKind::Forgejo => LocationKind::Forgejo,
            },
            target: Target::Account {
                base_url: base_url.trim_end_matches('/').to_string(),
                account,
            },
            key: fpr,
            purpose: match purpose {
                KeyPurpose::Auth => Purpose::SshAuth,
                KeyPurpose::Signing => Purpose::SshSigning,
            },
        })
        .map_err(Fail::error)?;
    match added {
        inventory::Added::New(id) => println!("added location {id}"),
        inventory::Added::Existing(id) => println!("already stored as location {id}"),
    }
    Ok(0)
}

async fn check(paths: &Paths, k: &str) -> Result<u8, Fail> {
    let (path, fpr) = key(paths, k)?;
    let mut store = paths.existing_store()?;
    let targets: Vec<(LocationKind, Target)> = store
        .list_for_key(&fpr)
        .map_err(Fail::error)?
        .into_iter()
        .map(|l| (l.kind, l.target))
        .collect();
    let (tokens, _) = setup::tokens(&targets).await?;
    let netlog = NetLog::new();
    let pgp = OpenPgpReader::user_default;
    let runner = CheckRunner::new()
        .with(Arc::new(paths.ssh(&netlog)))
        .with(Arc::new(GitHub::new(tokens.clone(), pgp(), netlog.clone())))
        .with(Arc::new(GitLab::new(tokens.clone(), pgp(), netlog.clone())))
        .with(Arc::new(Forgejo::new(tokens, pgp(), netlog.clone())));
    let results = runner
        .check_key(&mut store, &fpr, Some(&path))
        .await
        .map_err(Fail::error)?;
    for r in results {
        let what = match r.outcome {
            CheckOutcome::Checked(inventory::Status::Error(e)) => format!("error: {e}"),
            CheckOutcome::Checked(s) => s.as_str().to_string(),
            CheckOutcome::NoProvider => "not checked (no provider)".into(),
        };
        println!("[{}] {}: {what}", r.location, r.kind.as_str());
    }
    print!("{}", netlog.render());
    Ok(0)
}
