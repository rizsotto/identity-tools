//! Paths, providers, tokens and the questions a run asks.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use identity_core::{PublicKey, parse_public_keys, read_key_file};

use inventory::{LocationKind, Rotation, Store, Target, cut_known_secrets, scan_config};
use providers::{
    Forgejo, GitHub, GitLab, InMemoryTokenSource, NetLog, OpenPgpReader, SecretServiceTokens,
    SshServer, TokenKey, TokenSource,
};
use rotation::{Confirm, Crash, EngineEnv, Hooks, JournalPoint, Passphrase, Point, ProviderMap};

use crate::Fail;
use crate::cli::Global;

/// Where everything is.
pub struct Paths {
    pub home: PathBuf,
    pub db: PathBuf,
    pub ssh_dir: PathBuf,
    pub ssh_config: PathBuf,
    /// The ssh config was named on the command line.
    pub ssh_config_given: bool,
    pub known_hosts: Option<PathBuf>,
    pub ssh_program: PathBuf,
    pub allow_commands: bool,
}

impl Paths {
    pub fn from_cli(g: &Global) -> Result<Paths, Fail> {
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| Fail::Error("HOME is not set".into()))?;
        let data = std::env::var_os("XDG_DATA_HOME")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"));
        let ssh_dir = g.ssh_dir.clone().unwrap_or_else(|| home.join(".ssh"));
        Ok(Paths {
            db: g
                .db
                .clone()
                .unwrap_or_else(|| data.join("key-steward/inventory.db")),
            ssh_config: g
                .ssh_config
                .clone()
                .unwrap_or_else(|| ssh_dir.join("config")),
            ssh_config_given: g.ssh_config.is_some(),
            ssh_dir,
            known_hosts: g.known_hosts.clone(),
            ssh_program: g
                .ssh_program
                .clone()
                .unwrap_or_else(|| PathBuf::from("ssh")),
            allow_commands: g.allow_config_commands,
            home,
        })
    }

    /// Opens the database, creating it if needed.
    pub fn store(&self) -> Result<Store, Fail> {
        Store::open(&self.db).map_err(Fail::error)
    }

    /// Opens an existing database. A dry-run never creates one.
    pub fn existing_store(&self) -> Result<Store, Fail> {
        if !self.db.exists() {
            return Err(Fail::Refused(format!(
                "no database at {}; add locations first (locations import-ssh-config)",
                self.db.display()
            )));
        }
        self.store()
    }

    pub fn ssh(&self, netlog: &NetLog) -> SshServer {
        let mut s = SshServer::new(netlog.clone())
            .with_program(&self.ssh_program)
            .with_home(&self.home)
            .with_allow_commands(self.allow_commands);
        if self.ssh_config_given || self.ssh_config.exists() {
            s = s.with_config(&self.ssh_config);
        }
        if let Some(kh) = &self.known_hosts {
            s = s.with_known_hosts(kh);
        }
        s
    }

    /// The ssh config and the files it includes, for the config update.
    pub fn config_files(&self) -> Result<Vec<PathBuf>, Fail> {
        if !self.ssh_config.exists() {
            return Ok(Vec::new());
        }
        scan_config(&self.ssh_config, &self.home)
            .map(|s| s.files)
            .map_err(Fail::error)
    }

    pub fn env(&self, passphrase: Passphrase, comment: Option<String>) -> Result<EngineEnv, Fail> {
        let mut env = EngineEnv::new(&self.ssh_dir, &self.home);
        env.config_files = self.config_files()?;
        env.passphrase = passphrase;
        env.comment = comment;
        Ok(env)
    }

    /// The network log file of a rotation, next to the database. The
    /// creation time is in the name, so a file left from another database
    /// with the same rotation id is never appended to.
    pub fn netlog_path(&self, rot: &Rotation) -> PathBuf {
        let created = rot
            .created_at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.db
            .with_file_name(format!("rotation-{}-{created}.netlog", rot.id))
    }
}

/// The tokens of the forge accounts in `targets`, read once from the
/// Secret Service (S-4). Without forge accounts it is not contacted.
/// Each token is also returned, to register as a journal secret before
/// any journal write.
pub async fn tokens(
    targets: &[(LocationKind, Target)],
) -> Result<(Arc<InMemoryTokenSource>, Vec<String>), Fail> {
    let mem = Arc::new(InMemoryTokenSource::new());
    let keys: Vec<TokenKey> = targets
        .iter()
        .filter(|(k, _)| {
            matches!(
                k,
                LocationKind::GitHub | LocationKind::GitLab | LocationKind::Forgejo
            )
        })
        .filter_map(|(k, t)| TokenKey::for_target(*k, t))
        .collect();
    let mut secrets = Vec::new();
    if keys.is_empty() {
        return Ok((mem, secrets));
    }
    let ss = SecretServiceTokens::connect()
        .await
        .map_err(|e| Fail::Refused(e.to_string()))?;
    for key in keys {
        if let Some(t) = ss.token(&key).await.map_err(Fail::error)? {
            secrets.push(t.expose().to_string());
            mem.insert(key, t);
        }
    }
    Ok((mem, secrets))
}

pub fn providers(paths: &Paths, netlog: &NetLog, tokens: Arc<dyn TokenSource>) -> ProviderMap {
    let pgp = OpenPgpReader::user_default;
    ProviderMap::new()
        .with_ssh(paths.ssh(netlog))
        .with(Box::new(GitHub::new(tokens.clone(), pgp(), netlog.clone())))
        .with(Box::new(GitLab::new(tokens.clone(), pgp(), netlog.clone())))
        .with(Box::new(Forgejo::new(tokens, pgp(), netlog.clone())))
}

/// Asks a yes/no question on the terminal; an empty answer is `default`.
/// No terminal: no.
pub fn ask(question: &str, default: bool) -> bool {
    if !io::stdin().is_terminal() {
        return false;
    }
    eprint!("{question} ");
    let _ = io::stderr().flush();
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line).is_err() {
        return default;
    }
    match line.trim() {
        "" => default,
        a => a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes"),
    }
}

/// The retire question (S-2): `--yes` answers it, else the terminal.
pub struct RetireConfirm {
    pub yes: bool,
}

impl Confirm for RetireConfirm {
    fn retire(&self, files: &[PathBuf]) -> bool {
        if self.yes {
            return true;
        }
        let names: Vec<String> = files.iter().map(|f| f.display().to_string()).collect();
        ask(
            &format!(
                "The old key is gone from every location. Move {} to the retired dir? [y/N]",
                names.join(" and ")
            ),
            false,
        )
    }
}

/// The production hooks: write new network log entries to the rotation's
/// log file at every journal point, so a crash loses at most the last
/// call; after the new key is made, offer `ssh-add` for a key with a
/// passphrase.
pub struct RunHooks {
    pub netlog: NetLog,
    file: Mutex<Option<PathBuf>>,
    written: Mutex<usize>,
    /// Tokens of this run; cut out of the log file.
    secrets: Vec<String>,
    /// Private key paths whose `.pub` blobs are cut out of the log file.
    keys: Vec<PathBuf>,
    pub offer_ssh_add: Option<PathBuf>,
}

/// The base64 blob of the key in `<private>.pub`, if it can be read.
fn key_blob(private: &Path) -> Option<String> {
    let mut p = private.as_os_str().to_owned();
    p.push(".pub");
    let bytes = read_key_file(Path::new(&p)).ok()?;
    match parse_public_keys(&bytes)
        .ok()?
        .into_iter()
        .next()?
        .key
        .ok()?
    {
        PublicKey::Ssh(k) => k.encoded.split_whitespace().nth(1).map(str::to_string),
        _ => None,
    }
}

impl RunHooks {
    pub fn new(
        netlog: &NetLog,
        secrets: Vec<String>,
        keys: Vec<PathBuf>,
        offer_ssh_add: Option<PathBuf>,
    ) -> Self {
        RunHooks {
            netlog: netlog.clone(),
            file: Mutex::new(None),
            written: Mutex::new(0),
            secrets,
            keys,
            offer_ssh_add,
        }
    }

    pub fn set_file(&self, path: PathBuf) {
        *self.file.lock().unwrap_or_else(|e| e.into_inner()) = Some(path);
        self.flush();
    }

    /// Appends the entries not yet written. Known secrets (tokens, both
    /// key blobs) are cut out first, on top of the providers' own
    /// scrubbing (S-4, S-8). The file is opened without following a
    /// symlink and set to 0600.
    pub fn flush(&self) {
        let Some(path) = self.file.lock().unwrap_or_else(|e| e.into_inner()).clone() else {
            return;
        };
        let mut written = self.written.lock().unwrap_or_else(|e| e.into_inner());
        let entries = self.netlog.entries();
        if entries.len() <= *written {
            return;
        }
        let blobs: Vec<String> = self.keys.iter().filter_map(|k| key_blob(k)).collect();
        let secrets: Vec<&str> = self
            .secrets
            .iter()
            .chain(blobs.iter())
            .map(String::as_str)
            .collect();
        let text: String = entries[*written..]
            .iter()
            .map(|e| {
                let t = e
                    .time
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let line = format!("{} {}: {} -> {}", e.kind, e.target, e.action, e.outcome);
                let line: String = cut_known_secrets(&line, &secrets)
                    .chars()
                    .map(|c| if c.is_control() { ' ' } else { c })
                    .collect();
                format!("{t} {line}\n")
            })
            .collect();
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path);
        let r = f.and_then(|mut f| {
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            f.write_all(text.as_bytes())
        });
        match r {
            Ok(()) => *written = entries.len(),
            Err(e) => eprintln!(
                "key-steward: cannot write the network log {}: {e}",
                path.display()
            ),
        }
    }
}

impl Hooks for RunHooks {
    fn at(&self, p: &JournalPoint) -> Result<(), Crash> {
        self.flush();
        if p.point == Point::AfterDone
            && p.step == inventory::Step::Generate
            && let Some(new) = &self.offer_ssh_add
            && new.exists()
            && ask(
                &format!(
                    "If the new key has a passphrase, the checks need it in the ssh agent. \
                     Run ssh-add {} now? [Y/n]",
                    new.display()
                ),
                true,
            )
        {
            let _ = Command::new("ssh-add").arg(new).status();
        }
        Ok(())
    }
}

/// Reads the network log file of a rotation, if any.
pub fn read_netlog(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use inventory::SshHost;

    #[test]
    fn netlog_file_has_no_token_or_key_blob_and_is_private() {
        let home = test_support::TempHome::new(std::env::temp_dir());
        let dir = home.path().to_path_buf();
        let key = dir.join("id_new");
        let blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAMl5AYo+0XU3NureorqVJl9BQCzJ/7O6oQuY+n0zaV+";
        fs::write(
            dir.join("id_new.pub"),
            format!("ssh-ed25519 {blob} new@test\n"),
        )
        .unwrap();
        let token = "glpat-FAKE-token-0123456789abcdef";
        let log = NetLog::new();
        log.record(
            LocationKind::SshServer,
            &Target::Ssh(SshHost::new("srv")),
            format!("ssh srv echo {blob} {token}"),
            "exit 0",
        );
        let path = dir.join("rotation-1-5.netlog");
        // A stale file with loose mode: its mode is fixed.
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let hooks = RunHooks::new(&log, vec![token.into()], vec![key], None);
        hooks.set_file(path.clone());
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("ssh srv echo"), "{text}");
        assert!(!text.contains(blob) && !text.contains(token), "{text}");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // A symlink in its place is not followed.
        let link = dir.join("rotation-2-5.netlog");
        std::os::unix::fs::symlink(dir.join("elsewhere"), &link).unwrap();
        let hooks = RunHooks::new(&log, Vec::new(), Vec::new(), None);
        hooks.set_file(link);
        assert!(!dir.join("elsewhere").exists());
    }
}
