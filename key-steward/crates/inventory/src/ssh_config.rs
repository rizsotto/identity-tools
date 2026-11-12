//! Import SSH server locations from an ssh config file (UC-2).
//!
//! We read `Host` lines ourselves only to collect aliases (following
//! `Include`). Everything else, including `Match` and defaults, comes from
//! `ssh -G -F <config> <alias>`, so OpenSSH's own logic decides what a host
//! really resolves to. Private key files are never opened (S-1): keys are
//! matched by path against keys the caller already scanned.
//!
//! `ssh -G` runs `Match exec` commands from the config. Import refuses to
//! run `ssh -G` on such a config unless the caller sets
//! [`ImportOptions::allow_commands`] after the user agreed (S-7). Every
//! `ssh -G` run has a time limit.

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use identity_core::Fingerprint;

use crate::location::{LocationId, LocationKind, NewLocation, Purpose, SshHost, Target};
use crate::store::{Added, Store, StoreError};

/// OpenSSH's own limit on nested `Include`.
const MAX_INCLUDE_DEPTH: usize = 16;
const MAX_CONFIG_BYTES: u64 = 1_000_000;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("cannot read {path}: {reason}")]
    Read { path: PathBuf, reason: String },
    #[error("too many nested Include lines (more than {MAX_INCLUDE_DEPTH}) at {0}")]
    IncludeDepth(PathBuf),
    #[error("cannot run ssh: {0}")]
    Spawn(String),
    /// The config can make `ssh -G` run commands. Ask the user, then set
    /// [`ImportOptions::allow_commands`].
    #[error("the ssh config can run commands when it is read: {}", .0.join("; "))]
    CommandsNeedConsent(Vec<String>),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// A local SSH key the caller has scanned: its private key path (as ssh
/// would name it in `IdentityFile`) and its fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownKey {
    pub private_path: PathBuf,
    pub fingerprint: Fingerprint,
}

/// What to import.
#[derive(Debug, Clone)]
pub struct ImportOptions {
    /// The config file, passed to `ssh -F`. The app passes `~/.ssh/config`.
    pub config: PathBuf,
    /// The home dir: `~` in paths, and relative `Include` paths, which
    /// OpenSSH reads from `<home>/.ssh/`. Also the child's `HOME`.
    pub home: PathBuf,
    /// The `ssh` binary.
    pub ssh: PathBuf,
    /// Run `ssh -G` even if the config has `Match exec` (or an `Include`
    /// we cannot check). Set it only after the user agreed. Default: false.
    pub allow_commands: bool,
    /// Time limit for each `ssh -G` run.
    pub timeout: Duration,
}

impl ImportOptions {
    pub fn new(config: impl Into<PathBuf>, home: impl Into<PathBuf>) -> Self {
        ImportOptions {
            config: config.into(),
            home: home.into(),
            ssh: PathBuf::from("ssh"),
            allow_commands: false,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// What `ssh -G` says about a host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolved {
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// As ssh prints them: `~` and `%` tokens are not expanded.
    pub identity_files: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub added: Vec<LocationId>,
    /// Locations that were already stored. Their status is kept.
    pub existing: Vec<LocationId>,
    /// Aliases whose identity files match no scanned key.
    pub without_key: Vec<String>,
    /// Aliases `ssh -G` failed for, with its error text.
    pub failed: Vec<(String, String)>,
}

/// Imports every concrete `Host` alias as an `unverified` SSH server
/// location, one per scanned key that ssh would offer to that host.
pub fn import_ssh_config(
    store: &mut Store,
    opts: &ImportOptions,
    keys: &[KnownKey],
) -> Result<ImportReport, ImportError> {
    let scan = scan_config(&opts.config, &opts.home)?;
    if !scan.runs_commands.is_empty() && !opts.allow_commands {
        return Err(ImportError::CommandsNeedConsent(scan.runs_commands));
    }
    let mut report = ImportReport::default();
    for alias in scan.aliases {
        let resolved = match resolve(opts, &alias)? {
            Ok(r) => r,
            Err(why) => {
                report.failed.push((alias, why));
                continue;
            }
        };
        let matched = matching_keys(&resolved, &opts.home, keys);
        if matched.is_empty() {
            report.without_key.push(alias);
            continue;
        }
        let target = Target::Ssh(SshHost {
            alias: alias.clone(),
            hostname: resolved.hostname.clone(),
            user: resolved.user.clone(),
            port: resolved.port,
        });
        for key in matched {
            let added = store.add(&NewLocation {
                kind: LocationKind::SshServer,
                target: target.clone(),
                key: key.fingerprint.clone(),
                purpose: Purpose::SshAuth,
            })?;
            match added {
                Added::New(id) => report.added.push(id),
                Added::Existing(id) => report.existing.push(id),
            }
        }
    }
    Ok(report)
}

/// What reading the config files found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigScan {
    /// Concrete aliases from `Host` lines, in order, without duplicates.
    pub aliases: Vec<String>,
    /// Why `ssh -G` may run commands: each `Match exec` (file and line), and
    /// each `Include` whose files we cannot list. Empty if none.
    pub runs_commands: Vec<String>,
}

/// Reads the config and its `Include` files (also inside `Host` and
/// `Match` blocks). Skips alias patterns with `*` or `?` and negated (`!`)
/// patterns. Finds `Match exec`.
pub fn scan_config(config: &Path, home: &Path) -> Result<ConfigScan, ImportError> {
    let mut scan = ConfigScan::default();
    let mut seen = HashSet::new();
    collect(config, home, 0, &mut scan, &mut seen)?;
    Ok(scan)
}

/// The aliases of [`scan_config`].
pub fn host_aliases(config: &Path, home: &Path) -> Result<Vec<String>, ImportError> {
    Ok(scan_config(config, home)?.aliases)
}

fn collect(
    path: &Path,
    home: &Path,
    depth: usize,
    scan: &mut ConfigScan,
    seen: &mut HashSet<String>,
) -> Result<(), ImportError> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(ImportError::IncludeDepth(path.to_path_buf()));
    }
    let text = read_config(path)?;
    for (n, line) in text.lines().enumerate() {
        let Some((keyword, args)) = split_line(line) else {
            continue;
        };
        match keyword.to_ascii_lowercase().as_str() {
            "host" => {
                for pat in args {
                    let concrete = !pat.contains(['*', '?']) && !pat.starts_with('!');
                    if concrete && seen.insert(pat.clone()) {
                        scan.aliases.push(pat);
                    }
                }
            }
            "match" => {
                // Any "exec" on a Match line counts: ssh also takes
                // `exec="cmd"`, `"exec"` and `!exec`. Erring on the safe side
                // is fine here; it only means asking the user.
                if line.to_ascii_lowercase().contains("exec") {
                    scan.runs_commands.push(format!(
                        "Match exec in {} line {}",
                        path.display(),
                        n + 1
                    ));
                }
            }
            "include" => {
                for arg in args {
                    match include_files(&arg, home) {
                        Some(files) => {
                            for file in files {
                                collect(&file, home, depth + 1, scan, seen)?;
                            }
                        }
                        None => scan.runs_commands.push(format!(
                            "cannot check Include {arg} in {} line {}",
                            path.display(),
                            n + 1
                        )),
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn read_config(path: &Path) -> Result<String, ImportError> {
    let err = |reason: String| ImportError::Read {
        path: path.to_path_buf(),
        reason,
    };
    let mut buf = String::new();
    fs::File::open(path)
        .map_err(|e| err(e.to_string()))?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut buf)
        .map_err(|e| err(e.to_string()))?;
    if buf.len() as u64 > MAX_CONFIG_BYTES {
        return Err(err(format!("larger than {MAX_CONFIG_BYTES} bytes")));
    }
    Ok(buf)
}

/// Splits a config line into its keyword and arguments, as OpenSSH does:
/// `Keyword args` or `Keyword=args`, double quotes group words, `#` starts
/// a comment line.
fn split_line(line: &str) -> Option<(String, Vec<String>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let keyword = line[..end].to_string();
    let rest = line[end..].trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest);
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut in_arg = false;
    for c in rest.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                in_arg = true;
            }
            c if c.is_whitespace() && !quoted => {
                if in_arg {
                    args.push(std::mem::take(&mut cur));
                    in_arg = false;
                }
            }
            '#' if !quoted && !in_arg => break,
            c => {
                cur.push(c);
                in_arg = true;
            }
        }
    }
    if in_arg {
        args.push(cur);
    }
    Some((keyword, args))
}

/// The files an `Include` argument names. `~` is the home dir; relative
/// paths are under `<home>/.ssh/` (ssh_config(5), user config). `*`, `?`
/// and `[...]` work in the last path component. Missing files are skipped,
/// as ssh does. `None` if we cannot list the files (a glob in a directory
/// name, `${VAR}`, a `%` token or a `~user` path); the caller must then
/// assume the worst. `~/` is `home`, which must be the passwd home.
fn include_files(arg: &str, home: &Path) -> Option<Vec<PathBuf>> {
    // ssh expands `${VAR}`, `%` tokens and `~user` in Include paths; we do
    // not, so we cannot know which files it reads.
    if arg.contains(['$', '%']) || (arg.starts_with('~') && !arg.starts_with("~/")) {
        return None;
    }
    let path = if let Some(rest) = arg.strip_prefix("~/") {
        home.join(rest)
    } else if Path::new(arg).is_absolute() {
        PathBuf::from(arg)
    } else {
        home.join(".ssh").join(arg)
    };
    let is_glob = |s: &str| s.contains(['*', '?', '[']);
    let name = path.file_name()?.to_str()?;
    let dir = path.parent()?;
    if is_glob(&dir.to_string_lossy()) {
        return None;
    }
    if !is_glob(name) {
        return Some(if path.is_file() {
            vec![path.clone()]
        } else {
            Vec::new()
        });
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return Some(Vec::new());
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| !n.starts_with('.') && glob_match(name, n))
        })
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    Some(files)
}

fn glob_match(pattern: &str, name: &str) -> bool {
    /// Matches `[...]` at the start of `p` against `c`. Returns the rest of
    /// the pattern and whether it matched, or `None` if there is no `]`.
    fn class(p: &[char], c: char) -> Option<(&[char], bool)> {
        let mut i = 1;
        let negate = matches!(p.get(1), Some('!') | Some('^'));
        if negate {
            i += 1;
        }
        let mut hit = false;
        let mut first = true;
        while i < p.len() {
            if p[i] == ']' && !first {
                return Some((&p[i + 1..], hit != negate));
            }
            if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
                hit |= p[i] <= c && c <= p[i + 2];
                i += 3;
            } else {
                hit |= p[i] == c;
                i += 1;
            }
            first = false;
        }
        None
    }
    fn go(p: &[char], n: &[char]) -> bool {
        match p.split_first() {
            None => n.is_empty(),
            Some(('*', rest)) => (0..=n.len()).any(|i| go(rest, &n[i..])),
            Some(('?', rest)) => !n.is_empty() && go(rest, &n[1..]),
            Some(('[', _)) if !n.is_empty() => match class(p, n[0]) {
                Some((rest, true)) => go(rest, &n[1..]),
                Some((_, false)) => false,
                None => n[0] == '[' && go(&p[1..], &n[1..]),
            },
            Some((c, rest)) => n.first() == Some(c) && go(rest, &n[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    go(&p, &n)
}

/// Runs `ssh -G -F <config> -- <alias>`. The outer error is for "could not
/// run ssh"; the inner one is ssh's own error text for this alias.
pub fn resolve(opts: &ImportOptions, alias: &str) -> Result<Result<Resolved, String>, ImportError> {
    let mut child = Command::new(&opts.ssh)
        .arg("-G")
        .arg("-F")
        .arg(&opts.config)
        .arg("--")
        .arg(alias)
        .env("HOME", &opts.home)
        .env_remove("SSH_AUTH_SOCK")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ImportError::Spawn(format!("{}: {e}", opts.ssh.display())))?;
    let stdout = read_in_thread(child.stdout.take());
    let stderr = read_in_thread(child.stderr.take());
    let deadline = Instant::now() + opts.timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                // A command from the config may still hold the pipes open;
                // do not wait for the reader threads.
                return Ok(Err(format!(
                    "ssh -G took longer than {} seconds; stopped",
                    opts.timeout.as_secs_f32()
                )));
            }
            Err(e) => return Err(ImportError::Spawn(e.to_string())),
        }
    };
    let stdout = stdout.join().unwrap_or_default();
    let stderr = stderr.join().unwrap_or_default();
    if !status.success() {
        let err = String::from_utf8_lossy(&stderr);
        let err = err
            .lines()
            .filter(|l| !l.starts_with("Pseudo-terminal will not be allocated"))
            .collect::<Vec<_>>()
            .join(" ");
        return Ok(Err(format!("ssh -G failed ({status}): {}", err.trim())));
    }
    Ok(Ok(parse_g_output(&String::from_utf8_lossy(&stdout))))
}

fn read_in_thread<R: Read + Send + 'static>(pipe: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = pipe {
            let _ = p.take(MAX_CONFIG_BYTES).read_to_end(&mut buf);
        }
        buf
    })
}

fn parse_g_output(text: &str) -> Resolved {
    let mut r = Resolved::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        match key {
            "hostname" => r.hostname = Some(value.to_string()),
            "user" => r.user = Some(value.to_string()),
            "port" => r.port = value.parse().ok(),
            "identityfile" => r.identity_files.push(value.to_string()),
            _ => {}
        }
    }
    r
}

/// Expands `~` and the `%d`, `%h`, `%r`, `%%` tokens in an identity file
/// path. Returns `None` for other tokens; such a path matches no key.
fn expand_identity(path: &str, home: &Path, r: &Resolved) -> Option<PathBuf> {
    let home_str = home.to_str()?;
    let path = match path.strip_prefix("~/") {
        Some(rest) => format!("{home_str}/{rest}"),
        None => path.to_string(),
    };
    let mut out = String::new();
    let mut chars = path.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            '%' => out.push('%'),
            'd' => out.push_str(home_str),
            'h' => out.push_str(r.hostname.as_deref()?),
            'r' => out.push_str(r.user.as_deref()?),
            _ => return None,
        }
    }
    Some(PathBuf::from(out))
}

fn same_file(a: &Path, b: &Path) -> bool {
    a == b || matches!((a.canonicalize(), b.canonicalize()), (Ok(x), Ok(y)) if x == y)
}

fn matching_keys<'k>(r: &Resolved, home: &Path, keys: &'k [KnownKey]) -> Vec<&'k KnownKey> {
    let mut out: Vec<&KnownKey> = Vec::new();
    for file in &r.identity_files {
        let Some(path) = expand_identity(file, home, r) else {
            continue;
        };
        for key in keys {
            if same_file(&path, &key.private_path) && !out.contains(&key) {
                out.push(key);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Status;
    use identity_core::{PublicKey, parse_public_keys};

    fn keygen(path: &Path) -> KnownKey {
        let out = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "test", "-f"])
            .arg(path)
            .env("HOME", path.parent().unwrap())
            .stdin(Stdio::null())
            .output()
            .expect("ssh-keygen (openssh-clients) must be installed");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut pubpath = path.as_os_str().to_owned();
        pubpath.push(".pub");
        let parsed = parse_public_keys(&fs::read(pubpath).unwrap()).unwrap();
        let Ok(PublicKey::Ssh(key)) = &parsed[0].key else {
            panic!("not an ssh key: {parsed:?}");
        };
        KnownKey {
            private_path: path.to_path_buf(),
            fingerprint: key.fingerprint.clone(),
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
        config: PathBuf,
        work: KnownKey,
        personal: KnownKey,
    }

    /// A temp home with two keys and a config that uses `Include`, a glob
    /// include, wildcard and negated patterns, `Match` and `%` tokens.
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let ssh = home.join(".ssh");
        fs::create_dir_all(ssh.join("conf.d")).unwrap();
        let work = keygen(&ssh.join("id_work"));
        let personal = keygen(&ssh.join("id_ed25519"));
        let inc = ssh.join("conf.d");
        fs::write(
            inc.join("10-git"),
            "Host git.example.org\n  User git\n  IdentityFile ~/.ssh/id_work\n",
        )
        .unwrap();
        fs::write(
            inc.join("20-other"),
            "# comment\nHost=\"pi\" *.lan\n  HostName 192.0.2.7\n",
        )
        .unwrap();
        fs::write(inc.join(".hidden"), "Host hidden\n").unwrap();
        fs::write(inc.join("notes.txt"), "Host notes\n").unwrap();
        fs::write(
            ssh.join("work.conf"),
            "Host build build-alias\n  HostName build.example.com\n  Port 2222\n  \
             User me\n  IdentityFile %d/.ssh/id_work\n",
        )
        .unwrap();
        let config = ssh.join("config");
        fs::write(
            &config,
            format!(
                "Include {inc}/[0-9]*\nInclude {inc}/??-*\n\
                 Include {ssh}/work.conf\nInclude {ssh}/missing.conf\n\
                 Host * !bastion\n  ServerAliveInterval 30\n\
                 Host bastion jump? build\n  ForwardAgent no\n\
                 Match host nothing\n  User nobody\n",
                inc = inc.display(),
                ssh = ssh.display(),
            ),
        )
        .unwrap();
        Fixture {
            _dir: dir,
            home,
            config,
            work,
            personal,
        }
    }

    #[test]
    fn split_line_handles_equals_quotes_and_comments() {
        assert_eq!(
            split_line("  Host  a \"b c\" d # x"),
            Some(("Host".into(), vec!["a".into(), "b c".into(), "d".into()]))
        );
        assert_eq!(
            split_line("host=one"),
            Some(("host".into(), vec!["one".into()]))
        );
        assert_eq!(
            split_line("Host = one two"),
            Some(("Host".into(), vec!["one".into(), "two".into()]))
        );
        assert_eq!(split_line("   # comment"), None);
        assert_eq!(split_line(""), None);
    }

    #[test]
    fn host_aliases_follow_include_and_skip_wildcards() {
        let f = fixture();
        let aliases = host_aliases(&f.config, &f.home).unwrap();
        // `[0-9]*` and `??-*` both name 10-git and 20-other; each alias
        // is listed once.
        assert_eq!(
            aliases,
            vec!["git.example.org", "pi", "build", "build-alias", "bastion"]
        );
    }

    #[test]
    fn relative_include_is_under_home_ssh() {
        let f = fixture();
        let cfg = f.home.join(".ssh/relative");
        fs::write(&cfg, "Include work.conf\nInclude ~/.ssh/conf.d/10-*\n").unwrap();
        let aliases = host_aliases(&cfg, &f.home).unwrap();
        assert_eq!(aliases, vec!["build", "build-alias", "git.example.org"]);
    }

    #[test]
    fn include_loop_stops_at_depth_limit() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("loop");
        fs::write(&cfg, format!("Host a\nInclude {}\n", cfg.display())).unwrap();
        let err = host_aliases(&cfg, dir.path()).unwrap_err();
        assert!(matches!(err, ImportError::IncludeDepth(_)), "{err}");
    }

    #[test]
    fn expands_identity_tokens() {
        let r = Resolved {
            hostname: Some("h.example".into()),
            user: Some("bob".into()),
            ..Resolved::default()
        };
        let home = Path::new("/home/t");
        let e = |p| expand_identity(p, home, &r);
        assert_eq!(e("~/.ssh/id"), Some("/home/t/.ssh/id".into()));
        assert_eq!(e("%d/k_%h_%r%%"), Some("/home/t/k_h.example_bob%".into()));
        assert_eq!(e("/k/%u"), None);
        assert_eq!(e("/k/%"), None);
    }

    #[test]
    fn imports_hosts_from_config_fixture() {
        let f = fixture();
        let mut store = Store::open_in_memory().unwrap();
        let keys = [f.work.clone(), f.personal.clone()];
        let opts = ImportOptions::new(&f.config, &f.home);
        let report = import_ssh_config(&mut store, &opts, &keys).unwrap();
        assert!(report.failed.is_empty(), "{report:?}");
        assert!(report.existing.is_empty(), "{report:?}");
        assert!(report.without_key.is_empty(), "{report:?}");

        let locs = store.list().unwrap();
        let find = |alias: &str| -> Vec<_> {
            locs.iter()
                .filter(|l| matches!(&l.target, Target::Ssh(h) if h.alias == alias))
                .collect()
        };
        for l in &locs {
            assert_eq!(l.kind, LocationKind::SshServer);
            assert_eq!(l.purpose, Purpose::SshAuth);
            assert_eq!(l.status, Status::Unverified);
            assert_eq!(l.last_checked, None);
        }

        // An explicit IdentityFile replaces ssh's default list.
        let git = find("git.example.org");
        assert_eq!(git.len(), 1);
        assert_eq!(git[0].key, f.work.fingerprint);
        let Target::Ssh(h) = &git[0].target else {
            unreachable!()
        };
        assert_eq!(h.user.as_deref(), Some("git"));
        assert_eq!(h.port, Some(22));

        let build = find("build");
        assert_eq!(build.len(), 1);
        assert_eq!(build[0].key, f.work.fingerprint);
        let Target::Ssh(h) = &build[0].target else {
            unreachable!()
        };
        assert_eq!(h.hostname.as_deref(), Some("build.example.com"));
        assert_eq!(h.user.as_deref(), Some("me"));
        assert_eq!(h.port, Some(2222));

        // No IdentityFile: ssh's default list, of which id_ed25519 exists.
        let pi = find("pi");
        assert_eq!(pi.len(), 1);
        assert_eq!(pi[0].key, f.personal.fingerprint);
        let Target::Ssh(h) = &pi[0].target else {
            unreachable!()
        };
        assert_eq!(h.hostname.as_deref(), Some("192.0.2.7"));

        assert_eq!(find("build-alias").len(), 1);
        assert_eq!(find("bastion").len(), 1);
        for skipped in [
            "*", "*.lan", "!bastion", "jump?", "hidden", "notes", "nothing",
        ] {
            assert!(find(skipped).is_empty(), "{skipped} was imported");
        }

        // A second import adds nothing and keeps check results.
        let first = locs[0].id;
        store
            .set_status(first, &Status::Verified, std::time::SystemTime::now())
            .unwrap();
        let again = import_ssh_config(&mut store, &opts, &keys).unwrap();
        assert!(again.added.is_empty());
        assert_eq!(again.existing.len(), report.added.len());
        assert_eq!(store.list().unwrap().len(), locs.len());
        assert_eq!(store.get(first).unwrap().unwrap().status, Status::Verified);
    }

    #[test]
    fn hosts_without_a_scanned_key_are_reported() {
        let f = fixture();
        let mut store = Store::open_in_memory().unwrap();
        let opts = ImportOptions::new(&f.config, &f.home);
        let report = import_ssh_config(&mut store, &opts, &[]).unwrap();
        assert!(report.added.is_empty());
        assert_eq!(
            report.without_key,
            vec!["git.example.org", "pi", "build", "build-alias", "bastion"]
        );
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn bad_alias_is_reported_not_fatal() {
        let f = fixture();
        let cfg = f.home.join(".ssh/bad");
        fs::write(&cfg, "Host -oProxyCommand=x\nHost ok\n").unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let opts = ImportOptions::new(&cfg, &f.home);
        let report =
            import_ssh_config(&mut store, &opts, std::slice::from_ref(&f.personal)).unwrap();
        assert_eq!(report.failed.len(), 1, "{report:?}");
        assert_eq!(report.failed[0].0, "-oProxyCommand=x");
        assert_eq!(report.added.len(), 1);
    }

    #[test]
    fn glob_classes() {
        assert!(glob_match("[0-9]*", "10-git"));
        assert!(!glob_match("[0-9]*", "a10"));
        assert!(glob_match("[!a]x", "bx"));
        assert!(!glob_match("[!a]x", "ax"));
        assert!(glob_match("a[]]b", "a]b"));
        assert!(glob_match("a[b", "a[b"));
        assert!(glob_match("*.conf", "x.conf"));
        assert!(!glob_match("*.conf", "x.conf~"));
    }

    fn exec_fixture(cmd: &str) -> (Fixture, PathBuf) {
        let f = fixture();
        let inc = f.home.join(".ssh/conf.d/30-exec");
        fs::write(&inc, format!("Match exec \"{cmd}\"\n  User nobody\n")).unwrap();
        let cfg = f.home.join(".ssh/config_exec");
        fs::write(
            &cfg,
            format!("Include {}\nHost pi\n  HostName 192.0.2.7\n", inc.display()),
        )
        .unwrap();
        (f, cfg)
    }

    #[test]
    fn match_exec_is_refused_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("EXEC_RAN");
        let (f, cfg) = exec_fixture(&format!("touch {}", marker.display()));
        let mut store = Store::open_in_memory().unwrap();
        let opts = ImportOptions::new(&cfg, &f.home);
        let err =
            import_ssh_config(&mut store, &opts, std::slice::from_ref(&f.personal)).unwrap_err();
        let ImportError::CommandsNeedConsent(why) = &err else {
            panic!("{err}");
        };
        assert_eq!(why.len(), 1, "{why:?}");
        assert!(why[0].contains("30-exec line 1"), "{why:?}");
        assert!(!marker.exists(), "ssh -G ran the Match exec command");
        assert!(store.list().unwrap().is_empty());

        // Other spellings ssh accepts (re-review, OpenSSH 10.5p1 ran all).
        for (i, line) in [
            "Match !exec \"true\" host x",
            "Match exec=\"true\"",
            "Match \"exec\" \"true\"",
            "Match\texec\t\"true\"",
            "Match final exec \"true\"",
            "Match tagged t exec \"true\"",
            "Match exec \"true\"\r",
            "MATCH EXEC true",
        ]
        .iter()
        .enumerate()
        {
            let cfg2 = f.home.join(format!(".ssh/config_exec_{i}"));
            fs::write(&cfg2, format!("{line}\n  User x\n")).unwrap();
            assert_eq!(
                scan_config(&cfg2, &f.home).unwrap().runs_commands.len(),
                1,
                "{line:?}"
            );
        }
    }

    #[test]
    fn match_exec_runs_only_with_consent() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("EXEC_RAN");
        let (f, cfg) = exec_fixture(&format!("touch {}", marker.display()));
        let mut store = Store::open_in_memory().unwrap();
        let mut opts = ImportOptions::new(&cfg, &f.home);
        opts.allow_commands = true;
        let report =
            import_ssh_config(&mut store, &opts, std::slice::from_ref(&f.personal)).unwrap();
        assert_eq!(report.added.len(), 1, "{report:?}");
        assert!(marker.exists());
    }

    #[test]
    fn ssh_g_has_a_time_limit() {
        let (f, cfg) = exec_fixture("sleep 5");
        let mut store = Store::open_in_memory().unwrap();
        let mut opts = ImportOptions::new(&cfg, &f.home);
        opts.allow_commands = true;
        opts.timeout = Duration::from_millis(300);
        let start = Instant::now();
        let report =
            import_ssh_config(&mut store, &opts, std::slice::from_ref(&f.personal)).unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(4),
            "{:?}",
            start.elapsed()
        );
        assert_eq!(report.failed.len(), 1, "{report:?}");
        assert!(report.failed[0].1.contains("took longer"), "{report:?}");
    }

    #[test]
    fn include_we_cannot_list_needs_consent() {
        let f = fixture();
        let cfg = f.home.join(".ssh/config_dirglob");
        fs::write(
            &cfg,
            format!(
                "Include {}/*/x\nInclude ~other/cfg\nInclude ${{XINC}}\n\
                 Include {}/%u_inc\nHost a\n",
                f.home.display(),
                f.home.display()
            ),
        )
        .unwrap();
        let scan = scan_config(&cfg, &f.home).unwrap();
        assert_eq!(scan.aliases, vec!["a"]);
        assert_eq!(scan.runs_commands.len(), 4, "{:?}", scan.runs_commands);
        let mut store = Store::open_in_memory().unwrap();
        let opts = ImportOptions::new(&cfg, &f.home);
        assert!(matches!(
            import_ssh_config(&mut store, &opts, &[]),
            Err(ImportError::CommandsNeedConsent(_))
        ));
    }
}
