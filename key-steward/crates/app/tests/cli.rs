//! The `key-steward` binary against two test sshd servers (T16). Every
//! run gets a temp HOME, its own database and ssh dir, and no agent.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use providers::remote::APPLY;
use test_support::{ClientConfig, Sshd, TempHome};

const BASE: &str = env!("CARGO_TARGET_TMPDIR");
const BIN: &str = env!("CARGO_BIN_EXE_key-steward");

struct World {
    home: TempHome,
    a: Sshd,
    b: Sshd,
    cc: ClientConfig,
    old_path: PathBuf,
    old_blob: String,
}

fn keygen(path: &Path, comment: &str) {
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn blob(pub_path: &Path) -> String {
    fs::read_to_string(pub_path)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string()
}

/// The old key on srv-a and srv-b, named in the ssh config, and both
/// hosts imported as locations.
fn world() -> World {
    let home = TempHome::new(BASE);
    let ssh = home.ssh_dir();
    let old_path = ssh.join("id_old");
    keygen(&old_path, "old@test");
    let a = Sshd::start_named(BASE, "srv-a");
    let b = Sshd::start_named(BASE, "srv-b");
    a.authorize(&old_path);
    b.authorize(&old_path);
    let cc = ClientConfig::new(&[&a, &b]);
    let config = fs::read_to_string(cc.ssh_config()).unwrap().replace(
        "IdentityFile none",
        &format!("IdentityFile {}", old_path.display()),
    );
    fs::write(ssh.join("config"), config).unwrap();
    fs::set_permissions(ssh.join("config"), fs::Permissions::from_mode(0o600)).unwrap();
    let w = World {
        old_blob: blob(&ssh.join("id_old.pub")),
        home,
        a,
        b,
        cc,
        old_path,
    };
    let out = w.run(&["locations", "import-ssh-config"]);
    assert_ok(&out);
    assert!(stdout(&out).contains("2 added"), "{}", stdout(&out));
    w
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn assert_ok(o: &Output) {
    assert!(
        o.status.success(),
        "{:?}\n--- stdout\n{}\n--- stderr\n{}",
        o.status,
        stdout(o),
        stderr(o)
    );
}

impl World {
    fn ssh_dir(&self) -> PathBuf {
        self.home.ssh_dir()
    }

    fn db(&self) -> PathBuf {
        self.home.path().join("data/ks.db")
    }

    fn new_path(&self) -> PathBuf {
        self.ssh_dir().join("id_new")
    }

    fn command(&self, ssh_program: Option<&Path>) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.arg("--db")
            .arg(self.db())
            .arg("--ssh-dir")
            .arg(self.ssh_dir())
            .arg("--ssh-config")
            .arg(self.ssh_dir().join("config"))
            .arg("--known-hosts")
            .arg(self.cc.known_hosts())
            .env("HOME", self.home.path())
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("XDG_DATA_HOME")
            .stdin(Stdio::null());
        if let Some(p) = ssh_program {
            cmd.arg("--ssh-program").arg(p);
        }
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(None).args(args).output().unwrap()
    }

    fn rotate_args(&self, cmd: &str) -> Vec<String> {
        vec![
            "rotate".into(),
            cmd.into(),
            "--key".into(),
            self.old_path.display().to_string(),
            "--new-path".into(),
            self.new_path().display().to_string(),
            "--update-config".into(),
            "--no-passphrase".into(),
            "--comment".into(),
            "new@test".into(),
        ]
    }

    fn files(dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let meta = fs::symlink_metadata(&p).unwrap();
            if meta.is_dir() {
                Self::files(&p, out);
            } else if meta.is_file() {
                out.insert(p.clone(), fs::read(&p).unwrap());
            }
        }
    }

    /// The temp home (ssh dir, database) and both servers' homes.
    fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut out = BTreeMap::new();
        Self::files(self.home.path(), &mut out);
        Self::files(&self.a.server_home(), &mut out);
        Self::files(&self.b.server_home(), &mut out);
        out
    }

    fn keys_on(&self, s: &Sshd) -> String {
        fs::read_to_string(s.authorized_keys()).unwrap()
    }

    /// The rotation finished: each server holds the new key and not the
    /// old one, the config names only the new key, the old key files are
    /// in `retired/`.
    fn assert_rotated(&self) {
        let new_blob = blob(&self.ssh_dir().join("id_new.pub"));
        for s in [&self.a, &self.b] {
            let keys = self.keys_on(s);
            assert!(keys.contains(&new_blob), "{}: {keys}", s.alias());
            assert!(!keys.contains(&self.old_blob), "{}: {keys}", s.alias());
        }
        let config = fs::read_to_string(self.ssh_dir().join("config")).unwrap();
        assert!(!config.contains("id_old"), "{config}");
        assert_eq!(config.matches("id_new").count(), 2, "{config}");
        assert!(!self.old_path.exists());
        assert!(self.ssh_dir().join("retired/id_old").exists());
        assert!(self.ssh_dir().join("retired/id_old.pub").exists());
        // S-8: no key blob in the database.
        let db = fs::read(self.db()).unwrap();
        for b in [&new_blob, &self.old_blob] {
            assert!(!db.windows(b.len()).any(|w| w == b.as_bytes()));
        }
    }

    /// An ssh wrapper that runs the real ssh, then kills its parent (the
    /// app) with SIGKILL after the `kill_at`-th run of the apply script:
    /// a real `kill -9` after a remote edit and before its journal entry.
    fn wrapper(&self, kill_at: u32) -> PathBuf {
        let dir = self.home.path().join("wrapper");
        fs::create_dir_all(&dir).unwrap();
        let count = dir.join("count");
        let path = dir.join("ssh");
        let script = format!(
            "#!/bin/sh\n\
             ssh \"$@\"\n\
             rc=$?\n\
             for last; do :; done\n\
             case \"$last\" in\n\
             *\"count={len} 2\"*)\n\
             \x20 n=$(cat '{count}' 2>/dev/null || echo 0)\n\
             \x20 n=$((n + 1))\n\
             \x20 echo \"$n\" > '{count}'\n\
             \x20 if [ \"$n\" -eq {kill_at} ]; then kill -9 \"$PPID\"; fi\n\
             \x20 ;;\n\
             esac\n\
             exit $rc\n",
            len = APPLY.body.len(),
            count = count.display(),
        );
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}

#[test]
fn cli_plan_is_dry_run() {
    let w = world();
    let before = w.snapshot();

    let out = w.run(
        &w.rotate_args("plan")
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    assert_ok(&out);
    let text = stdout(&out);
    for want in [
        "Dry-run: nothing has been changed.",
        "Locations that will be changed (2)",
        "srv-a",
        "srv-b",
        "add the new key after line 2",
        "remove line 2",
        "before any removal: add `IdentityFile",
        "at retire: remove the old lines",
        "retired/id_old",
    ] {
        assert!(text.contains(want), "{want:?} not in\n{text}");
    }

    let mut args = w.rotate_args("plan");
    args.push("--json".into());
    let out = w.run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_ok(&out);
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(j["dry_run"], true);
    assert_eq!(j["locations"].as_array().unwrap().len(), 2);
    assert_eq!(
        j["config"]["insert_before_removals"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(!text.contains(&w.old_blob) && !stdout(&out).contains(&w.old_blob));

    // Nothing changed: local files, the database, both servers.
    assert_eq!(before, w.snapshot());
    assert!(!w.new_path().exists());
}

#[test]
fn cli_start_needs_yes() {
    let w = world();
    let before_db = fs::read(w.db()).unwrap();
    let before_a = w.keys_on(&w.a);

    let args = w.rotate_args("start");
    let out = w.run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("--yes"), "{}", stderr(&out));
    assert!(stdout(&out).contains("Dry-run"), "the plan is shown first");
    assert_eq!(fs::read(w.db()).unwrap(), before_db);
    assert_eq!(w.keys_on(&w.a), before_a);
    assert!(!w.new_path().exists());

    let mut args = args;
    args.push("--yes".into());
    let out = w.run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_ok(&out);
    assert!(
        stdout(&out).contains("Rotation 1: finished"),
        "{}",
        stdout(&out)
    );
    w.assert_rotated();

    let out = w.run(&["rotate", "status", "1"]);
    assert_ok(&out);
    assert!(
        stdout(&out).contains("Rotation 1: done"),
        "{}",
        stdout(&out)
    );
    let out = w.run(&["rotate", "log", "1"]);
    assert_ok(&out);
    let log = stdout(&out);
    assert!(log.contains("retire done"), "{log}");
    assert!(
        log.contains("ssh_server srv-a: ") && log.contains("BatchMode=yes"),
        "{log}"
    );
    assert!(!log.contains(&w.old_blob));
}

/// Starts with the kill wrapper, checks the app died by SIGKILL, then
/// resumes without it.
fn kill_then_resume(w: &World, kill_at: u32) -> String {
    let wrapper = w.wrapper(kill_at);
    let mut args = w.rotate_args("start");
    args.push("--yes".into());
    let out = w.command(Some(&wrapper)).args(&args).output().unwrap();
    assert_eq!(
        out.status.signal(),
        Some(9),
        "{:?}\n{}\n{}",
        out.status,
        stdout(&out),
        stderr(&out)
    );
    // Every location still has a key that logs in (S-3).
    for s in [&w.a, &w.b] {
        let keys = w.keys_on(s);
        assert!(
            keys.contains(&w.old_blob) || keys.contains(&blob(&w.ssh_dir().join("id_new.pub")))
        );
    }
    let out = w.run(&["rotate", "status"]);
    assert_ok(&out);
    let status = stdout(&out);

    let out = w.run(&["rotate", "resume", "1", "--yes"]);
    assert_ok(&out);
    assert!(
        stdout(&out).contains("Rotation 1: finished"),
        "{}",
        stdout(&out)
    );
    w.assert_rotated();
    status
}

#[test]
fn cli_kill_after_install_then_resume() {
    let w = world();
    let status = kill_then_resume(&w, 1);
    // Killed after the edit at srv-a, before its "done" entry.
    assert!(status.contains("last: install start"), "{status}");
    let log = stdout(&w.run(&["rotate", "log", "1"]));
    assert!(
        log.contains("install done location 1: settled after a restart"),
        "{log}"
    );
}

#[test]
fn cli_kill_after_remove_then_resume() {
    let w = world();
    let status = kill_then_resume(&w, 3);
    // Installs at srv-a and srv-b, then the removal at srv-a.
    assert!(status.contains("last: remove_old start"), "{status}");
    let keys = fs::read_to_string(w.a.authorized_keys()).unwrap();
    assert!(!keys.contains(&w.old_blob));
}
