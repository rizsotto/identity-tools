//! Remote scripts run locally, without ssh, under bash, dash and BusyBox
//! `sh` (SPEC 9.1, S-6). Each run uses the real bootstrap command, with
//! the shell under test as the login shell and as `sh` in `PATH`. For
//! BusyBox, `PATH` holds only BusyBox applets, like a small Alpine box.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use providers::remote::{
    self, APPLY, ApplyReply, Cksum, READ, ReadReply, cksum, parse_apply, parse_read,
};
use tempfile::TempDir;

struct Shell {
    name: &'static str,
    /// Holds `sh` (and for BusyBox all applets).
    bin: TempDir,
    path: String,
}

fn which(name: &str) -> PathBuf {
    for dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
        let p = Path::new(dir).join(name);
        if p.exists() {
            return p;
        }
    }
    panic!("{name} not found; it must be in the devcontainer");
}

fn shells() -> Vec<Shell> {
    let mut out = Vec::new();
    for name in ["bash", "dash", "busybox"] {
        let bin = tempfile::tempdir().unwrap();
        let exe = which(name);
        let path = if name == "busybox" {
            let list = Command::new(&exe).arg("--list").output().unwrap();
            for applet in String::from_utf8(list.stdout).unwrap().lines() {
                symlink(&exe, bin.path().join(applet)).unwrap();
            }
            bin.path().display().to_string()
        } else {
            symlink(&exe, bin.path().join("sh")).unwrap();
            format!("{}:/usr/bin:/bin", bin.path().display())
        };
        out.push(Shell { name, bin, path });
    }
    out
}

impl Shell {
    /// Runs `script` the way ssh would: the login shell gets the bootstrap
    /// command, stdin is the script and then the data.
    fn run(&self, home: &Path, script: remote::Script, stdin: Vec<u8>) -> (i32, Vec<u8>) {
        let mut cmd = if self.name == "busybox" {
            let mut c = Command::new(self.bin.path().join("sh"));
            c.arg("-c");
            c
        } else {
            let mut c = Command::new(which(self.name));
            c.arg("-c");
            c
        };
        let mut child = cmd
            .arg(script.command())
            .env_clear()
            .env("HOME", home)
            .env("PATH", &self.path)
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || {
            let _ = input.write_all(&stdin);
        });
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap();
        assert!(
            out.stderr.is_empty(),
            "{}: stderr {}",
            self.name,
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code().unwrap_or(-1), out.stdout)
    }

    fn read(&self, home: &Path) -> ReadReply {
        let (code, out) = self.run(home, READ, remote::read_stdin());
        parse_read(&out).unwrap_or_else(|e| panic!("{}: {e} (exit {code})", self.name))
    }

    fn apply(&self, home: &Path, old: Cksum, new: &[u8]) -> (i32, ApplyReply) {
        let (code, out) = self.run(home, APPLY, remote::apply_stdin(old, new));
        let reply = parse_apply(&out)
            .unwrap_or_else(|e| panic!("{}: {e}: {}", self.name, String::from_utf8_lossy(&out)));
        (code, reply)
    }
}

/// A temp HOME with `.ssh` (0700) and optionally `authorized_keys`.
fn home(content: Option<&[u8]>) -> TempDir {
    let home = tempfile::tempdir().unwrap();
    let ssh = home.path().join(".ssh");
    fs::create_dir(&ssh).unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    if let Some(c) = content {
        fs::write(ssh.join("authorized_keys"), c).unwrap();
    }
    home
}

fn ak(home: &TempDir) -> PathBuf {
    home.path().join(".ssh/authorized_keys")
}

/// Names in `.ssh` other than `authorized_keys`.
fn extra_files(home: &TempDir) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(home.path().join(".ssh"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != "authorized_keys")
        .collect();
    names.sort();
    names
}

fn mode(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
}

const OLD: &[u8] = b"# c\r\nrestrict ssh-ed25519 AAAA old\nssh-ed25519 BBBB other";
const NEW: &[u8] = b"# c\r\nrestrict ssh-ed25519 CCCC new\nssh-ed25519 BBBB other";

#[test]
fn scripts_under_three_shells() {
    for sh in shells() {
        let n = sh.name;

        let h = home(None);
        assert_eq!(sh.read(h.path()), ReadReply::Absent, "{n}");
        assert_eq!(sh.apply(h.path(), cksum(b""), NEW), (4, ApplyReply::Absent));
        assert!(extra_files(&h).is_empty(), "{n}");

        let h = home(Some(OLD));
        let ReadReply::Present { content, sum } = sh.read(h.path()) else {
            panic!("{n}: not present");
        };
        assert_eq!(content, OLD, "{n}");
        assert_eq!(sum, cksum(OLD), "{n}");
        let (code, reply) = sh.apply(h.path(), sum, NEW);
        assert_eq!((code, reply), (0, ApplyReply::Done(cksum(NEW))), "{n}");
        assert_eq!(fs::read(ak(&h)).unwrap(), NEW, "{n}");
        assert_eq!(
            sh.read(h.path()),
            ReadReply::Present {
                content: NEW.to_vec(),
                sum: cksum(NEW)
            },
            "{n}"
        );

        // Empty file and empty new content.
        let h = home(Some(b""));
        assert_eq!(
            sh.read(h.path()),
            ReadReply::Present {
                content: vec![],
                sum: cksum(b"")
            },
            "{n}"
        );
        assert_eq!(
            sh.apply(h.path(), cksum(b""), b"x\n").1,
            ApplyReply::Done(cksum(b"x\n"))
        );

        // A directory in its place.
        let h = home(None);
        fs::create_dir(ak(&h)).unwrap();
        assert_eq!(sh.read(h.path()), ReadReply::NotFile, "{n}");
        assert_eq!(
            sh.apply(h.path(), cksum(b""), NEW),
            (4, ApplyReply::NotFile)
        );

        // Over 1 MB is not sent.
        let big = vec![b'#'; 1_000_001];
        let h = home(Some(&big));
        assert_eq!(sh.read(h.path()), ReadReply::TooLarge, "{n}");

        // The new content does not arrive whole: nothing written.
        let h = home(Some(OLD));
        let mut stdin = remote::apply_stdin(cksum(OLD), NEW);
        stdin.truncate(stdin.len() - 3);
        let (code, out) = sh.run(h.path(), APPLY, stdin);
        assert_eq!((code, parse_apply(&out)), (6, Ok(ApplyReply::Short)), "{n}");
        assert_eq!(fs::read(ak(&h)).unwrap(), OLD, "{n}");
        assert!(extra_files(&h).is_empty(), "{n}: {:?}", extra_files(&h));

        // A bad header: nothing written.
        let h = home(Some(OLD));
        let stdin = [APPLY.body.as_bytes(), b"1 2 x 4\n", NEW].concat();
        let (code, out) = sh.run(h.path(), APPLY, stdin);
        assert_eq!(
            (code, parse_apply(&out)),
            (2, Ok(ApplyReply::BadInput)),
            "{n}"
        );
        assert_eq!(fs::read(ak(&h)).unwrap(), OLD, "{n}");

        // No temp file possible (`.ssh` not writable): nothing written.
        let h = home(Some(OLD));
        let ssh = h.path().join(".ssh");
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o500)).unwrap();
        assert_eq!(
            sh.apply(h.path(), cksum(OLD), NEW),
            (5, ApplyReply::NoTemp),
            "{n}"
        );
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(fs::read(ak(&h)).unwrap(), OLD, "{n}");
        assert!(extra_files(&h).is_empty(), "{n}");
    }
}

#[test]
fn apply_refuses_changed_file() {
    for sh in shells() {
        let h = home(Some(OLD));
        let changed = [OLD, b"\n"].concat();
        fs::write(ak(&h), &changed).unwrap();
        let (code, reply) = sh.apply(h.path(), cksum(OLD), NEW);
        assert_eq!((code, reply), (3, ApplyReply::Changed), "{}", sh.name);
        assert_eq!(fs::read(ak(&h)).unwrap(), changed, "{}", sh.name);
        assert!(extra_files(&h).is_empty(), "{}", sh.name);
    }
}

#[test]
fn apply_refuses_symlink() {
    for sh in shells() {
        let h = home(None);
        let real = h.path().join("real_keys");
        fs::write(&real, OLD).unwrap();
        symlink(&real, ak(&h)).unwrap();
        assert_eq!(sh.read(h.path()), ReadReply::Symlink, "{}", sh.name);
        let (code, reply) = sh.apply(h.path(), cksum(OLD), NEW);
        assert_eq!((code, reply), (4, ApplyReply::Symlink), "{}", sh.name);
        assert_eq!(fs::read(&real).unwrap(), OLD, "{}", sh.name);
        assert!(
            fs::symlink_metadata(ak(&h))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(extra_files(&h).is_empty(), "{}", sh.name);
    }
}

#[test]
fn apply_makes_backup_and_0600() {
    for sh in shells() {
        let n = sh.name;
        let h = home(Some(OLD));
        fs::set_permissions(ak(&h), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            sh.apply(h.path(), cksum(OLD), NEW).1,
            ApplyReply::Done(cksum(NEW))
        );
        assert_eq!(mode(&ak(&h)), 0o600, "{n}");
        let extra = extra_files(&h);
        assert_eq!(extra.len(), 1, "{n}: {extra:?}");
        let name = &extra[0];
        // authorized_keys.keysteward-YYYYMMDDTHHMMSSZ-<pid>
        let stamp = name
            .strip_prefix("authorized_keys.keysteward-")
            .unwrap_or_else(|| panic!("{n}: {name}"));
        let (time, pid) = stamp.split_once('-').unwrap();
        assert_eq!(time.len(), 16, "{n}: {name}");
        assert!(
            time.ends_with('Z') && time.as_bytes()[8] == b'T',
            "{n}: {name}"
        );
        assert!(pid.bytes().all(|b| b.is_ascii_digit()), "{n}: {name}");
        let backup = h.path().join(".ssh").join(name);
        assert_eq!(fs::read(&backup).unwrap(), OLD, "{n}");
        assert_eq!(mode(&backup), 0o600, "{n}");
    }
}

#[test]
fn bootstrap_has_no_quotes() {
    for script in [READ, APPLY] {
        let cmd = script.command();
        let inner = cmd
            .strip_prefix("sh -c '")
            .and_then(|c| c.strip_suffix('\''))
            .unwrap_or_else(|| panic!("{cmd}"));
        for bad in ['\'', '\\', '!', '\n'] {
            assert!(!inner.contains(bad), "{bad:?} in {cmd}");
        }
        assert_eq!(
            inner,
            format!(
                "eval \"$(dd bs=1 count={} 2>/dev/null)\"",
                script.body.len()
            )
        );
        let disk = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../remote-scripts")
            .join(script.name);
        assert_eq!(fs::read_to_string(disk).unwrap(), script.body);
        assert!(script.body.ends_with("main; exit $?\n"), "{}", script.name);
    }
}

#[test]
fn cksum_matches_posix_tool() {
    let mut inputs: Vec<Vec<u8>> = vec![vec![], b"a".to_vec(), OLD.to_vec()];
    // Lengths that need one, two and three length bytes.
    let mut x: u32 = 1;
    for len in [255, 256, 70_000, 1_000_000] {
        inputs.push(
            (0..len)
                .map(|_| {
                    x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    (x >> 16) as u8
                })
                .collect(),
        );
    }
    let tools = [vec![which("cksum")], vec![which("busybox"), "cksum".into()]];
    for input in &inputs {
        let ours = cksum(input).to_string();
        for tool in &tools {
            let mut child = Command::new(&tool[0])
                .args(&tool[1..])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(input).unwrap();
            let out = child.wait_with_output().unwrap();
            let theirs = String::from_utf8(out.stdout).unwrap();
            assert_eq!(theirs.trim(), ours, "{tool:?}, {} bytes", input.len());
        }
    }
}

#[test]
fn apply_header_is_not_globbed() {
    for sh in shells() {
        let h = home(Some(OLD));
        for name in ["1", "2", "3", "4"] {
            fs::write(h.path().join(name), "").unwrap();
        }
        let stdin = [APPLY.body.as_bytes(), b"*\n", NEW].concat();
        let (code, out) = sh.run(h.path(), APPLY, stdin);
        assert_eq!(
            (code, parse_apply(&out)),
            (2, Ok(ApplyReply::BadInput)),
            "{}",
            sh.name
        );
        assert_eq!(fs::read(ak(&h)).unwrap(), OLD, "{}", sh.name);
    }
}
