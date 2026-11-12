//! Test harness for the `send-secret` CLI: a throwaway home for every test.
//!
//! `TestEnv` makes a temp dir with `HOME`, `GNUPGHOME`, `XDG_CONFIG_HOME`
//! and `XDG_DATA_HOME`, and runs our binary, `gpg` and `age` with only those
//! variables (plus `PATH` and `LC_ALL=C`). Nothing reads or writes the real
//! home dir. The dir and its gpg-agent go away when the `TestEnv` drops.

// Each test binary uses a different part of the harness.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

pub struct TestEnv {
    dir: tempfile::TempDir,
}

/// The fixture dir made by `send-secret/tests/fixtures/gen.sh`.
pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

pub fn fixture(rel: &str) -> PathBuf {
    let path = fixtures().join(rel);
    assert!(path.is_file(), "missing fixture {rel}");
    path
}

/// A random string to put in plaintext, so a test can scan for it later.
pub fn marker() -> String {
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("read /dev/urandom");
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("send-secret-marker-{hex}")
}

impl TestEnv {
    pub fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("ss-test-")
            .tempdir()
            .expect("temp dir");
        let env = TestEnv { dir };
        for sub in [env.home(), env.config_home(), env.data_home()] {
            fs::create_dir_all(sub).expect("create dir");
        }
        fs::create_dir_all(env.gnupg_home()).expect("create GNUPGHOME");
        fs::set_permissions(env.gnupg_home(), fs::Permissions::from_mode(0o700))
            .expect("chmod GNUPGHOME");
        env
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    pub fn home(&self) -> PathBuf {
        self.root().join("home")
    }

    pub fn gnupg_home(&self) -> PathBuf {
        self.home().join(".gnupg")
    }

    pub fn config_home(&self) -> PathBuf {
        self.home().join(".config")
    }

    pub fn data_home(&self) -> PathBuf {
        self.home().join(".local/share")
    }

    /// A path inside the env for test input and output files.
    pub fn path(&self, name: &str) -> PathBuf {
        self.root().join(name)
    }

    /// A `Command` for `program` with a clean environment pointing at this env.
    pub fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear()
            .env("HOME", self.home())
            .env("GNUPGHOME", self.gnupg_home())
            .env("XDG_CONFIG_HOME", self.config_home())
            .env("XDG_DATA_HOME", self.data_home())
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("LC_ALL", "C")
            .current_dir(self.root())
            .stdin(Stdio::null());
        cmd
    }

    /// Our `send-secret` binary.
    pub fn ours(&self) -> Command {
        self.command(env!("CARGO_BIN_EXE_send-secret"))
    }

    /// `gpg` in batch mode with loopback pinentry, so it never prompts.
    pub fn gpg(&self) -> Command {
        let mut cmd = self.command("gpg");
        cmd.args(["--batch", "--no-tty", "--pinentry-mode", "loopback"]);
        cmd
    }

    /// Go `age`.
    pub fn age(&self) -> Command {
        self.command("age")
    }

    /// Imports a fixture OpenPGP key (`openpgp/<file>`) into this env's
    /// `GNUPGHOME`. Use the `.sec.asc` file to import a secret key.
    pub fn import_openpgp(&self, file: &str) {
        let path = fixture(&format!("openpgp/{file}"));
        let out = self
            .gpg()
            .arg("--import")
            .arg(path)
            .output()
            .expect("run gpg");
        assert_success(&out, "gpg --import");
    }

    /// Copies a fixture private key into the env with mode 0600, since git
    /// does not keep file modes and `ssh-keygen` refuses open keys.
    pub fn private_copy(&self, rel: &str) -> PathBuf {
        let dest = self.path(Path::new(rel).file_name().unwrap().to_str().unwrap());
        fs::copy(fixture(rel), &dest).expect("copy fixture");
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o600)).expect("chmod");
        dest
    }
}

impl Default for TestEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        // Kill the agent first, then remove its socket dir, which may live
        // under /run/user instead of the temp dir.
        for args in [&["--kill", "all"][..], &["--remove-socketdir"][..]] {
            let _ = self
                .command("gpgconf")
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// Runs `cmd`, feeding `input` on stdin.
pub fn run_with_input(cmd: &mut Command, input: &[u8]) -> Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let input = input.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let out = child.wait_with_output().expect("wait");
    // A child that fails before reading all input (a usage error) closes
    // the pipe; that is not a test failure.
    if let Err(e) = writer.join().expect("writer thread")
        && (e.kind() != std::io::ErrorKind::BrokenPipe || out.status.success())
    {
        panic!("write stdin: {e}");
    }
    out
}

pub fn assert_success(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}
