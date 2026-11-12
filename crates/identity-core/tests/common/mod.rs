//! A throwaway GnuPG home for tests. Never the real `~/.gnupg`.

#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

/// Kills its agent on drop.
pub struct GpgHome {
    dir: TempDir,
}

impl GpgHome {
    pub fn new() -> Self {
        // Short path under /tmp: the agent socket path has a length limit.
        let dir = tempfile::Builder::new()
            .prefix("ic-gpg")
            .tempdir_in("/tmp")
            .unwrap();
        GpgHome { dir }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn gpg(&self, args: &[&str]) -> Vec<u8> {
        let out = Command::new("gpg")
            .arg("--homedir")
            .arg(self.path())
            .args(["--batch", "--quiet", "--pinentry-mode", "loopback"])
            .args(["--passphrase", ""])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "gpg {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    /// `gpg --with-colons` output for `args`, as lines of fields.
    pub fn colons(&self, args: &[&str]) -> Vec<Vec<String>> {
        let mut all = vec!["--with-colons", "--fixed-list-mode"];
        all.extend_from_slice(args);
        String::from_utf8(self.gpg(&all))
            .unwrap()
            .lines()
            .map(|l| l.split(':').map(str::to_string).collect())
            .collect()
    }

    /// A sign-only primary key. Returns its fingerprint.
    pub fn gen_sign_only(&self, uid: &str) -> String {
        self.gpg(&["--quick-gen-key", uid, "ed25519", "sign", "1y"]);
        self.colons(&["--list-keys", uid])
            .iter()
            .find(|f| f[0] == "fpr")
            .map(|f| f[9].clone())
            .unwrap()
    }

    /// Ed25519 primary key plus a Cv25519 encryption subkey.
    pub fn gen_key(&self, uid: &str) -> String {
        let fpr = self.gen_sign_only(uid);
        self.gpg(&["--quick-add-key", &fpr, "cv25519", "encr", "1y"]);
        fpr
    }

    pub fn export(&self, fprs: &[&str]) -> Vec<u8> {
        let mut args = vec!["--armor", "--export"];
        args.extend_from_slice(fprs);
        self.gpg(&args)
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(self.path())
            .args(["--kill", "all"])
            .status();
    }
}
