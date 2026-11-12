//! `split_keys_leaves_keyring_untouched` (Send Secret M2 T03). Alone in
//! its own test binary because it sets `GNUPGHOME`, `HOME` and
//! `XDG_RUNTIME_DIR` for the whole process.

mod common;

use std::fs;
use std::path::Path;

use common::GpgHome;
use identity_core::Gpg;

/// Every file in `dir` (recursive) with its bytes.
fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(snapshot(&path));
        } else if path.is_file() {
            out.push((path.display().to_string(), fs::read(&path).unwrap()));
        }
    }
    out.sort();
    out
}

#[test]
fn split_keys_leaves_keyring_untouched() {
    let user = GpgHome::new();
    let mine = user.gen_key("Me Example (test fixture) <me@example.org>");
    let other = GpgHome::new();
    let a = other.gen_key("A Example (test fixture) <a@example.org>");
    let b = other.gen_key("B Example (test fixture) <b@example.org>");
    let blob = other.export(&[&a, &b]);

    let runtime = tempfile::tempdir().unwrap();
    // SAFETY: this test binary has only this test, so no other thread
    // reads the environment.
    unsafe {
        std::env::set_var("GNUPGHOME", user.path());
        std::env::set_var("HOME", user.path());
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
    }
    let list = || {
        user.colons(&["--list-keys"])
            .into_iter()
            .filter(|f| f[0] == "fpr")
            .map(|f| f[9].clone())
            .collect::<Vec<_>>()
    };
    let keys_before = list();
    let files_before = snapshot(user.path());

    let parts = Gpg::split_keys(&blob).unwrap();
    assert_eq!(parts.len(), 2);

    assert_eq!(snapshot(user.path()), files_before);
    assert_eq!(list(), keys_before);
    assert!(keys_before.contains(&mine));
    assert!(!keys_before.contains(&a) && !keys_before.contains(&b));
    // The throwaway home was made in XDG_RUNTIME_DIR and is gone.
    assert_eq!(fs::read_dir(runtime.path()).unwrap().count(), 0);
}
