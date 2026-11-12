//! SSH dir scan (Key Steward T04). Keys are made in a temp dir, never the
//! real `~/.ssh`.

use std::path::Path;
use std::process::Command;

use identity_core::{KeyAlgo, KeyError, PrivateKeyProtection, scan_ssh_dir};

fn keygen(dir: &Path, name: &str, args: &[&str]) {
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-C", "test@example.org", "-f"])
        .arg(dir.join(name))
        .args(args)
        .status()
        .unwrap()
        .success();
    assert!(ok, "ssh-keygen {args:?}");
}

#[test]
fn scan_temp_ssh_dir() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    keygen(d, "id_ed25519", &["-t", "ed25519", "-N", ""]);
    keygen(
        d,
        "id_rsa",
        &["-t", "rsa", "-b", "3072", "-N", "passphrase"],
    );
    keygen(d, "only_private", &["-t", "ed25519", "-N", ""]);
    std::fs::remove_file(d.join("only_private.pub")).unwrap();
    keygen(d, "pair", &["-t", "ed25519", "-N", ""]);
    std::fs::remove_file(d.join("pair")).unwrap();
    std::fs::write(d.join("garbage.pub"), "not a key\n").unwrap();
    let two = format!(
        "{}{}",
        std::fs::read_to_string(d.join("id_ed25519.pub")).unwrap(),
        std::fs::read_to_string(d.join("pair.pub")).unwrap()
    );
    std::fs::write(d.join("two.pub"), two).unwrap();
    std::fs::write(d.join("known_hosts"), "").unwrap();
    std::fs::write(d.join("config"), "Host x\n").unwrap();
    std::fs::create_dir(d.join("retired")).unwrap();
    keygen(&d.join("retired"), "old", &["-t", "ed25519", "-N", ""]);
    std::fs::create_dir(d.join("dir.pub")).unwrap();

    let found = scan_ssh_dir(d).unwrap();
    let names: Vec<_> = found
        .iter()
        .map(|f| f.public_path.file_name().unwrap().to_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "garbage.pub",
            "id_ed25519.pub",
            "id_rsa.pub",
            "pair.pub",
            "two.pub"
        ]
    );

    let ed = &found[1];
    assert_eq!(ed.key.as_ref().unwrap().algo, KeyAlgo::Ed25519);
    assert_eq!(
        ed.private_path.as_deref(),
        Some(d.join("id_ed25519").as_path())
    );
    assert_eq!(ed.protection, Some(PrivateKeyProtection::Unencrypted));
    let private_mtime = std::fs::metadata(d.join("id_ed25519"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(ed.file_date, Some(private_mtime));

    let rsa = &found[2];
    assert_eq!(rsa.key.as_ref().unwrap().algo, KeyAlgo::Rsa(3072));
    assert_eq!(rsa.protection, Some(PrivateKeyProtection::Encrypted));

    let pair = &found[3];
    assert!(pair.key.is_ok());
    assert_eq!(pair.private_path, None);
    assert_eq!(pair.protection, None);
    let pub_mtime = std::fs::metadata(d.join("pair.pub"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(pair.file_date, Some(pub_mtime));

    assert!(matches!(found[0].key, Err(KeyError::Line(_))));
    assert!(matches!(found[4].key, Err(KeyError::NotOneKey)));
}

#[test]
fn scan_missing_dir_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        scan_ssh_dir(&dir.path().join("nope")),
        Err(KeyError::Io(_))
    ));
}
