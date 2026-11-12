//! Key generation and retire against a temp HOME (T10).

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use rotation::{
    GEN_DIR_PREFIX, KeyType, KeygenError, KeygenRequest, Moved, Passphrase, Recovered, generate,
    recover, retire,
};
use test_support::TempHome;

const BASE: &str = env!("CARGO_TARGET_TMPDIR");

fn request(home: &TempHome, name: &str) -> KeygenRequest {
    let ssh = home.ssh_dir();
    let mut req = KeygenRequest::new(&ssh, ssh.join(name));
    req.passphrase = Passphrase::Empty;
    req.comment = Some("test@key-steward".into());
    req
}

fn keygen(path: &Path) {
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `ssh-keygen -lf <pub>`: bits, fingerprint, comment, type.
fn listing(pub_path: &Path) -> Vec<String> {
    let out = Command::new("ssh-keygen")
        .arg("-lf")
        .arg(pub_path)
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

fn pub_of(p: &Path) -> PathBuf {
    PathBuf::from(format!("{}.pub", p.display()))
}

fn gen_dirs(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(GEN_DIR_PREFIX))
        .collect()
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// A wrapper that runs the real `ssh-keygen`, then runs `then` with the
/// `-f` path as `$1`.
fn wrapper(home: &TempHome, then: &str) -> PathBuf {
    let p = home.path().join("keygen-wrapper.sh");
    fs::write(
        &p,
        format!(
            "#!/bin/sh\nssh-keygen \"$@\" || exit $?\n\
             while [ $# -gt 1 ]; do [ \"$1\" = -f ] && f=$2; shift; done\n\
             set -- \"$f\"\n{then}\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    p
}

#[test]
fn generate_makes_pair() {
    let home = TempHome::new(BASE);
    let req = request(&home, "id_new");
    let made = generate(&req).unwrap();
    assert_eq!(made.private_path, req.new_path);
    assert_eq!(made.public_path, pub_of(&req.new_path));
    let l = listing(&made.public_path);
    assert_eq!(l[1], made.fingerprint.as_str());
    assert_eq!(l[2], "test@key-steward");
    assert_eq!(l[3], "(ED25519)");
    assert_eq!(fs::metadata(&req.new_path).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(&req.new_path).unwrap().nlink(), 1);
    assert!(gen_dirs(&home.ssh_dir()).is_empty());

    let mut rsa = request(&home, "id_rsa_new");
    rsa.key_type = KeyType::Rsa;
    let made = generate(&rsa).unwrap();
    assert_eq!(listing(&made.public_path)[0], "4096");

    // S-1: Key Steward never opens the private file. The wrapper makes it
    // unreadable right after ssh-keygen wrote it; generation still works.
    let mut req = request(&home, "id_locked");
    req.program = wrapper(&home, "chmod 000 \"$1\"");
    let made = generate(&req).unwrap();
    assert_eq!(fs::metadata(&req.new_path).unwrap().mode() & 0o777, 0);
    assert_eq!(listing(&made.public_path)[1], made.fingerprint.as_str());
}

#[test]
fn generate_never_overwrites() {
    let home = TempHome::new(BASE);
    let ssh = home.ssh_dir();
    let req = request(&home, "id_taken");

    fs::write(&req.new_path, "keep me").unwrap();
    let err = generate(&req).unwrap_err();
    assert!(
        matches!(&err, KeygenError::Exists(p) if *p == req.new_path),
        "{err}"
    );
    assert_eq!(fs::read_to_string(&req.new_path).unwrap(), "keep me");
    fs::remove_file(&req.new_path).unwrap();

    fs::write(pub_of(&req.new_path), "keep me").unwrap();
    assert!(matches!(generate(&req), Err(KeygenError::Exists(_))));
    fs::remove_file(pub_of(&req.new_path)).unwrap();
    assert!(gen_dirs(&ssh).is_empty());

    // The name appears while ssh-keygen runs: the link fails, the other
    // file is untouched, and the new key stays in its temp dir.
    let mut req = request(&home, "id_race");
    req.program = wrapper(
        &home,
        &format!("echo theirs > '{}'", req.new_path.display()),
    );
    let err = generate(&req).unwrap_err();
    assert!(
        matches!(&err, KeygenError::Exists(p) if *p == req.new_path),
        "{err}"
    );
    assert_eq!(fs::read_to_string(&req.new_path).unwrap(), "theirs\n");
    let left = gen_dirs(&ssh);
    assert_eq!(left.len(), 1);
    assert_eq!(names(&ssh.join(&left[0])), ["id", "id.pub"]);

    // A failing ssh-keygen leaves nothing behind and touches nothing.
    let mut req = request(&home, "id_fail");
    req.program = PathBuf::from("false");
    assert!(matches!(generate(&req), Err(KeygenError::Keygen { .. })));
    assert!(!req.new_path.exists());
}

#[test]
fn recover_half_generated_key() {
    let home = TempHome::new(BASE);
    let ssh = home.ssh_dir();
    let retired = ssh.join("retired");

    // Neither final file: temp leftovers go to retired/, run again.
    let req = request(&home, "id_new");
    let tmp = ssh.join(format!("{GEN_DIR_PREFIX}1-2-0"));
    fs::create_dir(&tmp).unwrap();
    keygen(&tmp.join("id"));
    let Recovered::RunAgain { moved } = recover(&req).unwrap() else {
        panic!("expected RunAgain");
    };
    assert_eq!(moved.len(), 2);
    assert!(!tmp.exists());
    assert_eq!(
        names(&retired),
        ["keysteward-gen-1-2-0-id", "keysteward-gen-1-2-0-id.pub"]
    );
    assert_eq!(fs::metadata(&retired).unwrap().mode() & 0o777, 0o700);

    // Only the private file: moved to retired/, never deleted, run again.
    fs::create_dir(&tmp).unwrap();
    keygen(&tmp.join("id"));
    fs::hard_link(tmp.join("id"), &req.new_path).unwrap();
    let ino = fs::metadata(&req.new_path).unwrap().ino();
    let Recovered::RunAgain { moved } = recover(&req).unwrap() else {
        panic!("expected RunAgain");
    };
    assert_eq!(
        moved[0],
        Moved {
            from: req.new_path.clone(),
            to: retired.join("id_new"),
        }
    );
    assert_eq!(fs::metadata(retired.join("id_new")).unwrap().ino(), ino);
    assert!(!req.new_path.exists());
    assert!(!tmp.exists());
    // The temp name of the moved file was only a second name: dropped.
    assert_eq!(fs::metadata(retired.join("id_new")).unwrap().nlink(), 1);
    // The orphan .pub of that run is kept in retired/ too.
    assert!(names(&retired).iter().any(|n| n.ends_with("-id.pub")));

    // Then generate works.
    let made = generate(&req).unwrap();

    // Both final files plus temp names left by a crash: done, temp names
    // dropped, both files intact.
    fs::create_dir(&tmp).unwrap();
    fs::hard_link(&req.new_path, tmp.join("id")).unwrap();
    fs::hard_link(pub_of(&req.new_path), tmp.join("id.pub")).unwrap();
    let Recovered::Done(again) = recover(&req).unwrap() else {
        panic!("expected Done");
    };
    assert_eq!(*again, made);
    assert!(!tmp.exists());
    assert_eq!(fs::metadata(&req.new_path).unwrap().nlink(), 1);

    // Nothing at all: run again, nothing moved.
    let req = request(&home, "id_other");
    assert_eq!(
        recover(&req).unwrap(),
        Recovered::RunAgain { moved: vec![] }
    );
}

#[test]
fn retire_moves_without_overwrite() {
    let home = TempHome::new(BASE);
    let ssh = home.ssh_dir();
    let retired = ssh.join("retired");
    let old = ssh.join("id_old");

    keygen(&old);
    let ino = fs::metadata(&old).unwrap().ino();
    fs::set_permissions(&old, fs::Permissions::from_mode(0o000)).unwrap();
    // An older retired key with the same name, and a too open dir.
    fs::create_dir(&retired).unwrap();
    fs::set_permissions(&retired, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(retired.join("id_old"), "older").unwrap();

    let moved = retire(&ssh, &old).unwrap();
    assert_eq!(
        moved,
        vec![
            Moved {
                from: old.clone(),
                to: retired.join("id_old-1"),
            },
            Moved {
                from: pub_of(&old),
                to: retired.join("id_old-1.pub"),
            },
        ]
    );
    assert_eq!(fs::read_to_string(retired.join("id_old")).unwrap(), "older");
    assert_eq!(fs::metadata(retired.join("id_old-1")).unwrap().ino(), ino);
    assert!(!old.exists() && !pub_of(&old).exists());
    assert_eq!(fs::metadata(&retired).unwrap().mode() & 0o777, 0o700);

    // Again: nothing left to move.
    assert!(retire(&ssh, &old).unwrap().is_empty());

    // A crash after the link and before the unlink: retire again drops the
    // old name only, and keeps the pair on one suffix.
    let old2 = ssh.join("id_two");
    keygen(&old2);
    fs::write(retired.join("id_two.pub"), "older").unwrap();
    fs::hard_link(&old2, retired.join("id_two-1")).unwrap();
    let moved = retire(&ssh, &old2).unwrap();
    assert_eq!(moved[0].to, retired.join("id_two-1"));
    assert_eq!(moved[1].to, retired.join("id_two-1.pub"));
    assert_eq!(fs::metadata(retired.join("id_two-1")).unwrap().nlink(), 1);
    assert_eq!(
        fs::read_to_string(retired.join("id_two.pub")).unwrap(),
        "older"
    );

    // `retired` that is not a dir is refused, nothing moves.
    let home2 = TempHome::new(BASE);
    let ssh2 = home2.ssh_dir();
    keygen(&ssh2.join("id_x"));
    fs::write(ssh2.join("retired"), "").unwrap();
    assert!(retire(&ssh2, &ssh2.join("id_x")).is_err());
    assert!(ssh2.join("id_x").exists());
}

#[test]
fn recover_refuses_public_key_from_outside() {
    let home = TempHome::new(BASE);
    let ssh = home.ssh_dir();
    let req = request(&home, "id_new");
    // Crash after the private link; then another .pub shows up.
    let tmp = ssh.join(format!("{GEN_DIR_PREFIX}9-9-0"));
    fs::create_dir(&tmp).unwrap();
    keygen(&tmp.join("id"));
    fs::hard_link(tmp.join("id"), &req.new_path).unwrap();
    keygen(&ssh.join("other"));
    fs::copy(ssh.join("other.pub"), pub_of(&req.new_path)).unwrap();

    let err = recover(&req).unwrap_err();
    assert!(
        matches!(&err, KeygenError::PublicKeyMismatch(p) if *p == pub_of(&req.new_path)),
        "{err}"
    );
    // Nothing moved or removed.
    assert!(req.new_path.exists() && pub_of(&req.new_path).exists());
    assert_eq!(names(&tmp), ["id", "id.pub"]);
    assert!(!ssh.join("retired").exists());
}
