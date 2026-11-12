use std::fs;
use std::os::unix::fs::PermissionsExt;

use test_support::{Sshd, check_dir_chain, current_user};

const BASE: &str = env!("CARGO_TARGET_TMPDIR");

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn harness_sshd_accepts_test_key() {
    let sshd = Sshd::start(BASE);
    let out = sshd.run(&sshd.client_key(), "true");
    assert!(out.status.success(), "ssh failed: {}", stderr(&out));

    let other = sshd.new_key("other");
    let out = sshd.run(&other, "true");
    assert_eq!(out.status.code(), Some(255), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("Permission denied"),
        "{}",
        stderr(&out)
    );

    sshd.authorize(&other);
    let out = sshd.run(&other, "true");
    assert!(out.status.success(), "ssh failed: {}", stderr(&out));
}

#[test]
fn harness_server_home_is_temp() {
    let sshd = Sshd::start(BASE);
    let out = sshd.run(&sshd.client_key(), "echo $HOME; cd ~ && pwd -P");
    assert!(out.status.success(), "ssh failed: {}", stderr(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines();
    let home = sshd.server_home().canonicalize().unwrap();
    assert_eq!(lines.next(), Some(sshd.server_home().to_str().unwrap()));
    assert_eq!(lines.next(), Some(home.to_str().unwrap()));
    assert!(
        !stderr(&out).contains("Could not chdir to home directory"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn harness_two_servers_at_once() {
    let a = Sshd::start(BASE);
    let b = Sshd::start(BASE);
    assert_ne!(a.port(), b.port());
    assert!(a.run(&a.client_key(), "true").status.success());
    assert!(b.run(&b.client_key(), "true").status.success());
    let cross = b.run(&a.client_key(), "true");
    assert!(!cross.status.success(), "a's key logged in to b");
}

#[test]
fn harness_restart_on_same_port() {
    let mut sshd = Sshd::start(BASE);
    let port = sshd.port();
    sshd.stop();
    let out = sshd.run(&sshd.client_key(), "true");
    assert!(!out.status.success(), "login worked while sshd was stopped");
    sshd.restart();
    assert_eq!(sshd.port(), port);
    let out = sshd.run(&sshd.client_key(), "true");
    assert!(out.status.success(), "ssh failed: {}", stderr(&out));
}

#[test]
fn harness_strict_modes_rejects_group_writable_file() {
    let sshd = Sshd::start(BASE);
    let ak = sshd.authorized_keys();
    fs::set_permissions(&ak, fs::Permissions::from_mode(0o660)).unwrap();
    let out = sshd.run(&sshd.client_key(), "true");
    assert_eq!(out.status.code(), Some(255), "{}", stderr(&out));
    assert!(
        sshd.log().contains("bad ownership or modes"),
        "{}",
        sshd.log()
    );

    fs::set_permissions(&ak, fs::Permissions::from_mode(0o600)).unwrap();
    let out = sshd.run(&sshd.client_key(), "true");
    assert!(out.status.success(), "ssh failed: {}", stderr(&out));
}

#[test]
fn harness_ssh_config_has_no_real_home_paths() {
    let sshd = Sshd::start(BASE);
    let out = sshd
        .ssh()
        .arg("-G")
        .arg("-i")
        .arg(sshd.client_key())
        .arg(sshd.alias())
        .output()
        .unwrap();
    assert!(out.status.success(), "ssh -G failed: {}", stderr(&out));
    let real_home = current_user().home;
    let dir = sshd.dir().to_path_buf();
    let config = String::from_utf8_lossy(&out.stdout);
    for word in config.split_whitespace() {
        assert!(!word.starts_with("~/"), "unexpanded home path: {word}");
        let p = std::path::Path::new(word);
        if p.is_absolute() && !p.starts_with(&dir) {
            assert!(
                !p.starts_with(&real_home),
                "real home path in config: {word}"
            );
        }
    }
    assert!(config.contains(&format!("port {}", sshd.port())));
    assert!(config.contains("globalknownhostsfile /dev/null"));
}

#[test]
fn harness_failed_logins_do_not_block() {
    let sshd = Sshd::start(BASE);
    let wrong = sshd.new_key("wrong");
    for _ in 0..20 {
        assert!(!sshd.run(&wrong, "true").status.success());
    }
    let out = sshd.run(&sshd.client_key(), "true");
    assert!(out.status.success(), "ssh failed: {}", stderr(&out));
    assert!(!sshd.log().contains("penalty"), "{}", sshd.log());
}

#[test]
fn harness_unknown_host_key_is_refused() {
    let sshd = Sshd::start(BASE);
    fs::write(sshd.known_hosts(), "").unwrap();
    let out = sshd.run(&sshd.client_key(), "true");
    assert_eq!(out.status.code(), Some(255));
    assert!(
        stderr(&out).contains("Host key verification failed"),
        "{}",
        stderr(&out)
    );
    assert_eq!(fs::read_to_string(sshd.known_hosts()).unwrap(), "");
}

#[test]
fn dir_chain_check_names_the_bad_dir() {
    let base = tempfile::Builder::new().tempdir_in(BASE).unwrap();
    let bad = base.path().join("open");
    fs::create_dir(&bad).unwrap();
    fs::set_permissions(&bad, fs::Permissions::from_mode(0o777)).unwrap();
    let inner = bad.join("inner");
    fs::create_dir(&inner).unwrap();
    let err = check_dir_chain(&inner, current_user().uid).unwrap_err();
    assert!(err.contains(bad.to_str().unwrap()), "{err}");
    assert!(err.contains("777"), "{err}");
    assert!(check_dir_chain(BASE.as_ref(), current_user().uid).is_ok());
}

#[test]
fn no_sshd_left_after_drop() {
    let sshd = Sshd::start(BASE);
    let dir = sshd.dir().to_path_buf();
    drop(sshd);
    let needle = format!("{}/sshd_config", dir.display());
    for entry in fs::read_dir("/proc").unwrap().flatten() {
        if let Ok(cmdline) = fs::read(entry.path().join("cmdline")) {
            let cmdline = String::from_utf8_lossy(&cmdline).replace('\0', " ");
            assert!(!cmdline.contains(&needle), "stray sshd: {cmdline}");
        }
    }
}
