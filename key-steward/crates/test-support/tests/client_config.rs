//! Several test servers in one client config (M2 T03a).

use std::path::Path;

use test_support::{ClientConfig, Sshd, current_user};

const BASE: &str = env!("CARGO_TARGET_TMPDIR");

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn two_servers_in_one_config() {
    let a = Sshd::start_named(BASE, "alpha");
    let b = Sshd::start_named_with(BASE, "beta", "LogLevel DEBUG1\n");
    assert_eq!((a.alias(), b.alias()), ("alpha", "beta"));
    let cfg = ClientConfig::new(&[&a, &b]);

    let out = cfg.run(&a.client_key(), "alpha", "true");
    assert!(out.status.success(), "alpha: {}", stderr(&out));
    let out = cfg.run(&b.client_key(), "beta", "echo $HOME");
    assert!(out.status.success(), "beta: {}", stderr(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        b.server_home().to_str().unwrap()
    );
    let cross = cfg.run(&a.client_key(), "beta", "true");
    assert!(!cross.status.success(), "a's key logged in to beta");

    // Each server's own config still works with its alias.
    assert!(a.run(&a.client_key(), "true").status.success());
}

#[test]
fn client_config_has_no_real_home_paths() {
    let a = Sshd::start_named(BASE, "alpha");
    let b = Sshd::start_named(BASE, "beta");
    let cfg = ClientConfig::new(&[&a, &b]);
    let real_home = current_user().home;
    for alias in ["alpha", "beta"] {
        let out = cfg.ssh().arg("-G").arg(alias).output().unwrap();
        assert!(out.status.success(), "ssh -G failed: {}", stderr(&out));
        let config = String::from_utf8_lossy(&out.stdout);
        for word in config.split_whitespace() {
            assert!(!word.starts_with("~/"), "unexpanded home path: {word}");
            let p = Path::new(word);
            if p.is_absolute() && !p.starts_with(cfg.dir()) {
                assert!(
                    !p.starts_with(&real_home),
                    "real home path in config: {word}"
                );
            }
        }
        assert!(config.contains(&format!(
            "userknownhostsfile {}",
            cfg.known_hosts().display()
        )));
        assert!(config.contains("globalknownhostsfile /dev/null"));
        assert!(config.contains("batchmode yes"));
        assert!(config.contains("stricthostkeychecking true"));
    }
    let kh = std::fs::read_to_string(cfg.known_hosts()).unwrap();
    assert!(kh.contains(&format!("[127.0.0.1]:{} ", a.port())));
    assert!(kh.contains(&format!("[127.0.0.1]:{} ", b.port())));
}
