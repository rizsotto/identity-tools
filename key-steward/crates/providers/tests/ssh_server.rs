//! `ssh_server` verify against the test sshd (FR-3, S-3, S-5).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use identity_core::{Fingerprint, PublicKey, parse_public_keys};
use providers::{
    KeyRef, LocationKind, NetLog, Provider, ProviderError, Purpose, SshHost, SshServer, Target,
    VerifyError, VerifyStatus,
};
use test_support::Sshd;

const BASE: &str = env!("CARGO_TARGET_TMPDIR");

fn fingerprint(key: &Path) -> Fingerprint {
    let mut pubpath = key.as_os_str().to_owned();
    pubpath.push(".pub");
    let parsed = parse_public_keys(&fs::read(pubpath).unwrap()).unwrap();
    match &parsed[0].key {
        Ok(PublicKey::Ssh(k)) => k.fingerprint.clone(),
        other => panic!("not an ssh key: {other:?}"),
    }
}

fn key_ref(key: &Path) -> KeyRef {
    KeyRef {
        fingerprint: fingerprint(key),
        purpose: Purpose::SshAuth,
        identity_file: Some(key.to_path_buf()),
    }
}

fn target(sshd: &Sshd) -> Target {
    Target::Ssh(SshHost::new(sshd.alias()))
}

/// The provider as tests must run it: the harness config and known_hosts,
/// a temp HOME and no agent.
fn provider(sshd: &Sshd, config: PathBuf, log: &NetLog) -> SshServer {
    SshServer::new(log.clone())
        .with_config(config)
        .with_known_hosts(sshd.known_hosts())
        .with_home(sshd.client_home())
        .without_agent()
}

/// A copy of the harness config whose host also has `IdentityFile <old>`,
/// like a user config that names the old key.
fn config_with_identity(sshd: &Sshd, old: &Path, extra: &str) -> PathBuf {
    let mut cfg = fs::read_to_string(sshd.ssh_config()).unwrap();
    cfg.push_str(&format!("  IdentityFile {}\n{extra}", old.display()));
    let path = sshd.dir().join("ssh_config_with_old_key");
    fs::write(&path, cfg).unwrap();
    path
}

async fn verify(p: &SshServer, sshd: &Sshd, key: &Path) -> VerifyStatus {
    p.verify(&target(sshd), &key_ref(key)).await.unwrap()
}

#[tokio::test]
async fn verify_ok_against_test_sshd() {
    let sshd = Sshd::start(BASE);
    let log = NetLog::new();
    let p = provider(&sshd, sshd.ssh_config(), &log);
    assert_eq!(
        verify(&p, &sshd, &sshd.client_key()).await,
        VerifyStatus::Verified,
        "{}",
        log.render()
    );

    let entries = log.entries();
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.kind, LocationKind::SshServer);
    assert_eq!(e.target, sshd.alias());
    for part in [
        "ssh ",
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "ConnectTimeout=10",
        "StrictHostKeyChecking=yes",
        sshd.client_key().to_str().unwrap(),
    ] {
        assert!(e.action.contains(part), "{part} not in {}", e.action);
    }
    assert!(e.outcome.contains("verified"), "{}", e.outcome);
}

#[tokio::test]
async fn verify_missing_key() {
    let sshd = Sshd::start(BASE);
    let log = NetLog::new();
    let p = provider(&sshd, sshd.ssh_config(), &log);
    let new = sshd.new_key("new");
    assert_eq!(verify(&p, &sshd, &new).await, VerifyStatus::Missing);
    assert!(
        log.entries()[0].outcome.contains("missing"),
        "{}",
        log.render()
    );

    sshd.authorize(&new);
    assert_eq!(verify(&p, &sshd, &new).await, VerifyStatus::Verified);
}

/// S-3: `-i` adds to the config's IdentityFile list. The old key in the
/// config logs in and ssh exits 0, but the key under test is not installed.
#[tokio::test]
async fn verify_missing_key_with_second_valid_key_in_config() {
    let sshd = Sshd::start(BASE);
    let log = NetLog::new();
    let cfg = config_with_identity(&sshd, &sshd.client_key(), "");
    let new = sshd.new_key("new");

    // The trap is real: plain ssh with this config logs in.
    let out = Command::new("ssh")
        .arg("-F")
        .arg(&cfg)
        .env("HOME", sshd.client_home())
        .env_remove("SSH_AUTH_SOCK")
        .stdin(Stdio::null())
        .arg("-i")
        .arg(&new)
        .args([sshd.alias(), "true"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let p = provider(&sshd, cfg, &log);
    assert_eq!(
        verify(&p, &sshd, &new).await,
        VerifyStatus::Missing,
        "{}",
        log.render()
    );

    sshd.authorize(&new);
    assert_eq!(verify(&p, &sshd, &new).await, VerifyStatus::Verified);
}

/// The fingerprint check must work whatever the user's config says about
/// log level and fingerprint format.
#[tokio::test]
async fn verify_ignores_config_log_level_and_fingerprint_hash() {
    let sshd = Sshd::start(BASE);
    let log = NetLog::new();
    let cfg = config_with_identity(
        &sshd,
        &sshd.new_key("unused"),
        "  LogLevel QUIET\n  FingerprintHash md5\n",
    );
    let p = provider(&sshd, cfg, &log);
    assert_eq!(
        verify(&p, &sshd, &sshd.client_key()).await,
        VerifyStatus::Verified,
        "{}",
        log.render()
    );
}

/// The new key is installed but needs a passphrase and no agent holds it.
/// ssh then logs in with the old key from the config. That is not a
/// verified new key.
#[tokio::test]
async fn verify_encrypted_key_without_agent_is_not_verified() {
    let sshd = Sshd::start(BASE);
    let log = NetLog::new();
    let enc = sshd.dir().join("keys/encrypted");
    let out = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "fake-passphrase",
            "-C",
            "enc",
            "-f",
        ])
        .arg(&enc)
        .env("HOME", sshd.client_home())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success());
    sshd.authorize(&enc);
    let cfg = config_with_identity(&sshd, &sshd.client_key(), "");
    let p = provider(&sshd, cfg, &log);
    assert_eq!(
        verify(&p, &sshd, &enc).await,
        VerifyStatus::Error(VerifyError::KeyNotUsable),
        "{}",
        log.render()
    );
}

#[tokio::test]
async fn unknown_host_key_is_error() {
    let sshd = Sshd::start(BASE);
    let log = NetLog::new();
    let empty = sshd.dir().join("known_hosts_empty");
    fs::write(&empty, "").unwrap();
    let p = provider(&sshd, sshd.ssh_config(), &log).with_known_hosts(empty.clone());
    assert_eq!(
        verify(&p, &sshd, &sshd.client_key()).await,
        VerifyStatus::Error(VerifyError::UnknownHostKey),
        "{}",
        log.render()
    );
    // Never accepted: the known_hosts file is still empty.
    assert_eq!(fs::read_to_string(&empty).unwrap(), "");
    assert!(
        log.entries()[0].outcome.contains("error"),
        "{}",
        log.render()
    );
}

#[tokio::test]
async fn changed_host_key_is_error() {
    let sshd = Sshd::start(BASE);
    let log = NetLog::new();
    let other = sshd.new_key("not-the-host-key");
    let mut pubpath = other.into_os_string();
    pubpath.push(".pub");
    let line = fs::read_to_string(&pubpath).unwrap();
    let mut f = line.split_whitespace();
    let wrong = sshd.dir().join("known_hosts_wrong");
    fs::write(
        &wrong,
        format!(
            "[127.0.0.1]:{} {} {}\n",
            sshd.port(),
            f.next().unwrap(),
            f.next().unwrap()
        ),
    )
    .unwrap();
    let p = provider(&sshd, sshd.ssh_config(), &log).with_known_hosts(wrong);
    assert_eq!(
        verify(&p, &sshd, &sshd.client_key()).await,
        VerifyStatus::Error(VerifyError::HostKeyChanged),
        "{}",
        log.render()
    );
}

#[tokio::test]
async fn stopped_server_is_unreachable() {
    let mut sshd = Sshd::start(BASE);
    let log = NetLog::new();
    let p = provider(&sshd, sshd.ssh_config(), &log);
    sshd.stop();
    let got = verify(&p, &sshd, &sshd.client_key()).await;
    assert!(
        matches!(got, VerifyStatus::Error(VerifyError::Unreachable(_))),
        "{got:?}\n{}",
        log.render()
    );
}

#[tokio::test]
async fn add_list_remove_are_not_yet() {
    let sshd = Sshd::start(BASE);
    let p = provider(&sshd, sshd.ssh_config(), &NetLog::new());
    let t = target(&sshd);
    assert!(matches!(p.list(&t).await, Err(ProviderError::NotYet(_))));
    let fpr = fingerprint(&sshd.client_key());
    assert!(matches!(
        p.remove(&t, &fpr).await,
        Err(ProviderError::NotYet(_))
    ));
    let account = Target::Account {
        base_url: "https://example.invalid".into(),
        account: "me".into(),
    };
    assert!(matches!(
        p.verify(&account, &key_ref(&sshd.client_key())).await,
        Err(ProviderError::WrongTarget { .. })
    ));
}
