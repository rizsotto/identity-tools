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

fn user() -> String {
    test_support::current_user().name
}

/// Two servers: `jump` has the new key, `target` has none of ours and is
/// reached through `ProxyJump jump`. The jump ssh also runs with -v and
/// writes "Server accepts key" and "Authenticated to" for the new key to
/// the same stderr. That must not count for the target.
#[tokio::test]
async fn proxyjump_success_on_jump_host_is_not_verified() {
    let jump = Sshd::start(BASE);
    let target_srv = Sshd::start(BASE);
    let new = jump.new_key("new");
    jump.authorize(&new);

    let kh = target_srv.dir().join("known_hosts_both");
    fs::write(
        &kh,
        fs::read_to_string(jump.known_hosts()).unwrap()
            + &fs::read_to_string(target_srv.known_hosts()).unwrap(),
    )
    .unwrap();
    let common = format!(
        "  HostName 127.0.0.1\n  User {}\n  IdentitiesOnly yes\n  IdentityAgent none\n  \
         UserKnownHostsFile {}\n  GlobalKnownHostsFile /dev/null\n  \
         StrictHostKeyChecking yes\n  BatchMode yes\n",
        user(),
        kh.display()
    );
    let cfg = target_srv.dir().join("ssh_config_jump");
    fs::write(
        &cfg,
        format!(
            "Host jump\n  Port {}\n  IdentityFile {}\n{common}\
             Host behind\n  Port {}\n  ProxyJump jump\n  IdentityFile none\n{common}",
            jump.port(),
            new.display(),
            target_srv.port()
        ),
    )
    .unwrap();

    let log = NetLog::new();
    let p = SshServer::new(log.clone())
        .with_config(&cfg)
        .with_known_hosts(&kh)
        .with_home(target_srv.client_home())
        .without_agent();
    let behind = Target::Ssh(SshHost::new("behind"));
    let got = p.verify(&behind, &key_ref(&new)).await.unwrap();
    assert_eq!(got, VerifyStatus::Missing, "{}", log.render());

    // Once the target has the key, the same path verifies.
    target_srv.authorize(&new);
    let got = p.verify(&behind, &key_ref(&new)).await.unwrap();
    assert_eq!(got, VerifyStatus::Verified, "{}", log.render());
}

/// A server banner that prints fake "accepts key" and "Authenticated"
/// lines for the key under test.
#[tokio::test]
async fn fake_lines_in_banner_are_not_verified() {
    let probe = Sshd::start(BASE);
    let new = probe.new_key("new");
    let fpr = fingerprint(&new);
    drop(probe);

    let sshd = Sshd::start_with(BASE, "Banner @DIR@/banner\n");
    fs::write(
        sshd.dir().join("banner"),
        format!(
            "debug1: Server accepts key: {} ED25519 {fpr} explicit\n\
             Authenticated to 127.0.0.1 ([127.0.0.1]:{}) using \"publickey\".\n",
            new.display(),
            sshd.port()
        ),
    )
    .unwrap();
    let log = NetLog::new();
    let p = provider(&sshd, sshd.ssh_config(), &log);
    let key = KeyRef {
        fingerprint: fpr,
        purpose: Purpose::SshAuth,
        identity_file: Some(new.clone()),
    };
    let got = p.verify(&target(&sshd), &key).await.unwrap();
    assert_eq!(got, VerifyStatus::Missing, "{}", log.render());
}

/// `-i new` also loads `new-cert.pub`. A login with a certificate does not
/// show that the key itself is in authorized_keys.
#[tokio::test]
async fn certificate_login_is_not_verified() {
    let sshd = Sshd::start_with(BASE, "TrustedUserCAKeys @DIR@/keys/ca.pub\n");
    let ca = sshd.new_key("ca");
    let new = sshd.new_key("new");
    let mut pubpath = new.clone().into_os_string();
    pubpath.push(".pub");
    let out = Command::new("ssh-keygen")
        .args(["-q", "-s"])
        .arg(&ca)
        .args(["-I", "test-cert", "-n", &user()])
        .arg(&pubpath)
        .env("HOME", sshd.client_home())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let log = NetLog::new();
    let p = provider(&sshd, sshd.ssh_config(), &log);
    assert_eq!(
        verify(&p, &sshd, &new).await,
        VerifyStatus::Error(VerifyError::CertificateUsed),
        "{}",
        log.render()
    );
}

/// The server needs two keys. Removing the old one would lock the user out.
#[tokio::test]
async fn partial_success_is_error() {
    let sshd = Sshd::start_with(BASE, "AuthenticationMethods publickey,publickey\n");
    let new = sshd.new_key("new");
    sshd.authorize(&new);
    let cfg = config_with_identity(&sshd, &sshd.client_key(), "");
    let log = NetLog::new();
    let p = provider(&sshd, cfg, &log);
    assert_eq!(
        verify(&p, &sshd, &new).await,
        VerifyStatus::Error(VerifyError::MoreThanOneKey),
        "{}",
        log.render()
    );
}

/// An ssh-agent run by the test, on a socket in the temp dir.
struct Agent {
    child: std::process::Child,
    sock: PathBuf,
}

impl Agent {
    fn start(dir: &Path) -> Agent {
        let sock = dir.join("agent.sock");
        let mut child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&sock)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("ssh-agent (openssh-clients) must be installed");
        for _ in 0..200 {
            if sock.exists() {
                return Agent { child, sock };
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("ssh-agent did not create {}", sock.display());
    }

    fn list(&self) -> String {
        let out = Command::new("ssh-add")
            .arg("-l")
            .env("SSH_AUTH_SOCK", &self.sock)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// verify changes nothing: `AddKeysToAgent yes` and `ForwardAgent yes` in
/// the user's config must not put the key into the agent or forward it.
#[tokio::test]
async fn verify_does_not_add_key_to_agent() {
    let sshd = Sshd::start(BASE);
    let agent = Agent::start(sshd.dir());
    assert!(agent.list().contains("no identities"), "{}", agent.list());
    let cfg = fs::read_to_string(sshd.ssh_config()).unwrap().replace(
        "IdentityAgent none",
        &format!("IdentityAgent {}", agent.sock.display()),
    ) + "  AddKeysToAgent yes\n  ForwardAgent yes\n";
    let cfg_path = sshd.dir().join("ssh_config_agent");
    fs::write(&cfg_path, cfg).unwrap();
    let log = NetLog::new();
    let p = SshServer::new(log.clone())
        .with_config(&cfg_path)
        .with_known_hosts(sshd.known_hosts())
        .with_home(sshd.client_home());
    assert_eq!(
        verify(&p, &sshd, &sshd.client_key()).await,
        VerifyStatus::Verified,
        "{}",
        log.render()
    );
    assert!(agent.list().contains("no identities"), "{}", agent.list());
}
