//! `ssh_server` verify against the test sshd (FR-3, S-3, S-5).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use identity_core::{Fingerprint, PublicKey, parse_public_keys};
use providers::{
    KeyRef, LocationKind, NetLog, Provider, ProviderError, Purpose, RemoveOpts, SshHost, SshServer,
    Target, VerifyError, VerifyStatus,
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
        " -E ",
        " -- testsshd true",
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
        p.remove(
            &t,
            &fpr,
            &RemoveOpts {
                purpose: Purpose::SshAuth,
                keep: None,
            }
        )
        .await,
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

/// `ssh -i new` also loads `new-cert.pub`, and a config can name a
/// `CertificateFile`. A certificate login does not show that the key itself
/// is in authorized_keys, so neither may count.
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
        VerifyStatus::Missing,
        "{}",
        log.render()
    );
    let mut cert = new.clone().into_os_string();
    cert.push("-cert.pub");
    let cfg = config_with_identity(
        &sshd,
        &sshd.client_key(),
        &format!("  CertificateFile {}\n", PathBuf::from(cert).display()),
    );
    let p = provider(&sshd, cfg, &log);
    assert_eq!(
        verify(&p, &sshd, &new).await,
        VerifyStatus::Missing,
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

fn keygen(dir: &Path, name: &str, args: &[&str], home: &Path) -> PathBuf {
    let path = dir.join(name);
    let out = Command::new("ssh-keygen")
        .args(["-q", "-C", name])
        .args(args)
        .arg("-f")
        .arg(&path)
        .env("HOME", home)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    path
}

/// An old RSA key in PEM format with no `.pub` next to it. ssh can only
/// use it as "Trying private key", with no "Server accepts key" line.
fn pem_key_without_pub(sshd: &Sshd) -> PathBuf {
    let pem = keygen(
        &sshd.dir().join("keys"),
        "oldpem",
        &["-t", "rsa", "-b", "2048", "-m", "PEM", "-N", ""],
        &sshd.client_home(),
    );
    sshd.authorize(&pem);
    let mut public = pem.clone().into_os_string();
    public.push(".pub");
    fs::remove_file(public).unwrap();
    pem
}

/// Re-review: the new key's `.pub` does not match its private file. The
/// server accepts the public half, ssh cannot sign, and before the fix the
/// PEM key from the config logged in after it.
#[tokio::test]
async fn mismatched_pub_with_pem_key_in_config_is_not_verified() {
    let sshd = Sshd::start(BASE);
    let pem = pem_key_without_pub(&sshd);
    let new = sshd.new_key("new");
    let stale = sshd.new_key("stale");
    sshd.authorize(&stale);
    let mut stale_pub = stale.into_os_string();
    stale_pub.push(".pub");
    let mut new_pub = new.clone().into_os_string();
    new_pub.push(".pub");
    fs::copy(&stale_pub, &new_pub).unwrap();

    let cfg = config_with_identity(&sshd, &pem, "");
    let log = NetLog::new();
    let p = provider(&sshd, cfg, &log);
    let got = verify(&p, &sshd, &new).await;
    assert_eq!(
        got,
        VerifyStatus::Error(VerifyError::KeyNotUsable),
        "{}",
        log.render()
    );
}

/// Re-review: an encrypted new key (no agent) is accepted but cannot sign;
/// the PEM key from the config must not log in after it.
#[tokio::test]
async fn encrypted_key_with_pem_key_in_config_is_not_verified() {
    let sshd = Sshd::start(BASE);
    let pem = pem_key_without_pub(&sshd);
    let enc = keygen(
        &sshd.dir().join("keys"),
        "newenc",
        &["-t", "ed25519", "-N", "fake-passphrase"],
        &sshd.client_home(),
    );
    sshd.authorize(&enc);
    let cfg = config_with_identity(&sshd, &pem, "");
    let log = NetLog::new();
    let p = provider(&sshd, cfg, &log);
    assert_eq!(
        verify(&p, &sshd, &enc).await,
        VerifyStatus::Error(VerifyError::KeyNotUsable),
        "{}",
        log.render()
    );
}

/// Host block lines for a test sshd reached as `name`.
fn host_block(name: &str, sshd: &Sshd, kh: &Path, extra: &str) -> String {
    format!(
        "Host {name}\n  HostName 127.0.0.1\n  Port {}\n  User {}\n  IdentitiesOnly yes\n  \
         IdentityAgent none\n  UserKnownHostsFile {}\n  GlobalKnownHostsFile /dev/null\n  \
         StrictHostKeyChecking yes\n  BatchMode yes\n{extra}",
        sshd.port(),
        user(),
        kh.display()
    )
}

fn known_hosts_of(servers: &[&Sshd], path: &Path) {
    let all: String = servers
        .iter()
        .map(|s| fs::read_to_string(s.known_hosts()).unwrap())
        .collect();
    fs::write(path, all).unwrap();
}

/// Two jump hosts: `hop1` takes the new key, `hop2` needs the old key and
/// is reached through `hop1`, the target has only the old key. The new key
/// is not on the target, so the result must be `Missing`.
#[tokio::test]
async fn two_hop_proxyjump_is_not_verified() {
    let hop1 = Sshd::start(BASE);
    let hop2 = Sshd::start(BASE);
    let tgt = Sshd::start(BASE);
    let new = hop1.new_key("new");
    hop1.authorize(&new);
    let old = tgt.client_key();
    hop2.authorize(&old);

    let kh = tgt.dir().join("known_hosts_all");
    known_hosts_of(&[&hop1, &hop2, &tgt], &kh);
    let cfg = tgt.dir().join("ssh_config_hops");
    fs::write(
        &cfg,
        host_block(
            "hop1",
            &hop1,
            &kh,
            &format!("  IdentityFile {}\n", new.display()),
        ) + &host_block(
            "hop2",
            &hop2,
            &kh,
            &format!("  IdentityFile {}\n", old.display()),
        ) + &host_block(
            "far",
            &tgt,
            &kh,
            &format!("  IdentityFile {}\n  ProxyJump hop1,hop2\n", old.display()),
        ),
    )
    .unwrap();
    let log = NetLog::new();
    let p = SshServer::new(log.clone())
        .with_config(&cfg)
        .with_home(tgt.client_home())
        .without_agent();
    let far = Target::Ssh(SshHost::new("far"));
    let got = p.verify(&far, &key_ref(&new)).await.unwrap();
    assert_eq!(got, VerifyStatus::Missing, "{}", log.render());

    tgt.authorize(&new);
    let got = p.verify(&far, &key_ref(&new)).await.unwrap();
    assert_eq!(got, VerifyStatus::Verified, "{}", log.render());
}

/// The jump ssh gets the safety options too: its `AddKeysToAgent yes` must
/// not add a key, and its `StrictHostKeyChecking accept-new` must not write
/// to known_hosts.
#[tokio::test]
async fn jump_host_gets_safe_options() {
    let jump = Sshd::start(BASE);
    let tgt = Sshd::start(BASE);
    let agent = Agent::start(jump.dir());
    let jkey = jump.client_key();
    let kh = tgt.dir().join("known_hosts_all");
    known_hosts_of(&[&jump, &tgt], &kh);
    let jump_extra = format!(
        "  IdentityFile {}\n  AddKeysToAgent yes\n  ForwardAgent yes\n",
        jkey.display()
    );
    let cfg = tgt.dir().join("ssh_config_jump_opts");
    fs::write(
        &cfg,
        host_block("jmp", &jump, &kh, &jump_extra).replace(
            "IdentityAgent none",
            &format!("IdentityAgent {}", agent.sock.display()),
        ) + &host_block("far", &tgt, &kh, "  ProxyJump jmp\n"),
    )
    .unwrap();
    let log = NetLog::new();
    let p = SshServer::new(log.clone())
        .with_config(&cfg)
        .with_home(tgt.client_home());
    let far = Target::Ssh(SshHost::new("far"));
    let got = p.verify(&far, &key_ref(&tgt.client_key())).await.unwrap();
    assert_eq!(got, VerifyStatus::Verified, "{}", log.render());
    assert!(agent.list().contains("no identities"), "{}", agent.list());

    // Unknown jump host key with accept-new: refused, nothing written.
    let empty = tgt.dir().join("known_hosts_jump_empty");
    fs::write(&empty, "").unwrap();
    let cfg2 = tgt.dir().join("ssh_config_accept_new");
    fs::write(
        &cfg2,
        host_block("jmp", &jump, &empty, &jump_extra).replace(
            "StrictHostKeyChecking yes",
            "StrictHostKeyChecking accept-new",
        ) + &host_block("far", &tgt, &kh, "  ProxyJump jmp\n"),
    )
    .unwrap();
    let p = SshServer::new(log.clone())
        .with_config(&cfg2)
        .with_home(tgt.client_home())
        .without_agent();
    let got = p.verify(&far, &key_ref(&tgt.client_key())).await.unwrap();
    assert!(
        matches!(&got, VerifyStatus::Error(VerifyError::UnknownJumpHostKey(h)) if h.contains(&jump.port().to_string())),
        "{got:?}\n{}",
        log.render()
    );
    assert_eq!(fs::read_to_string(&empty).unwrap(), "");
}

#[tokio::test]
async fn match_exec_needs_consent() {
    let sshd = Sshd::start(BASE);
    let marker = sshd.dir().join("EXEC_RAN");
    let cfg = sshd.dir().join("ssh_config_exec");
    fs::write(
        &cfg,
        fs::read_to_string(sshd.ssh_config()).unwrap()
            + &format!("Match exec=\"touch {}\"\n  User nobody\n", marker.display()),
    )
    .unwrap();
    let log = NetLog::new();
    let p = provider(&sshd, cfg.clone(), &log);
    let err = p
        .verify(&target(&sshd), &key_ref(&sshd.client_key()))
        .await
        .unwrap_err();
    assert!(
        matches!(err, ProviderError::CommandsNeedConsent(_)),
        "{err}"
    );
    assert!(!marker.exists());

    let p = provider(&sshd, cfg, &log).with_allow_commands(true);
    let _ = p
        .verify(&target(&sshd), &key_ref(&sshd.client_key()))
        .await
        .unwrap();
    assert!(marker.exists());
}

/// A user ProxyCommand must not get the `-E` log file as an open fd.
#[tokio::test]
async fn proxy_command_does_not_inherit_the_log() {
    let sshd = Sshd::start(BASE);
    let fds = sshd.dir().join("proxy_fds");
    let cfg = config_with_identity(
        &sshd,
        &sshd.new_key("unused"),
        &format!(
            "  ProxyCommand sh -c 'ls /proc/$$/fd > {}; exec /usr/sbin/sshd -i -f {}'\n",
            fds.display(),
            sshd.dir().join("sshd_config").display()
        ),
    );
    let log = NetLog::new();
    let p = provider(&sshd, cfg, &log);
    assert_eq!(
        verify(&p, &sshd, &sshd.client_key()).await,
        VerifyStatus::Verified,
        "{}",
        log.render()
    );
    let listed = fs::read_to_string(&fds).unwrap();
    let open: Vec<&str> = listed.split_whitespace().collect();
    assert_eq!(open, ["0", "1", "2"], "{listed}");
}

/// A non-loopback IPv4 address of this machine and a name for it: the
/// container's own host name, which Docker and Podman put in /etc/hosts.
/// ssh skips the CheckHostIP work for loopback addresses.
fn own_name_and_ip() -> (String, std::net::Ipv4Addr) {
    use std::net::ToSocketAddrs;
    let name = fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();
    let ip = (name.as_str(), 0)
        .to_socket_addrs()
        .ok()
        .into_iter()
        .flatten()
        .find_map(|a| match a.ip() {
            std::net::IpAddr::V4(ip) if !ip.is_loopback() => Some(ip),
            _ => None,
        });
    match ip {
        Some(ip) => (name, ip),
        None => panic!(
            "this test needs the host name in /etc/hostname ({name:?}) to resolve to a \
             non-loopback IPv4 address, as in the devcontainer"
        ),
    }
}

/// `CheckHostIP yes` in the user's config would add `[IP]:port` to
/// known_hosts when the host is reached by name. The check is read-only.
#[tokio::test]
async fn check_host_ip_does_not_write_known_hosts() {
    let (name, ip) = own_name_and_ip();
    let sshd = Sshd::start_with(BASE, &format!("ListenAddress {ip}:@PORT@\n"));
    let hostpub = fs::read_to_string(sshd.dir().join("hostkey.pub")).unwrap();
    let mut f = hostpub.split_whitespace();
    let kh = sshd.dir().join("known_hosts_by_name");
    let before = format!(
        "[{name}]:{} {} {}\n",
        sshd.port(),
        f.next().unwrap(),
        f.next().unwrap()
    );
    fs::write(&kh, &before).unwrap();
    let cfg = sshd.dir().join("ssh_config_checkhostip");
    fs::write(
        &cfg,
        host_block("byname", &sshd, &kh, "  CheckHostIP yes\n")
            .replace("HostName 127.0.0.1", &format!("HostName {name}")),
    )
    .unwrap();
    let log = NetLog::new();
    let p = SshServer::new(log.clone())
        .with_config(&cfg)
        .with_home(sshd.client_home())
        .without_agent();
    let t = Target::Ssh(SshHost::new("byname"));
    let got = p.verify(&t, &key_ref(&sshd.client_key())).await.unwrap();
    assert_eq!(got, VerifyStatus::Verified, "{}", log.render());
    assert_eq!(fs::read_to_string(&kh).unwrap(), before);
}
