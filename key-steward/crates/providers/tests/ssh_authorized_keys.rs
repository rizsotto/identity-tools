//! `ssh_server` list, add and remove against the test sshd (FR-6, SPEC 9.1,
//! S-3, S-5, S-6).

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use identity_core::{Fingerprint, PublicKey, SshPublicKey, parse_public_keys};
use providers::remote::ProtocolError;
use providers::{
    AuthorizedKeysError, KeyRef, NetLog, Provider, ProviderError, Purpose, SshHost, SshServer,
    Target, VerifyStatus,
};
use test_support::Sshd;

const BASE: &str = env!("CARGO_TARGET_TMPDIR");

fn public(key: &Path) -> SshPublicKey {
    let mut p = key.as_os_str().to_owned();
    p.push(".pub");
    match &parse_public_keys(&fs::read(p).unwrap()).unwrap()[0].key {
        Ok(PublicKey::Ssh(k)) => k.clone(),
        other => panic!("not an ssh key: {other:?}"),
    }
}

fn fpr(key: &Path) -> Fingerprint {
    public(key).fingerprint
}

fn key_ref(key: &Path) -> KeyRef {
    KeyRef {
        fingerprint: fpr(key),
        purpose: Purpose::SshAuth,
        identity_file: Some(key.to_path_buf()),
    }
}

fn target(sshd: &Sshd) -> Target {
    Target::Ssh(SshHost::new(sshd.alias()))
}

fn provider(sshd: &Sshd, log: &NetLog) -> SshServer {
    SshServer::new(log.clone())
        .with_config(sshd.ssh_config())
        .with_known_hosts(sshd.known_hosts())
        .with_home(sshd.client_home())
        .without_agent()
}

fn write_keys(sshd: &Sshd, content: &[u8]) {
    fs::write(sshd.authorized_keys(), content).unwrap();
    fs::set_permissions(sshd.authorized_keys(), fs::Permissions::from_mode(0o600)).unwrap();
}

/// Backups the apply script left in the server's `~/.ssh`.
fn backups(sshd: &Sshd) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(sshd.server_home().join(".ssh"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("authorized_keys.keysteward-")
        })
        .collect();
    out.sort();
    out
}

/// No key blob of these keys and no file content in the network log.
fn assert_log_clean(log: &NetLog, keys: &[&Path]) {
    let text = log.render();
    for k in keys {
        let blob = public(k).encoded;
        let blob = blob.split_once(' ').unwrap().1;
        assert!(!text.contains(blob), "{text}");
    }
}

fn ak_err(e: ProviderError) -> AuthorizedKeysError {
    match e {
        ProviderError::AuthorizedKeys(e) => e,
        other => panic!("not an authorized_keys error: {other:?}"),
    }
}

#[tokio::test]
async fn list_against_test_sshd() {
    let sshd = Sshd::start(BASE);
    let other = sshd.new_key("other");
    let ca = sshd.new_key("ca");
    let login = sshd.client_key();
    let content = format!(
        "# a comment\n\nrestrict {}\ncert-authority {} ca\n{} other\x07key\r\n",
        public(&login).encoded,
        public(&ca).encoded,
        public(&other).encoded,
    );
    write_keys(&sshd, content.as_bytes());
    let log = NetLog::new();
    let p = provider(&sshd, &log);
    let got = p
        .list_as(&target(&sshd), &key_ref(&login))
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", log.render()));
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(got[0].fingerprint, fpr(&login));
    assert_eq!(got[0].remote_id.as_deref(), Some("3"));
    assert_eq!(got[0].title, None);
    assert_eq!(got[1].fingerprint, fpr(&other));
    assert_eq!(got[1].purpose, Purpose::SshAuth);
    assert_eq!(got[1].remote_id.as_deref(), Some("5"));
    assert_eq!(got[1].title.as_deref(), Some("otherkey"));

    // The trait method logs in with the key from `with_login`.
    let via_trait = provider(&sshd, &log)
        .with_login(key_ref(&login))
        .list(&target(&sshd))
        .await
        .unwrap();
    assert_eq!(via_trait, got);

    let entries = log.entries();
    assert_eq!(entries.len(), 2, "{}", log.render());
    for part in [
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "IdentitiesOnly=yes",
        " -- testsshd sh -c 'eval \"$(dd bs=1 count=",
    ] {
        assert!(
            entries[0].action.contains(part),
            "{part} not in {}",
            entries[0].action
        );
    }
    assert!(
        entries[0]
            .outcome
            .starts_with("exit 0, logged in with SHA256:"),
        "{}",
        entries[0].outcome
    );
    assert_log_clean(&log, &[&login, &other, &ca]);
    assert!(!log.render().contains("a comment"));
}

#[tokio::test]
async fn forced_command_is_refused() {
    let sshd = Sshd::start(BASE);
    let login = sshd.client_key();
    let content = format!("command=\"echo hi\" {}\n", public(&login).encoded);
    write_keys(&sshd, content.as_bytes());
    let log = NetLog::new();
    let err = provider(&sshd, &log)
        .list_as(&target(&sshd), &key_ref(&login))
        .await
        .unwrap_err();
    assert_eq!(
        ak_err(err),
        AuthorizedKeysError::Protocol(ProtocolError::NoMarker),
        "{}",
        log.render()
    );
    assert_eq!(
        fs::read(sshd.authorized_keys()).unwrap(),
        content.as_bytes()
    );
}

#[tokio::test]
async fn symlink_is_refused() {
    let sshd = Sshd::start(BASE);
    let real = sshd.server_home().join(".ssh/real_keys");
    fs::rename(sshd.authorized_keys(), &real).unwrap();
    symlink("real_keys", sshd.authorized_keys()).unwrap();
    let log = NetLog::new();
    let err = provider(&sshd, &log)
        .list_as(&target(&sshd), &key_ref(&sshd.client_key()))
        .await
        .unwrap_err();
    assert_eq!(
        ak_err(err),
        AuthorizedKeysError::Symlink,
        "{}",
        log.render()
    );
    assert!(
        fs::symlink_metadata(sshd.authorized_keys())
            .unwrap()
            .is_symlink()
    );
}

/// The login key is not accepted: the error says so, nothing ran.
#[tokio::test]
async fn list_with_a_key_not_installed_fails_login() {
    let sshd = Sshd::start(BASE);
    let stranger = sshd.new_key("stranger");
    let log = NetLog::new();
    let err = provider(&sshd, &log)
        .list_as(&target(&sshd), &key_ref(&stranger))
        .await
        .unwrap_err();
    assert_eq!(
        ak_err(err),
        AuthorizedKeysError::Login(VerifyStatus::Missing),
        "{}",
        log.render()
    );
    assert!(
        log.entries()[0].outcome.contains("login missing"),
        "{}",
        log.render()
    );
    assert!(backups(&sshd).is_empty());
}
