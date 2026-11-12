//! `ssh_server` list, add and remove against the test sshd (FR-6, SPEC 9.1,
//! S-3, S-5, S-6).

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use identity_core::{Fingerprint, PublicKey, SshPublicKey, parse_public_keys};
use providers::remote::ProtocolError;
use providers::{
    AddOpts, AuthorizedKeysError, KeyRef, NetLog, OldKeyCheck, Provider, ProviderError, Purpose,
    RemoveOpts, SshHost, SshRemoved, SshServer, Target, VerifyStatus,
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

/// Fills a fixture template (see `tests/authorized_keys.rs`) with keys
/// made for this server.
struct Keys {
    old: PathBuf,
    new: PathBuf,
    other: PathBuf,
    ca: PathBuf,
}

impl Keys {
    fn new(sshd: &Sshd) -> Keys {
        Keys {
            old: sshd.client_key(),
            new: sshd.new_key("new@example.org"),
            other: sshd.new_key("other"),
            ca: sshd.new_key("ca"),
        }
    }

    fn fill(&self, template: &[u8]) -> Vec<u8> {
        let mut s = String::from_utf8(template.to_vec()).unwrap();
        for (name, key) in [
            ("OLD", &self.old),
            ("NEW", &self.new),
            ("OTHER", &self.other),
            ("CA", &self.ca),
        ] {
            s = s.replace(&format!("{{{name}}}"), &public(key).encoded);
        }
        let old = public(&self.old).encoded;
        let (key_type, blob) = old.split_once(' ').unwrap();
        let (b1, b2) = blob.split_at(10);
        s.replace("{OLD_TYPE}", key_type)
            .replace("{OLD_B1}", b1)
            .replace("{OLD_B2}", b2)
            .into_bytes()
    }
}

/// `(name, input, expected output)` for each fixture in `dir`.
fn fixtures(dir: &str, keys: &Keys) -> Vec<(String, Vec<u8>, Option<Vec<u8>>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/authorized-keys")
        .join(dir);
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "in") {
            out.push((
                path.file_stem().unwrap().to_string_lossy().into_owned(),
                keys.fill(&fs::read(&path).unwrap()),
                fs::read(path.with_extension("out"))
                    .ok()
                    .map(|b| keys.fill(&b)),
            ));
        }
    }
    out.sort();
    out
}

fn clear_backups(sshd: &Sshd) {
    for b in backups(sshd) {
        fs::remove_file(b).unwrap();
    }
}

/// Add fixtures where sshd itself stops the login with the old key:
/// every old key line has a forced command, or a `from=` that does not
/// match 127.0.0.1 (then a forced command). Key Steward refuses them.
const ADD_BLOCKED_BY_SSHD: &[&str] = &[
    "command-spaces",
    "from-commas",
    "options-quotes",
    "two-lines",
];

#[tokio::test]
async fn fixtures_end_to_end_against_sshd() {
    let sshd = Sshd::start(BASE);
    let keys = Keys::new(&sshd);
    let log = NetLog::new();
    let p = provider(&sshd, &log);
    let t = target(&sshd);
    let mut written = 0;

    for (name, input, want) in fixtures("add", &keys) {
        write_keys(&sshd, &input);
        clear_backups(&sshd);
        let got = p.add_key(&t, &public(&keys.new), &key_ref(&keys.old)).await;
        let file = fs::read(sshd.authorized_keys()).unwrap();
        match (&want, got) {
            (Some(want), Ok(changed)) if !ADD_BLOCKED_BY_SSHD.contains(&name.as_str()) => {
                assert_eq!(
                    String::from_utf8_lossy(&file),
                    String::from_utf8_lossy(want),
                    "add/{name}"
                );
                assert_eq!(changed, want != &input, "add/{name}");
                let b = backups(&sshd);
                assert_eq!(b.len(), usize::from(changed), "add/{name}");
                if changed {
                    assert_eq!(fs::read(&b[0]).unwrap(), input, "add/{name} backup");
                    written += 1;
                }
            }
            (_, Err(e)) if want.is_none() || ADD_BLOCKED_BY_SSHD.contains(&name.as_str()) => {
                let e = ak_err(e);
                assert!(
                    matches!(
                        e,
                        AuthorizedKeysError::Login(VerifyStatus::Missing)
                            | AuthorizedKeysError::Protocol(ProtocolError::NoMarker)
                    ),
                    "add/{name}: {e:?}"
                );
                assert_eq!(file, input, "add/{name} changed");
                assert!(backups(&sshd).is_empty(), "add/{name}");
            }
            (_, got) => panic!("add/{name}: {got:?}\n{}", log.render()),
        }
    }

    for (name, input, want) in fixtures("remove", &keys) {
        write_keys(&sshd, &input);
        clear_backups(&sshd);
        let got = p.remove_key(&t, &fpr(&keys.old), &key_ref(&keys.new)).await;
        let file = fs::read(sshd.authorized_keys()).unwrap();
        match (&want, got) {
            (Some(want), Ok(removed)) => {
                assert_eq!(
                    String::from_utf8_lossy(&file),
                    String::from_utf8_lossy(want),
                    "remove/{name}"
                );
                assert_eq!(removed.changed, want != &input, "remove/{name}");
                let pure = providers::authorized_keys::AuthorizedKeys::parse(&input)
                    .unwrap()
                    .remove(&fpr(&keys.old), &fpr(&keys.new))
                    .unwrap();
                assert_eq!(
                    removed.ca_lines_with_old_key, pure.ca_lines_with_old_key,
                    "remove/{name}"
                );
                if name == "mixed" {
                    assert_eq!(removed.ca_lines_with_old_key, [5]);
                }
                assert_eq!(
                    backups(&sshd).len(),
                    usize::from(removed.changed),
                    "remove/{name}"
                );
                written += usize::from(removed.changed);
            }
            (None, Err(e)) => {
                // The new key has no line sshd accepts, so it cannot log in.
                assert_eq!(
                    ak_err(e),
                    AuthorizedKeysError::Login(VerifyStatus::Missing),
                    "remove/{name}"
                );
                assert_eq!(file, input, "remove/{name} changed");
                assert!(backups(&sshd).is_empty(), "remove/{name}");
            }
            (_, got) => panic!("remove/{name}: {got:?}\n{}", log.render()),
        }
    }
    assert!(written >= 14, "only {written} fixtures written");
    assert_log_clean(&log, &[&keys.old, &keys.new, &keys.other, &keys.ca]);
}

/// A wrapper around `ssh` that appends a line to the server file right
/// before the apply script runs, like another tool editing it.
fn ssh_that_edits_before_apply(sshd: &Sshd) -> PathBuf {
    let path = sshd.dir().join("ssh-wrapper");
    let script = format!(
        "#!/bin/sh\ncase \"$*\" in *\"count={} \"*) printf '# changed\\n' >> '{}' ;; esac\nexec ssh \"$@\"\n",
        providers::remote::APPLY.body.len(),
        sshd.authorized_keys().display()
    );
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[tokio::test]
async fn concurrent_change_writes_nothing() {
    let sshd = Sshd::start(BASE);
    let new = sshd.new_key("new");
    let before = fs::read(sshd.authorized_keys()).unwrap();
    let log = NetLog::new();
    let p = provider(&sshd, &log).with_program(ssh_that_edits_before_apply(&sshd));
    let err = p
        .add_key(&target(&sshd), &public(&new), &key_ref(&sshd.client_key()))
        .await
        .unwrap_err();
    assert_eq!(
        ak_err(err),
        AuthorizedKeysError::Changed,
        "{}",
        log.render()
    );
    let mut want = before;
    want.extend_from_slice(b"# changed\n");
    assert_eq!(fs::read(sshd.authorized_keys()).unwrap(), want);
    assert!(backups(&sshd).is_empty());
    let left: Vec<_> = fs::read_dir(sshd.server_home().join(".ssh"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, ["authorized_keys"], "temp file left behind");
}

#[tokio::test]
async fn remove_logs_in_with_new_key() {
    let sshd = Sshd::start(BASE);
    let old = sshd.client_key();
    let new = sshd.new_key("new");
    let log = NetLog::new();
    let p = provider(&sshd, &log);
    let t = target(&sshd);

    // The new key's line runs a forced command: its login cannot run the
    // script, so the old key stays (S-3).
    let forced = format!(
        "{}\ncommand=\"echo hi\" {}\n",
        public(&old).encoded,
        public(&new).encoded
    );
    write_keys(&sshd, forced.as_bytes());
    let err = p
        .remove_key(&t, &fpr(&old), &key_ref(&new))
        .await
        .unwrap_err();
    assert_eq!(
        ak_err(err),
        AuthorizedKeysError::Protocol(ProtocolError::NoMarker)
    );
    assert_eq!(fs::read(sshd.authorized_keys()).unwrap(), forced.as_bytes());

    // The new key is not installed: the login fails, even though the old
    // key would log in.
    let only_old = format!("{}\n", public(&old).encoded);
    write_keys(&sshd, only_old.as_bytes());
    let err = p
        .remove_key(&t, &fpr(&old), &key_ref(&new))
        .await
        .unwrap_err();
    assert_eq!(
        ak_err(err),
        AuthorizedKeysError::Login(VerifyStatus::Missing)
    );
    assert_eq!(
        fs::read(sshd.authorized_keys()).unwrap(),
        only_old.as_bytes()
    );

    // Both installed: the removal logs in with the new key only.
    sshd.authorize(&new);
    let log_start = sshd.log().len();
    assert_eq!(
        p.check_old_key(&t, &key_ref(&old)).await.unwrap(),
        OldKeyCheck::StillAccepted
    );
    let removed = p
        .remove_key(&t, &fpr(&old), &key_ref(&new))
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", log.render()));
    assert_eq!(
        removed,
        SshRemoved {
            changed: true,
            ca_lines_with_old_key: vec![]
        }
    );
    assert_eq!(
        fs::read(sshd.authorized_keys()).unwrap(),
        fs::read(new.with_extension("pub")).unwrap()
    );
    let server_log = sshd.log()[log_start..].to_string();
    let accepted: Vec<&str> = server_log
        .lines()
        .filter(|l| l.contains("Accepted publickey"))
        .collect();
    // One login for the check of the old key, two (read, apply) with the new.
    assert_eq!(accepted.len(), 3, "{server_log}");
    assert!(accepted[0].contains(&fpr(&old).to_string()), "{server_log}");
    for l in &accepted[1..] {
        assert!(l.contains(&fpr(&new).to_string()), "{server_log}");
    }

    // The negative check after removal: the old key no longer logs in.
    assert_eq!(
        p.check_old_key(&t, &key_ref(&old)).await.unwrap(),
        OldKeyCheck::Refused
    );

    // Through the trait, a second run finds nothing to do.
    p.remove(
        &t,
        &fpr(&old),
        &RemoveOpts {
            purpose: Purpose::SshAuth,
            keep: Some(key_ref(&new)),
        },
    )
    .await
    .unwrap();
    assert_eq!(backups(&sshd).len(), 1);
    assert_log_clean(&log, &[&old, &new]);
}

#[tokio::test]
async fn strict_modes_accepts_result() {
    use std::os::unix::fs::MetadataExt;
    let sshd = Sshd::start(BASE);
    let old = sshd.client_key();
    let new = sshd.new_key("new");
    let before = fs::read(sshd.authorized_keys()).unwrap();
    fs::set_permissions(sshd.authorized_keys(), fs::Permissions::from_mode(0o644)).unwrap();
    let log = NetLog::new();
    let p = provider(&sshd, &log);
    let t = target(&sshd);
    assert_eq!(
        p.verify(&t, &key_ref(&new)).await.unwrap(),
        VerifyStatus::Missing
    );

    p.add(
        &t,
        &PublicKey::Ssh(public(&new)),
        &AddOpts {
            purpose: Purpose::SshAuth,
            title: None,
            like: Some(key_ref(&old)),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("{e}\n{}", log.render()));

    let mode = |p: &Path| fs::metadata(p).unwrap().mode() & 0o777;
    assert_eq!(mode(&sshd.authorized_keys()), 0o600);
    assert_eq!(mode(&sshd.server_home().join(".ssh")), 0o700);
    let b = backups(&sshd);
    assert_eq!(b.len(), 1);
    assert_eq!(mode(&b[0]), 0o600);
    assert_eq!(fs::read(&b[0]).unwrap(), before);
    // sshd runs with StrictModes yes and accepts the new file.
    assert_eq!(
        p.verify(&t, &key_ref(&new)).await.unwrap(),
        VerifyStatus::Verified
    );
    assert_eq!(
        p.verify(&t, &key_ref(&old)).await.unwrap(),
        VerifyStatus::Verified
    );
}

#[tokio::test]
async fn add_and_remove_need_the_right_options() {
    let sshd = Sshd::start(BASE);
    let new = sshd.new_key("new");
    let p = provider(&sshd, &NetLog::new());
    let t = target(&sshd);
    let add = |purpose, like| AddOpts {
        purpose,
        title: None,
        like,
    };
    let key = PublicKey::Ssh(public(&new));
    let e = p
        .add(&t, &key, &add(Purpose::SshAuth, None))
        .await
        .unwrap_err();
    assert_eq!(ak_err(e), AuthorizedKeysError::NoLoginKey);
    let e = p
        .add(
            &t,
            &key,
            &add(Purpose::SshSigning, Some(key_ref(&sshd.client_key()))),
        )
        .await
        .unwrap_err();
    assert!(matches!(ak_err(e), AuthorizedKeysError::Unsupported(_)));
    let e = p
        .remove(
            &t,
            &fpr(&sshd.client_key()),
            &RemoveOpts {
                purpose: Purpose::SshAuth,
                keep: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(ak_err(e), AuthorizedKeysError::NoLoginKey);
}

/// The apply script's `done` line names another checksum than the content
/// sent (here forged by an ssh wrapper): an error, not success.
#[tokio::test]
async fn apply_answer_must_match_content_sent() {
    let sshd = Sshd::start(BASE);
    let new = sshd.new_key("new");
    let wrapper = sshd.dir().join("ssh-wrapper");
    let script = format!(
        "#!/bin/sh\ncase \"$*\" in *\"count={} \"*) ssh \"$@\" | sed 's/^done [0-9]*/done 1/'; exit ;; esac\nexec ssh \"$@\"\n",
        providers::remote::APPLY.body.len(),
    );
    fs::write(&wrapper, script).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let log = NetLog::new();
    let err = provider(&sshd, &log)
        .with_program(wrapper)
        .add_key(&target(&sshd), &public(&new), &key_ref(&sshd.client_key()))
        .await
        .unwrap_err();
    assert_eq!(
        ak_err(err),
        AuthorizedKeysError::NotConfirmed,
        "{}",
        log.render()
    );
}
