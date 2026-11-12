//! Check runner against the test sshd and mock forges.

mod common;

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use common::*;
use identity_core::{Fingerprint, PublicKey, parse_public_keys};
use inventory::{LocationKind, NewLocation, Purpose, SshHost, Status, Store, Target};
use providers::{
    CheckOutcome, CheckRunner, GitHub, GitLab, InMemoryTokenSource, NetLog, OpenPgpReader,
    SshServer, Token, TokenKey,
};
use test_support::{Sshd, TempGnupgHome};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BASE: &str = env!("CARGO_TARGET_TMPDIR");

fn ssh_key(private: &Path) -> (Fingerprint, String) {
    let mut p = private.as_os_str().to_owned();
    p.push(".pub");
    let text = fs::read_to_string(p).unwrap();
    match &parse_public_keys(text.as_bytes()).unwrap()[0].key {
        Ok(PublicKey::Ssh(k)) => (k.fingerprint.clone(), k.encoded.clone()),
        other => panic!("{other:?}"),
    }
}

fn add(
    store: &mut Store,
    kind: LocationKind,
    target: &Target,
    key: &Fingerprint,
    purpose: Purpose,
) -> i64 {
    store
        .add(&NewLocation {
            kind,
            target: target.clone(),
            key: key.clone(),
            purpose,
        })
        .unwrap()
        .id()
}

#[tokio::test]
async fn check_all_updates_status() {
    let sshd = Sshd::start(BASE);
    let (fpr, encoded) = ssh_key(&sshd.client_key());
    let other = sshd.new_key("other");
    let (other_fpr, _) = ssh_key(&other);

    // GitHub has the key for auth, not for signing.
    let github = MockServer::start().await;
    let body = serde_json::json!([{ "id": 7, "key": encoded, "title": "test" }]);
    Mock::given(method("GET"))
        .and(path("/user/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&github)
        .await;
    for p in ["/user/ssh_signing_keys", "/user/gpg_keys"] {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&github)
            .await;
    }
    // GitLab refuses the token.
    let gitlab = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).set_body_string(TOKEN))
        .mount(&gitlab)
        .await;

    let gh_target = account("https://github.com");
    let gl_target = account(&gitlab.uri());
    let tokens = InMemoryTokenSource::new();
    tokens.insert(
        TokenKey::for_target(LocationKind::GitHub, &gh_target).unwrap(),
        Token::new(TOKEN),
    );
    tokens.insert(
        TokenKey::for_target(LocationKind::GitLab, &gl_target).unwrap(),
        Token::new(TOKEN),
    );
    let tokens = Arc::new(tokens);
    let gnupg = TempGnupgHome::new();
    let log = NetLog::new();
    let runner = CheckRunner::new()
        .with(Arc::new(
            SshServer::new(log.clone())
                .with_config(sshd.ssh_config())
                .with_known_hosts(sshd.known_hosts())
                .with_home(sshd.client_home())
                .without_agent(),
        ))
        .with(Arc::new(
            GitHub::new(
                tokens.clone(),
                OpenPgpReader::with_home(gnupg.path()),
                log.clone(),
            )
            .with_api_url(github.uri()),
        ))
        .with(Arc::new(GitLab::new(
            tokens,
            OpenPgpReader::with_home(gnupg.path()),
            log.clone(),
        )));

    let mut store = Store::open_in_memory().unwrap();
    let ssh_target = Target::Ssh(SshHost::new(sshd.alias()));
    let vks_target = account("https://keys.openpgp.org");
    let on_server = add(
        &mut store,
        LocationKind::SshServer,
        &ssh_target,
        &fpr,
        Purpose::SshAuth,
    );
    let gh_auth = add(
        &mut store,
        LocationKind::GitHub,
        &gh_target,
        &fpr,
        Purpose::SshAuth,
    );
    let gh_sign = add(
        &mut store,
        LocationKind::GitHub,
        &gh_target,
        &fpr,
        Purpose::SshSigning,
    );
    let gl = add(
        &mut store,
        LocationKind::GitLab,
        &gl_target,
        &fpr,
        Purpose::SshAuth,
    );
    let vks = add(
        &mut store,
        LocationKind::Vks,
        &vks_target,
        &fpr,
        Purpose::SshAuth,
    );
    let not_ours = add(
        &mut store,
        LocationKind::SshServer,
        &ssh_target,
        &other_fpr,
        Purpose::SshAuth,
    );

    let before = SystemTime::now();
    let results = runner
        .check_key(&mut store, &fpr, Some(&sshd.client_key()))
        .await
        .unwrap();
    assert_eq!(results.len(), 5, "{results:?}");
    let vks_result = results.iter().find(|r| r.location == vks).unwrap();
    assert_eq!(vks_result.outcome, CheckOutcome::NoProvider);

    let get = |id| store.get(id).unwrap().unwrap();
    assert_eq!(get(on_server).status, Status::Verified, "{}", log.render());
    assert_eq!(get(gh_auth).status, Status::Verified);
    assert_eq!(get(gh_sign).status, Status::Missing);
    let reason = match get(gl).status {
        Status::Error(r) => r,
        s => panic!("{s:?}"),
    };
    assert!(reason.contains("401"), "{reason}");
    for id in [on_server, gh_auth, gh_sign, gl] {
        let t = get(id).last_checked.expect("last_checked is set");
        assert!(t >= before - std::time::Duration::from_secs(1));
    }
    // No provider, or another key: untouched.
    for id in [vks, not_ours] {
        assert_eq!(get(id).status, Status::Unverified);
        assert_eq!(get(id).last_checked, None);
    }
    for r in &results {
        if let CheckOutcome::Checked(s) = &r.outcome {
            assert_eq!(&get(r.location).status, s);
        }
    }
    assert_no_token(&log, &[reason]);
}
