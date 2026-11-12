//! GitLab provider against wiremock with the mock forge fixtures.

mod common;

use common::*;
use identity_core::Fingerprint;
use providers::{
    GitLab, LocationKind, NetLog, OpenPgpReader, Provider, ProviderError, Purpose, Target,
    VerifyStatus,
};
use test_support::TempGnupgHome;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn json(body: String) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body, "application/json")
}

/// A self-hosted GitLab under `<server>/gitlab`. Page 1 of the SSH keys
/// sends only `x-next-page`, as GitLab.com may do.
async fn mock_gitlab() -> MockServer {
    let server = MockServer::start().await;
    let get = |p: &str| {
        Mock::given(method("GET"))
            .and(path(format!("/gitlab/api/v4{p}")))
            .and(header("private-token", TOKEN))
    };
    get("/user")
        .respond_with(json(fixture("gitlab/user.json")))
        .mount(&server)
        .await;
    get("/user/keys")
        .and(query_param("page", "2"))
        .respond_with(json(fixture("gitlab/user_keys_page2.json")).insert_header("x-next-page", ""))
        .mount(&server)
        .await;
    get("/user/keys")
        .and(query_param("per_page", "100"))
        .respond_with(json(fixture("gitlab/user_keys.json")).insert_header("x-next-page", "2"))
        .mount(&server)
        .await;
    get("/user/gpg_keys")
        .and(query_param("per_page", "100"))
        .respond_with(json(fixture("gitlab/user_gpg_keys.json")))
        .mount(&server)
        .await;
    server
}

fn gitlab(server: &MockServer, gnupg: &TempGnupgHome, log: &NetLog) -> (GitLab, Target) {
    let target = account(&format!("{}/gitlab/", server.uri()));
    let p = GitLab::new(
        tokens(LocationKind::GitLab, &target),
        OpenPgpReader::with_home(gnupg.path()),
        log.clone(),
    );
    (p, target)
}

#[tokio::test]
async fn gitlab_list_against_mock() {
    let server = mock_gitlab().await;
    let gnupg = TempGnupgHome::new();
    let log = NetLog::new();
    let (p, target) = gitlab(&server, &gnupg, &log);
    assert_eq!(p.kind(), LocationKind::GitLab);
    let keys = p.list(&target).await.unwrap();

    let of = |purpose| -> Vec<Fingerprint> {
        keys.iter()
            .filter(|k| k.purpose == purpose)
            .map(|k| k.fingerprint.clone())
            .collect()
    };
    let page1 = ssh_fprs("gitlab/user_keys.json");
    let page2 = ssh_fprs("gitlab/user_keys_page2.json");
    // Page 1: "auth only", then "signing only". Page 2: both.
    let mut auth = vec![page1[0].clone()];
    auth.extend(page2.clone());
    let mut signing = vec![page1[1].clone()];
    signing.extend(page2);
    assert_eq!(of(Purpose::SshAuth), auth);
    assert_eq!(of(Purpose::SshSigning), signing);
    assert_eq!(
        of(Purpose::OpenPgp),
        vec![openpgp_fpr("gitlab/user_gpg_keys.json")]
    );
    assert_eq!(keys[0].title.as_deref(), Some("auth only"));
    assert_eq!(keys[0].remote_id.as_deref(), Some("1"));

    let entries = log.entries();
    assert_eq!(entries.len(), 4, "{}", log.render());
    assert!(entries[0].action.ends_with("/gitlab/api/v4/user"));
    assert!(
        entries[2]
            .action
            .contains("/gitlab/api/v4/user/keys?per_page=100&page=2")
    );
    assert_no_token(&log, &[]);
}

#[tokio::test]
async fn gitlab_verify_by_fingerprint() {
    let server = mock_gitlab().await;
    let gnupg = TempGnupgHome::new();
    let log = NetLog::new();
    let (p, target) = gitlab(&server, &gnupg, &log);

    let page1 = ssh_fprs("gitlab/user_keys.json");
    let both = ssh_fprs("gitlab/user_keys_page2.json")[0].clone();
    let cases = [
        (page1[0].clone(), Purpose::SshAuth, VerifyStatus::Verified),
        (page1[0].clone(), Purpose::SshSigning, VerifyStatus::Missing),
        (
            page1[1].clone(),
            Purpose::SshSigning,
            VerifyStatus::Verified,
        ),
        (page1[1].clone(), Purpose::SshAuth, VerifyStatus::Missing),
        (both.clone(), Purpose::SshAuth, VerifyStatus::Verified),
        (both, Purpose::SshSigning, VerifyStatus::Verified),
        (
            openpgp_fpr("gitlab/user_gpg_keys.json"),
            Purpose::OpenPgp,
            VerifyStatus::Verified,
        ),
        (
            Fingerprint::OpenPgp("0000000000000000000000000000000000000000".into()),
            Purpose::OpenPgp,
            VerifyStatus::Missing,
        ),
    ];
    for (fpr, purpose, want) in cases {
        let got = p.verify(&target, &key(fpr.clone(), purpose)).await.unwrap();
        assert_eq!(got, want, "{fpr} {purpose:?}");
    }
    assert_no_token(&log, &[]);
}

#[tokio::test]
async fn gitlab_refuses_plain_http_and_ssh_targets() {
    let gnupg = TempGnupgHome::new();
    let log = NetLog::new();
    let target = account("http://gitlab.example.org");
    let p = GitLab::new(
        tokens(LocationKind::GitLab, &target),
        OpenPgpReader::with_home(gnupg.path()),
        log.clone(),
    );
    let err = p.list(&target).await.unwrap_err();
    assert!(err.to_string().contains("https"), "{err}");
    assert_no_token(&log, &[err.to_string()]);

    let ssh = Target::Ssh(providers::SshHost::new("build"));
    let err = p.list(&ssh).await.unwrap_err();
    assert!(matches!(err, ProviderError::WrongTarget { .. }), "{err:?}");
}

#[tokio::test]
async fn gitlab_token_owner_must_be_target_account() {
    let gnupg = TempGnupgHome::new();
    let other = owner_only("/gitlab/api/v4", "username", "someoneelse").await;
    let log = NetLog::new();
    let (p, target) = gitlab(&other, &gnupg, &log);
    let k = key(openpgp_fpr("gitlab/user_gpg_keys.json"), Purpose::OpenPgp);
    assert_owner_mismatch(&p, &target, &log, &k).await;
}
