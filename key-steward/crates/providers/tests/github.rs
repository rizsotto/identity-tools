//! GitHub provider against wiremock with the mock forge fixtures.

mod common;

use std::sync::Arc;

use common::*;
use identity_core::Fingerprint;
use providers::{
    GitHub, InMemoryTokenSource, LocationKind, NetLog, OpenPgpReader, Provider, ProviderError,
    Purpose, VerifyStatus,
};
use test_support::TempGnupgHome;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn json(body: String) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body, "application/json")
}

/// A mock GitHub with the fixtures. `gpg_body` replaces the GPG key list.
async fn mock_github(gpg_body: Option<String>) -> MockServer {
    let server = MockServer::start().await;
    let auth = format!("Bearer {TOKEN}");
    let get = |p: &str| {
        Mock::given(method("GET"))
            .and(path(p.to_string()))
            .and(header("authorization", auth.as_str()))
            .and(header("x-github-api-version", "2026-03-10"))
            .and(header("accept", "application/vnd.github+json"))
    };
    get("/user")
        .respond_with(json(fixture("github/user.json")))
        .mount(&server)
        .await;
    get("/user/keys")
        .and(query_param("page", "2"))
        .respond_with(json(fixture("github/user_keys_page2.json")))
        .mount(&server)
        .await;
    let next = format!(
        "<{}/user/keys?per_page=100&page=2>; rel=\"next\"",
        server.uri()
    );
    get("/user/keys")
        .and(query_param("per_page", "100"))
        .respond_with(json(fixture("github/user_keys.json")).insert_header("link", next.as_str()))
        .mount(&server)
        .await;
    get("/user/ssh_signing_keys")
        .and(query_param("per_page", "100"))
        .respond_with(json(fixture("github/user_ssh_signing_keys.json")))
        .mount(&server)
        .await;
    get("/user/gpg_keys")
        .and(query_param("per_page", "100"))
        .respond_with(json(
            gpg_body.unwrap_or_else(|| fixture("github/user_gpg_keys.json")),
        ))
        .mount(&server)
        .await;
    server
}

fn github(server: &MockServer, gnupg: &TempGnupgHome, log: &NetLog) -> (GitHub, providers::Target) {
    let target = account("https://github.com");
    let p = GitHub::new(
        tokens(LocationKind::GitHub, &target),
        OpenPgpReader::with_home(gnupg.path()),
        log.clone(),
    )
    .with_api_url(server.uri());
    (p, target)
}

#[tokio::test]
async fn github_list_against_mock() {
    let server = mock_github(None).await;
    let gnupg = TempGnupgHome::new();
    let log = NetLog::new();
    let (p, target) = github(&server, &gnupg, &log);
    assert_eq!(p.kind(), LocationKind::GitHub);
    let keys = p.list(&target).await.unwrap();

    let of = |purpose| -> Vec<Fingerprint> {
        keys.iter()
            .filter(|k| k.purpose == purpose)
            .map(|k| k.fingerprint.clone())
            .collect()
    };
    let mut auth = ssh_fprs("github/user_keys.json");
    auth.extend(ssh_fprs("github/user_keys_page2.json"));
    assert_eq!(of(Purpose::SshAuth), auth);
    assert_eq!(
        of(Purpose::SshSigning),
        ssh_fprs("github/user_ssh_signing_keys.json")
    );
    assert_eq!(
        of(Purpose::OpenPgp),
        vec![openpgp_fpr("github/user_gpg_keys.json")]
    );

    let laptop = &keys[0];
    assert_eq!(laptop.title.as_deref(), Some("laptop"));
    assert_eq!(laptop.remote_id.as_deref(), Some("101"));
    let gpg = keys.iter().find(|k| k.purpose == Purpose::OpenPgp).unwrap();
    assert_eq!(gpg.title.as_deref(), Some("Test User key"));
    assert_eq!(gpg.remote_id.as_deref(), Some("301"));

    // NFR-2: one entry per request, no token (S-4).
    let entries = log.entries();
    assert_eq!(entries.len(), 5, "{}", log.render());
    assert!(entries[0].action.ends_with("/user"), "{}", log.render());
    assert!(entries.iter().all(|e| e.kind == LocationKind::GitHub));
    assert_no_token(&log, &[]);
}

#[tokio::test]
async fn github_verify_by_fingerprint() {
    let server = mock_github(None).await;
    let gnupg = TempGnupgHome::new();
    let log = NetLog::new();
    let (p, target) = github(&server, &gnupg, &log);

    let auth = ssh_fprs("github/user_keys_page2.json")[0].clone();
    let signing = ssh_fprs("github/user_ssh_signing_keys.json")[0].clone();
    let gpg = openpgp_fpr("github/user_gpg_keys.json");
    let cases = [
        (auth.clone(), Purpose::SshAuth, VerifyStatus::Verified),
        (signing.clone(), Purpose::SshSigning, VerifyStatus::Verified),
        (signing, Purpose::SshAuth, VerifyStatus::Missing),
        (auth, Purpose::SshSigning, VerifyStatus::Missing),
        (gpg, Purpose::OpenPgp, VerifyStatus::Verified),
        (
            Fingerprint::Ssh("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
            Purpose::SshAuth,
            VerifyStatus::Missing,
        ),
        // A subkey is not the key.
        (
            Fingerprint::OpenPgp("694E9F3A2DD06653E88F7951F8E39F2E3888B67F".into()),
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
async fn github_gpg_key_without_raw_key_is_not_missing() {
    let mut body: serde_json::Value =
        serde_json::from_str(&fixture("github/user_gpg_keys.json")).unwrap();
    body[0]["raw_key"] = serde_json::Value::Null;
    let server = mock_github(Some(body.to_string())).await;
    let gnupg = TempGnupgHome::new();
    let log = NetLog::new();
    let (p, target) = github(&server, &gnupg, &log);
    let gpg = openpgp_fpr("github/user_gpg_keys.json");
    let keys = p.list(&target).await.unwrap();
    assert!(!keys.iter().any(|k| k.purpose == Purpose::OpenPgp));
    let got = p
        .verify(&target, &key(gpg, Purpose::OpenPgp))
        .await
        .unwrap();
    assert!(matches!(got, VerifyStatus::Error(_)), "{got:?}");
}

#[tokio::test]
async fn github_errors_hold_no_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!("bad token {TOKEN}")))
        .mount(&server)
        .await;
    let gnupg = TempGnupgHome::new();
    let log = NetLog::new();
    let (p, target) = github(&server, &gnupg, &log);
    let err = p.list(&target).await.unwrap_err();
    assert!(
        matches!(err, ProviderError::HttpStatus { status: 401, .. }),
        "{err:?}"
    );
    assert_no_token(&log, &[err.to_string(), format!("{err:?}")]);

    // No token stored: refused before any request.
    let none = GitHub::new(
        Arc::new(InMemoryTokenSource::new()),
        OpenPgpReader::with_home(gnupg.path()),
        log.clone(),
    )
    .with_api_url(server.uri());
    let before = log.entries().len();
    let err = none.list(&target).await.unwrap_err();
    assert!(matches!(err, ProviderError::NoToken(_)), "{err:?}");
    assert_eq!(log.entries().len(), before);

    // Only github.com without an explicit API URL.
    let other = GitHub::new(
        tokens(LocationKind::GitHub, &account("https://example.org")),
        OpenPgpReader::with_home(gnupg.path()),
        log.clone(),
    );
    let err = other
        .list(&account("https://example.org"))
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::WrongTarget { .. }), "{err:?}");
}

/// A local GnuPG failure is not reported as the forge's fault.
#[tokio::test]
async fn github_local_gpg_failure_is_not_blamed_on_forge() {
    use std::os::unix::ffi::OsStringExt;
    let server = mock_github(None).await;
    let log = NetLog::new();
    let target = account("https://github.com");
    // A home path with a NUL byte: GnuPG cannot be set up.
    let bad_home =
        std::path::PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/no\0home".to_vec()));
    let p = GitHub::new(
        tokens(LocationKind::GitHub, &target),
        OpenPgpReader::with_home(bad_home),
        log.clone(),
    )
    .with_api_url(server.uri());
    let gpg = openpgp_fpr("github/user_gpg_keys.json");
    let got = p
        .verify(&target, &key(gpg, Purpose::OpenPgp))
        .await
        .unwrap();
    let text = match got {
        VerifyStatus::Error(providers::VerifyError::Other(t)) => t,
        other => panic!("{other:?}"),
    };
    assert!(text.contains("GnuPG failed"), "{text}");
    assert!(!text.contains("did not send"), "{text}");
}

/// The forge lists the token owner's keys, so the owner must be the
/// target account (case does not matter).
#[tokio::test]
async fn github_token_owner_must_be_target_account() {
    let gnupg = TempGnupgHome::new();
    let server = mock_github(None).await;
    let target = account_named("https://github.com", "TestUser");
    let p = GitHub::new(
        tokens(LocationKind::GitHub, &target),
        OpenPgpReader::with_home(gnupg.path()),
        NetLog::new(),
    )
    .with_api_url(server.uri());
    assert!(!p.list(&target).await.unwrap().is_empty());

    let other = owner_only("", "login", "someoneelse").await;
    let log = NetLog::new();
    let (p, target) = github(&other, &gnupg, &log);
    let k = key(openpgp_fpr("github/user_gpg_keys.json"), Purpose::OpenPgp);
    assert_owner_mismatch(&p, &target, &log, &k).await;
}
