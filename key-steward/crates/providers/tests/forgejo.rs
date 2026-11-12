//! Forgejo provider (also Gitea and Codeberg) against wiremock with the
//! mock forge fixtures.

mod common;

use common::*;
use identity_core::Fingerprint;
use providers::{
    Forgejo, LocationKind, NetLog, OpenPgpReader, Provider, Purpose, Target, VerifyStatus,
};
use test_support::TempGnupgHome;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn json(body: String) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body, "application/json")
}

/// A mock Forgejo. `page2` replaces the second page of SSH keys.
async fn mock_forgejo(page2: Option<String>) -> MockServer {
    let server = MockServer::start().await;
    let auth = format!("token {TOKEN}");
    let get = |p: &str| {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1{p}")))
            .and(header("authorization", auth.as_str()))
    };
    get("/user/keys")
        .and(query_param("page", "2"))
        .respond_with(json(
            page2.unwrap_or_else(|| fixture("forgejo/user_keys_page2.json")),
        ))
        .mount(&server)
        .await;
    let next = format!(
        "<{0}/api/v1/user/keys?limit=50&page=2>; rel=\"next\", \
         <{0}/api/v1/user/keys?limit=50&page=2>; rel=\"last\"",
        server.uri()
    );
    get("/user/keys")
        .and(query_param("limit", "50"))
        .respond_with(
            json(fixture("forgejo/user_keys.json"))
                .insert_header("link", next.as_str())
                .insert_header("x-total-count", "3"),
        )
        .mount(&server)
        .await;
    get("/user/gpg_keys")
        .and(query_param("limit", "50"))
        .respond_with(json(fixture("forgejo/user_gpg_keys.json")))
        .mount(&server)
        .await;
    server
}

fn forgejo(server: &MockServer, gnupg: &TempGnupgHome, log: &NetLog) -> (Forgejo, Target) {
    let target = account(&server.uri());
    let p = Forgejo::new(
        tokens(LocationKind::Forgejo, &target),
        OpenPgpReader::with_home(gnupg.path()),
        log.clone(),
    );
    (p, target)
}

#[tokio::test]
async fn forgejo_list_against_mock() {
    let server = mock_forgejo(None).await;
    let gnupg = TempGnupgHome::new();
    let log = NetLog::new();
    let (p, target) = forgejo(&server, &gnupg, &log);
    assert_eq!(p.kind(), LocationKind::Forgejo);
    let keys = p.list(&target).await.unwrap();

    let of = |purpose| -> Vec<Fingerprint> {
        keys.iter()
            .filter(|k| k.purpose == purpose)
            .map(|k| k.fingerprint.clone())
            .collect()
    };
    let mut ssh = ssh_fprs("forgejo/user_keys.json");
    ssh.extend(ssh_fprs("forgejo/user_keys_page2.json"));
    // One SSH key list serves auth and signing.
    assert_eq!(of(Purpose::SshAuth), ssh);
    assert_eq!(of(Purpose::SshSigning), ssh);
    assert_eq!(
        of(Purpose::OpenPgp),
        vec![openpgp_fpr("forgejo/user_gpg_keys.json")]
    );
    assert_eq!(keys[0].title.as_deref(), Some("laptop"));
    assert_eq!(keys[0].remote_id.as_deref(), Some("11"));

    assert_eq!(log.entries().len(), 3, "{}", log.render());
    assert_no_token(&log, &[]);
}

#[tokio::test]
async fn forgejo_verify_by_fingerprint() {
    let server = mock_forgejo(None).await;
    let gnupg = TempGnupgHome::new();
    let log = NetLog::new();
    let (p, target) = forgejo(&server, &gnupg, &log);
    let ssh = ssh_fprs("forgejo/user_keys_page2.json")[0].clone();
    let cases = [
        (ssh.clone(), Purpose::SshAuth, VerifyStatus::Verified),
        (ssh, Purpose::SshSigning, VerifyStatus::Verified),
        (
            openpgp_fpr("forgejo/user_gpg_keys.json"),
            Purpose::OpenPgp,
            VerifyStatus::Verified,
        ),
        (
            Fingerprint::Ssh("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
            Purpose::SshAuth,
            VerifyStatus::Missing,
        ),
    ];
    for (fpr, purpose, want) in cases {
        let got = p.verify(&target, &key(fpr.clone(), purpose)).await.unwrap();
        assert_eq!(got, want, "{fpr} {purpose:?}");
    }
    assert_no_token(&log, &[]);
}

/// The server's `fingerprint` field is never trusted: a key whose field
/// names our key but whose key text is another key is not ours.
#[tokio::test]
async fn forgejo_ignores_server_fingerprint_field() {
    let ours = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let mut page2: serde_json::Value =
        serde_json::from_str(&fixture("forgejo/user_keys_page2.json")).unwrap();
    page2[0]["fingerprint"] = ours.into();
    let server = mock_forgejo(Some(page2.to_string())).await;
    let gnupg = TempGnupgHome::new();
    let log = NetLog::new();
    let (p, target) = forgejo(&server, &gnupg, &log);
    let got = p
        .verify(
            &target,
            &key(Fingerprint::Ssh(ours.into()), Purpose::SshAuth),
        )
        .await
        .unwrap();
    assert_eq!(got, VerifyStatus::Missing);
    let keys = p.list(&target).await.unwrap();
    assert!(
        keys.iter()
            .any(|k| k.fingerprint == ssh_fprs("forgejo/user_keys_page2.json")[0])
    );
}
