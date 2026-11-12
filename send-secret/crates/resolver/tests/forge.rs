//! GitHub and GitLab sources against loopback wiremock servers only.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use identity_core::{KeyAlgo, KeyKind, LineError};
use resolver::{
    Found, GitHubSource, GitLabSource, KeyBytes, KeySource, Net, OriginMap, RejectReason,
    ResolverConfig, SourceError, Unusable, parse_query,
};
use tokio::time::Instant;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cfg() -> ResolverConfig {
    ResolverConfig {
        source_timeout: Duration::from_millis(300),
        max_redirects: 5,
    }
}

fn net(origins: &[(&str, SocketAddr)]) -> Net {
    let mut map = OriginMap::new();
    for (origin, addr) in origins {
        map.insert(origin, *addr).unwrap();
    }
    Net::with_mock_origins(&cfg(), map).unwrap()
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn data(rel: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests")
        .join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

async fn mount(server: &MockServer, at: &str, resp: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(resp)
        .expect(1)
        .mount(server)
        .await;
}

fn ok(body: Vec<u8>) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_bytes(body)
}

fn status(code: u16) -> ResponseTemplate {
    ResponseTemplate::new(code)
}

/// A GitHub mock that answers `.keys` and `.gpg` for `alice`, and nothing else.
async fn github(keys: ResponseTemplate, gpg: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    mount(&server, "/alice.keys", keys).await;
    mount(&server, "/alice.gpg", gpg).await;
    server
}

async fn github_lookup(server: &MockServer) -> Result<Found, SourceError> {
    let net = net(&[("https://github.com", *server.address())]);
    let q = parse_query("github:alice").unwrap();
    GitHubSource.lookup(&q, Some(&net), soon()).await
}

#[tokio::test]
async fn github_keys_list_gives_usable_keys_and_skip_notes() {
    let server = github(
        ok(data("fixtures/ssh/multi.keys")),
        ok(data("mock-sources/github-empty.gpg")),
    )
    .await;
    let found = github_lookup(&server).await.unwrap();
    let got: Vec<_> = found
        .keys
        .iter()
        .map(|k| (k.key.algo(), k.usable.clone()))
        .collect();
    assert_eq!(
        got,
        vec![
            (KeyAlgo::Ed25519, Ok(())),
            (KeyAlgo::Rsa(3072), Ok(())),
            (
                KeyAlgo::Ecdsa("nistp256".into()),
                Err(Unusable::EcdsaNotAge)
            ),
            (KeyAlgo::SkEd25519, Err(Unusable::SkKey)),
            (KeyAlgo::Rsa(8192), Err(Unusable::RsaSize(8192))),
            (KeyAlgo::Rsa(1024), Err(Unusable::RsaSize(1024))),
        ]
    );
    for k in &found.keys {
        assert_eq!(k.source.location, "https://github.com/alice.keys");
        assert_eq!(k.source.first_url, None);
        assert!(matches!(&k.bytes, KeyBytes::Ssh(s) if s.split(' ').count() == 2));
    }
    assert!(found.rejected.is_empty());
}

#[tokio::test]
async fn github_empty_gpg_is_no_key_not_an_error() {
    let server = github(status(404), ok(data("mock-sources/github-empty.gpg"))).await;
    let found = github_lookup(&server).await.unwrap();
    assert_eq!(found, Found::default());
}

#[tokio::test]
async fn github_keys_404_and_gpg_with_key() {
    let server = github(status(404), ok(data("fixtures/openpgp/alice.asc"))).await;
    let found = github_lookup(&server).await.unwrap();
    assert_eq!(found.keys.len(), 1);
    let k = &found.keys[0];
    assert_eq!(k.key.kind(), KeyKind::OpenPgp);
    assert_eq!(k.usable, Ok(()));
    assert_eq!(k.source.location, "https://github.com/alice.gpg");
    assert!(matches!(&k.bytes, KeyBytes::OpenPgp(b) if b[0] & 0x80 != 0));
    assert!(
        k.shown_user_ids
            .iter()
            .any(|u| u.has_email("alice@example.org"))
    );
}

#[tokio::test]
async fn github_gpg_expired_key_is_unusable_with_note() {
    let server = github(status(404), ok(data("fixtures/openpgp/eve-expired.asc"))).await;
    let found = github_lookup(&server).await.unwrap();
    assert_eq!(found.keys.len(), 1);
    assert_eq!(found.keys[0].usable, Err(Unusable::Expired));
}

#[tokio::test]
async fn github_both_404_is_not_found() {
    let server = github(status(404), status(404)).await;
    assert_eq!(github_lookup(&server).await, Err(SourceError::NotFound));
}

#[tokio::test]
async fn github_junk_keys_is_malformed() {
    let server = github(ok(data("mock-sources/junk.bin")), status(404)).await;
    assert!(matches!(
        github_lookup(&server).await,
        Err(SourceError::Malformed(_))
    ));
}

#[tokio::test]
async fn github_gpg_without_armor_header_is_malformed() {
    for body in ["mock-sources/not-found.html", "mock-sources/junk.bin"] {
        let server = github(status(404), ok(data(body))).await;
        assert!(
            matches!(github_lookup(&server).await, Err(SourceError::Malformed(_))),
            "{body}"
        );
    }
}

#[tokio::test]
async fn github_gpg_armor_with_no_readable_key_is_no_key() {
    let server = github(status(404), ok(data("mock-sources/broken-armor.asc"))).await;
    assert_eq!(github_lookup(&server).await, Ok(Found::default()));
}

#[tokio::test]
async fn github_html_keys_is_malformed() {
    let server = github(ok(data("mock-sources/not-found.html")), status(404)).await;
    assert!(matches!(
        github_lookup(&server).await,
        Err(SourceError::Malformed(_))
    ));
}

#[tokio::test]
async fn github_empty_keys_list_is_no_key() {
    let server = github(ok(Vec::new()), ok(data("mock-sources/github-empty.gpg"))).await;
    assert_eq!(github_lookup(&server).await, Ok(Found::default()));
}

#[tokio::test]
async fn github_gpg_shows_only_valid_user_ids() {
    let server = github(
        status(404),
        ok(data("fixtures/openpgp/rita-revoked-uid.asc")),
    )
    .await;
    let found = github_lookup(&server).await.unwrap();
    let k = &found.keys[0];
    assert!(!k.shown_user_ids.is_empty());
    assert!(k.shown_user_ids.iter().all(|u| !u.revoked && !u.invalid));
    assert!(
        !k.shown_user_ids
            .iter()
            .any(|u| u.uid.contains("rita@example.org"))
    );
}

#[tokio::test]
async fn github_bad_line_is_a_reject_next_to_good_keys() {
    let mut body = b"not a key at all\n".to_vec();
    body.extend(data("fixtures/ssh/erin_ed25519.pub"));
    let server = github(ok(body), status(404)).await;
    let found = github_lookup(&server).await.unwrap();
    assert_eq!(found.keys.len(), 1);
    assert_eq!(found.rejected.len(), 1);
    assert!(matches!(
        found.rejected[0].reason,
        RejectReason::BadLine {
            line: 1,
            error: LineError::UnknownType | LineError::Malformed
        }
    ));
}

#[tokio::test]
async fn github_oversized_is_too_large() {
    let big = vec![b'a'; 1_000_001];
    let server = github(ok(big.clone()), ok(big)).await;
    assert_eq!(github_lookup(&server).await, Err(SourceError::TooLarge));
}

#[tokio::test]
async fn github_429_is_rate_limited() {
    let limited = || status(429).insert_header("retry-after", "30");
    let server = github(limited(), limited()).await;
    assert_eq!(
        github_lookup(&server).await,
        Err(SourceError::RateLimited {
            retry_after: Some(Duration::from_secs(30))
        })
    );
}

#[tokio::test]
async fn github_one_part_failing_keeps_the_other_parts_keys_marked_incomplete() {
    let server = github(ok(data("fixtures/ssh/erin_ed25519.pub")), status(500)).await;
    let found = github_lookup(&server).await.unwrap();
    assert_eq!(found.keys.len(), 1);
    assert_eq!(found.incomplete, vec![SourceError::Http(500)]);
}

#[tokio::test]
async fn github_rate_limited_part_keeps_retry_after() {
    let server = github(
        status(429).insert_header("retry-after", "30"),
        ok(data("fixtures/openpgp/alice.asc")),
    )
    .await;
    let found = github_lookup(&server).await.unwrap();
    assert_eq!(found.keys.len(), 1);
    assert_eq!(
        found.incomplete,
        vec![SourceError::RateLimited {
            retry_after: Some(Duration::from_secs(30))
        }]
    );
}

#[tokio::test]
async fn github_complete_answer_is_not_incomplete() {
    let server = github(status(404), ok(data("fixtures/openpgp/alice.asc"))).await;
    assert!(github_lookup(&server).await.unwrap().incomplete.is_empty());
}

#[tokio::test]
async fn github_error_beats_empty_answer() {
    let server = github(status(500), ok(data("mock-sources/github-empty.gpg"))).await;
    assert_eq!(github_lookup(&server).await, Err(SourceError::Http(500)));
}

#[tokio::test]
async fn github_slow_answer_times_out() {
    let slow = || ok(data("fixtures/ssh/erin_ed25519.pub")).set_delay(Duration::from_secs(2));
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(slow())
        .mount(&server)
        .await;
    let net = net(&[("https://github.com", *server.address())]);
    let q = parse_query("github:alice").unwrap();
    let deadline = Instant::now() + Duration::from_millis(300);
    assert_eq!(
        GitHubSource.lookup(&q, Some(&net), deadline).await,
        Err(SourceError::Timeout)
    );
}

#[tokio::test]
async fn github_redirect_is_shown_as_source() {
    let server = MockServer::start().await;
    mount(
        &server,
        "/alice.keys",
        status(301).insert_header("location", "https://github.com/Alice.keys"),
    )
    .await;
    mount(
        &server,
        "/Alice.keys",
        ok(data("fixtures/ssh/erin_ed25519.pub")),
    )
    .await;
    mount(&server, "/alice.gpg", status(404)).await;
    let found = github_lookup(&server).await.unwrap();
    let s = &found.keys[0].source;
    assert_eq!(s.location, "https://github.com/Alice.keys");
    assert_eq!(
        s.first_url.as_deref(),
        Some("https://github.com/alice.keys")
    );
}

#[tokio::test]
async fn no_net_is_an_error_not_a_request() {
    let q = parse_query("github:alice").unwrap();
    assert!(matches!(
        GitHubSource.lookup(&q, None, soon()).await,
        Err(SourceError::Net(_))
    ));
    let q = parse_query("gitlab:alice").unwrap();
    assert!(matches!(
        GitLabSource.lookup(&q, None, soon()).await,
        Err(SourceError::Net(_))
    ));
}

#[test]
fn sources_accept_only_their_queries() {
    let gh = parse_query("github:alice").unwrap();
    let gl = parse_query("gitlab:alice").unwrap();
    let mail = parse_query("alice@example.org").unwrap();
    assert!(GitHubSource.accepts(&gh));
    assert!(!GitHubSource.accepts(&gl));
    assert!(!GitHubSource.accepts(&mail));
    assert!(GitLabSource.accepts(&gl));
    assert!(!GitLabSource.accepts(&gh));
    assert!(!GitLabSource.accepts(&mail));
}

#[tokio::test]
async fn gitlab_com_keys_exact_path() {
    let server = MockServer::start().await;
    mount(&server, "/alice.keys", ok(data("fixtures/ssh/multi.keys"))).await;
    let net = net(&[("https://gitlab.com", *server.address())]);
    let q = parse_query("gitlab:alice").unwrap();
    let found = GitLabSource.lookup(&q, Some(&net), soon()).await.unwrap();
    assert_eq!(found.keys.len(), 6);
    assert_eq!(
        found.keys[0].source.location,
        "https://gitlab.com/alice.keys"
    );
    let log = net.log().entries();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].action, "GET https://gitlab.com/alice.keys");
}

#[tokio::test]
async fn gitlab_host_asks_the_mapped_host_only() {
    let com = MockServer::start().await;
    let own = MockServer::start().await;
    mount(&own, "/bob.keys", ok(data("fixtures/ssh/erin_ed25519.pub"))).await;
    let net = net(&[
        ("https://gitlab.com", *com.address()),
        ("https://git.example.org:8443", *own.address()),
    ]);
    let q = parse_query("gitlab:git.example.org:8443/bob").unwrap();
    let found = GitLabSource.lookup(&q, Some(&net), soon()).await.unwrap();
    assert_eq!(found.keys.len(), 1);
    assert_eq!(
        found.keys[0].source.location,
        "https://git.example.org:8443/bob.keys"
    );
    assert!(com.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn gitlab_404_is_not_found_and_429_rate_limited() {
    let server = MockServer::start().await;
    mount(&server, "/alice.keys", status(404)).await;
    mount(&server, "/bob.keys", status(429)).await;
    let net = net(&[("https://gitlab.com", *server.address())]);
    let alice = parse_query("gitlab:alice").unwrap();
    assert_eq!(
        GitLabSource.lookup(&alice, Some(&net), soon()).await,
        Err(SourceError::NotFound)
    );
    let bob = parse_query("gitlab:bob").unwrap();
    assert!(matches!(
        GitLabSource.lookup(&bob, Some(&net), soon()).await,
        Err(SourceError::RateLimited { .. })
    ));
}

#[tokio::test]
async fn gitlab_oversized_and_junk() {
    let server = MockServer::start().await;
    mount(&server, "/big.keys", ok(vec![b'a'; 1_000_001])).await;
    mount(&server, "/junk.keys", ok(data("mock-sources/junk.bin"))).await;
    let net = net(&[("https://gitlab.com", *server.address())]);
    let big = parse_query("gitlab:big").unwrap();
    assert_eq!(
        GitLabSource.lookup(&big, Some(&net), soon()).await,
        Err(SourceError::TooLarge)
    );
    let junk = parse_query("gitlab:junk").unwrap();
    assert!(matches!(
        GitLabSource.lookup(&junk, Some(&net), soon()).await,
        Err(SourceError::Malformed(_))
    ));
}
