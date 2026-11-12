//! WKD source against two loopback mock servers, one for the advanced host
//! (`openpgpkey.example.org`) and one for the direct host (`example.org`).
//! No real network, no real DNS.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use identity_core::{Fingerprint, Gpg, PublicKey, wkd_hash};
use resolver::{
    Found, KeyBytes, KeySource, Mode, Net, OriginMap, Query, RejectReason, Resolver,
    ResolverConfig, SourceError, SourceKind, Unusable, WkdSource, parse_query,
};
use tokio::time::Instant;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ADVANCED: &str = "https://openpgpkey.example.org";
const DIRECT: &str = "https://example.org";

fn cfg() -> ResolverConfig {
    ResolverConfig {
        source_timeout: Duration::from_millis(300),
        max_redirects: 5,
    }
}

fn fixture(rel: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests")
        .join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn key(name: &str) -> Vec<u8> {
    fixture(&format!("fixtures/openpgp/{name}"))
}

fn fpr_of(name: &str) -> Fingerprint {
    let keys = Gpg::split_keys(&key(name)).unwrap();
    assert_eq!(keys.len(), 1);
    keys[0].0.fingerprint.clone()
}

fn net(origins: &[(&str, SocketAddr)]) -> Net {
    let mut map = OriginMap::new();
    for (origin, addr) in origins {
        map.insert(origin, *addr).unwrap();
    }
    Net::with_mock_origins(&cfg(), map).unwrap()
}

fn email(s: &str) -> Query {
    let q = parse_query(s).unwrap();
    assert!(matches!(q, Query::Email(_)));
    q
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn advanced_path(local: &str) -> String {
    format!("/.well-known/openpgpkey/example.org/hu/{}", wkd_hash(local))
}

fn direct_path(local: &str) -> String {
    format!("/.well-known/openpgpkey/hu/{}", wkd_hash(local))
}

/// A server that answers `path` once with `resp`.
async fn serving(path_: &str, local: &str, resp: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(path_))
        .and(query_param("l", local))
        .respond_with(resp)
        .expect(1)
        .mount(&server)
        .await;
    server
}

/// A server that must get no request at all.
async fn untouched() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    server
}

fn ok(body: Vec<u8>) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_bytes(body)
}

async fn lookup(net: &Net, q: &str) -> Result<Found, SourceError> {
    WkdSource::new().lookup(&email(q), Some(net), soon()).await
}

/// Serves `body` for `local` at the advanced host; the direct host must
/// not be asked.
async fn advanced_answer(local: &str, body: Vec<u8>) -> Result<Found, SourceError> {
    let adv = serving(&advanced_path(local), local, ok(body)).await;
    let direct = untouched().await;
    let net = net(&[(ADVANCED, *adv.address()), (DIRECT, *direct.address())]);
    let r = lookup(&net, &format!("{local}@example.org")).await;
    adv.verify().await;
    direct.verify().await;
    r
}

#[test]
fn accepts_only_email() {
    let s = WkdSource::new();
    assert_eq!(s.kind(), SourceKind::Wkd);
    assert!(s.accepts(&email("alice@example.org")));
    assert!(!s.accepts(&parse_query("github:alice").unwrap()));
    assert!(!s.accepts(&parse_query("Alice").unwrap()));
    assert!(!s.accepts(&Query::pasted(b"x".to_vec()).unwrap()));
}

#[tokio::test]
async fn advanced_used_when_host_has_address() {
    let found = advanced_answer("alice", key("alice.gpg")).await.unwrap();
    assert!(found.rejected.is_empty());
    assert_eq!(found.keys.len(), 1);
    let k = &found.keys[0];
    assert_eq!(k.fingerprint(), fpr_of("alice.asc"));
    assert_eq!(k.usable, Ok(()));
    assert_eq!(k.source.kind, SourceKind::Wkd);
    assert_eq!(
        k.source.location,
        format!("{ADVANCED}{}?l=alice", advanced_path("alice"))
    );
    assert_eq!(k.source.first_url, None);
    assert!(!k.shown_user_ids.is_empty());
    assert!(
        k.shown_user_ids
            .iter()
            .all(|u| u.has_email("alice@example.org"))
    );
    let KeyBytes::OpenPgp(bytes) = &k.bytes else {
        panic!("not OpenPGP bytes");
    };
    let again = Gpg::split_keys(bytes).unwrap();
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].0.fingerprint, k.fingerprint());
}

#[tokio::test]
async fn direct_used_when_advanced_host_has_no_address() {
    let direct = serving(&direct_path("alice"), "alice", ok(key("alice.asc"))).await;
    let net = net(&[(DIRECT, *direct.address())]);
    let found = lookup(&net, "alice@example.org").await.unwrap();
    direct.verify().await;
    assert_eq!(found.keys.len(), 1);
    assert_eq!(found.keys[0].fingerprint(), fpr_of("alice.asc"));
    assert_eq!(
        found.keys[0].source.location,
        format!("{DIRECT}{}?l=alice", direct_path("alice"))
    );
    let log = net.log().entries();
    assert_eq!(log[0].action, "DNS openpgpkey.example.org");
    assert_eq!(log[0].outcome, "no address");
    assert!(log[1].action.starts_with("GET https://example.org/"));
    assert_eq!(log.len(), 2);
}

#[tokio::test]
async fn dns_check_is_logged_before_advanced_request() {
    let adv = serving(&advanced_path("alice"), "alice", ok(key("alice.gpg"))).await;
    let net = net(&[(ADVANCED, *adv.address())]);
    lookup(&net, "alice@example.org").await.unwrap();
    let log = net.log().entries();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].action, "DNS openpgpkey.example.org");
    assert_eq!(log[0].outcome, "has an address");
    assert!(
        log[1]
            .action
            .starts_with("GET https://openpgpkey.example.org/")
    );
}

#[tokio::test]
async fn armored_answer_is_found() {
    let found = advanced_answer("alice", key("alice.asc")).await.unwrap();
    assert_eq!(found.keys.len(), 1);
    assert_eq!(found.keys[0].fingerprint(), fpr_of("alice.asc"));
}

#[tokio::test]
async fn query_case_does_not_matter() {
    let found = advanced_answer("Alice", key("alice.gpg")).await.unwrap();
    assert_eq!(wkd_hash("Alice"), wkd_hash("alice"));
    assert_eq!(found.keys.len(), 1);
}

async fn no_fallback(resp: ResponseTemplate) -> SourceError {
    let adv = serving(&advanced_path("alice"), "alice", resp).await;
    let direct = untouched().await;
    let net = net(&[(ADVANCED, *adv.address()), (DIRECT, *direct.address())]);
    let err = lookup(&net, "alice@example.org").await.unwrap_err();
    direct.verify().await;
    err
}

#[tokio::test]
async fn advanced_404_does_not_fall_back() {
    assert_eq!(
        no_fallback(ResponseTemplate::new(404)).await,
        SourceError::NotFound
    );
}

#[tokio::test]
async fn advanced_500_does_not_fall_back() {
    assert_eq!(
        no_fallback(ResponseTemplate::new(500)).await,
        SourceError::Http(500)
    );
}

#[tokio::test]
async fn advanced_429_is_rate_limited_and_does_not_fall_back() {
    let err = no_fallback(ResponseTemplate::new(429).insert_header("retry-after", "30")).await;
    assert_eq!(
        err,
        SourceError::RateLimited {
            retry_after: Some(Duration::from_secs(30))
        }
    );
}

#[tokio::test]
async fn advanced_timeout_does_not_fall_back() {
    let adv = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ok(key("alice.gpg")).set_delay(Duration::from_secs(2)))
        .mount(&adv)
        .await;
    let direct = untouched().await;
    let net = net(&[(ADVANCED, *adv.address()), (DIRECT, *direct.address())]);
    let deadline = Instant::now() + Duration::from_millis(300);
    let err = WkdSource::new()
        .lookup(&email("alice@example.org"), Some(&net), deadline)
        .await
        .unwrap_err();
    assert_eq!(err, SourceError::Timeout);
    direct.verify().await;
}

#[tokio::test]
async fn advanced_connection_failure_does_not_fall_back() {
    // Stands in for a TLS error: the advanced host has an address, but the
    // connection fails.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let direct = untouched().await;
    let net = net(&[(ADVANCED, closed), (DIRECT, *direct.address())]);
    let err = lookup(&net, "alice@example.org").await.unwrap_err();
    assert!(matches!(err, SourceError::Net(_)), "{err:?}");
    direct.verify().await;
    assert_eq!(net.log().entries().len(), 2);
}

#[tokio::test]
async fn direct_404_is_not_found() {
    let direct = serving(&direct_path("alice"), "alice", ResponseTemplate::new(404)).await;
    let net = net(&[(DIRECT, *direct.address())]);
    assert_eq!(
        lookup(&net, "alice@example.org").await.unwrap_err(),
        SourceError::NotFound
    );
}

#[tokio::test]
async fn concatenated_keys_keep_match_and_reject_other() {
    let found = advanced_answer("alice", key("alice-mallory.gpg"))
        .await
        .unwrap();
    assert_eq!(found.keys.len(), 1);
    assert_eq!(found.keys[0].fingerprint(), fpr_of("alice.asc"));
    assert_eq!(found.rejected.len(), 1);
    let r = &found.rejected[0];
    assert_eq!(r.reason, RejectReason::EmailMismatch);
    assert_eq!(r.fingerprint, Some(fpr_of("mallory-other.asc")));
    assert_eq!(r.source.kind, SourceKind::Wkd);
}

#[tokio::test]
async fn other_persons_key_alone_is_rejected() {
    let found = advanced_answer("alice", key("mallory-other.asc"))
        .await
        .unwrap();
    assert!(found.keys.is_empty());
    assert_eq!(found.rejected.len(), 1);
    assert_eq!(found.rejected[0].reason, RejectReason::EmailMismatch);
}

#[tokio::test]
async fn revoked_matching_user_id_is_rejected() {
    let found = advanced_answer("rita", key("rita-revoked-uid.asc"))
        .await
        .unwrap();
    assert!(found.keys.is_empty());
    assert_eq!(found.rejected.len(), 1);
    assert_eq!(found.rejected[0].reason, RejectReason::EmailMismatch);
    assert_eq!(
        found.rejected[0].fingerprint,
        Some(fpr_of("rita-revoked-uid.asc"))
    );
}

#[tokio::test]
async fn only_matching_user_ids_are_shown() {
    let found = advanced_answer("olivia", key("olivia-two-uids.asc"))
        .await
        .unwrap();
    assert_eq!(found.keys.len(), 1);
    let k = &found.keys[0];
    assert_eq!(k.shown_user_ids.len(), 1);
    assert_eq!(
        k.shown_user_ids[0].email.as_deref(),
        Some("olivia@example.org")
    );
    let PublicKey::OpenPgp(summary) = &k.key else {
        panic!("not OpenPGP");
    };
    assert_eq!(summary.user_ids, k.shown_user_ids);
}

#[tokio::test]
async fn expired_key_is_kept_with_note() {
    let found = advanced_answer("eve", key("eve-expired.asc"))
        .await
        .unwrap();
    assert_eq!(found.keys.len(), 1);
    assert_eq!(found.keys[0].usable, Err(Unusable::Expired));
}

#[tokio::test]
async fn malformed_answers() {
    for body in [
        fixture("mock-sources/junk.bin"),
        fixture("mock-sources/not-found.html"),
        fixture("mock-sources/broken-armor.asc"),
        fixture("mock-sources/github-empty.gpg"),
        Vec::new(),
    ] {
        let err = advanced_answer("alice", body).await.unwrap_err();
        assert!(matches!(err, SourceError::Malformed(_)), "{err:?}");
    }
}

#[tokio::test]
async fn oversized_answer_is_refused() {
    let err = advanced_answer("alice", vec![b'A'; 1_000_001])
        .await
        .unwrap_err();
    assert_eq!(err, SourceError::TooLarge);
}

#[tokio::test]
async fn redirect_to_https_is_followed_and_shown() {
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/wkd/alice"))
        .respond_with(ok(key("alice.gpg")))
        .expect(1)
        .mount(&target)
        .await;
    let adv = serving(
        &advanced_path("alice"),
        "alice",
        ResponseTemplate::new(302).insert_header("location", "https://keys.example.net/wkd/alice"),
    )
    .await;
    let net = net(&[
        (ADVANCED, *adv.address()),
        ("https://keys.example.net", *target.address()),
    ]);
    let found = lookup(&net, "alice@example.org").await.unwrap();
    let src = &found.keys[0].source;
    assert_eq!(src.location, "https://keys.example.net/wkd/alice");
    assert_eq!(
        src.first_url.as_deref(),
        Some(format!("{ADVANCED}{}?l=alice", advanced_path("alice")).as_str())
    );
}

#[tokio::test]
async fn redirect_to_http_is_refused() {
    let err = no_fallback(
        ResponseTemplate::new(302).insert_header("location", "http://example.org/alice"),
    )
    .await;
    assert!(matches!(err, SourceError::Net(_)), "{err:?}");
}

#[tokio::test]
async fn no_net_is_an_error() {
    let err = WkdSource::new()
        .lookup(&email("alice@example.org"), None, soon())
        .await
        .unwrap_err();
    assert!(matches!(err, SourceError::Net(_)));
}

#[tokio::test]
async fn through_resolver() {
    let adv = serving(
        &advanced_path("alice"),
        "alice",
        ok(key("alice-mallory.gpg")),
    )
    .await;
    let net = net(&[(ADVANCED, *adv.address())]);
    let resolver = Resolver::new(cfg(), Some(net), vec![Box::new(WkdSource::new())]);
    let res = resolver
        .resolve(&email("alice@example.org"), Mode::Full)
        .await;
    assert_eq!(res.candidates.len(), 1);
    assert_eq!(res.candidates[0].fingerprint, fpr_of("alice.asc"));
    assert_eq!(res.rejected.len(), 1);
    assert!(res.errors.is_empty());
    assert_eq!(res.requests.len(), 2);

    let none = resolver
        .resolve(&email("alice@example.org"), Mode::LocalOnly)
        .await;
    assert!(none.candidates.is_empty() && none.errors.is_empty());
}

#[tokio::test]
async fn too_many_keys_are_rejected() {
    let alice = key("alice.gpg");
    let blob: Vec<u8> = (0..=identity_core::MAX_SPLIT_KEYS)
        .flat_map(|_| alice.clone())
        .collect();
    let found = advanced_answer("alice", blob).await.unwrap();
    assert!(found.keys.is_empty());
    assert_eq!(found.rejected.len(), 1);
    assert_eq!(found.rejected[0].reason, RejectReason::TooManyKeys);
}
