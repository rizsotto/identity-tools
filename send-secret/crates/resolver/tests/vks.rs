//! keys.openpgp.org source against a loopback wiremock server only.

use std::path::PathBuf;
use std::time::Duration;

use identity_core::Fingerprint;
use resolver::{
    Found, KeySource, Net, OriginMap, RejectReason, ResolverConfig, SourceError, VksSource,
    parse_query,
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

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn data(rel: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests")
        .join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// A keys.openpgp.org mock answering `resp` at `at` only.
async fn vks(at: &str, resp: ResponseTemplate) -> (MockServer, Net) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(resp)
        .expect(1)
        .mount(&server)
        .await;
    let mut map = OriginMap::new();
    map.insert("https://keys.openpgp.org", *server.address())
        .unwrap();
    let net = Net::with_mock_origins(&cfg(), map).unwrap();
    (server, net)
}

async fn lookup(net: &Net, query: &str) -> Result<Found, SourceError> {
    let q = parse_query(query).unwrap();
    VksSource.lookup(&q, Some(net), soon()).await
}

fn ok(rel: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "application/pgp-keys")
        .set_body_bytes(data(rel))
}

const ALICE: &str = "/vks/v1/by-email/alice@example.org";

#[tokio::test]
async fn exact_path_escapes_plus() {
    let (_s, net) = vks(
        "/vks/v1/by-email/a%2Bb@example.org",
        ResponseTemplate::new(404),
    )
    .await;
    assert_eq!(
        lookup(&net, "a+b@Example.ORG").await,
        Err(SourceError::NotFound)
    );
    let log = net.log().entries();
    assert_eq!(log.len(), 1);
    assert_eq!(
        log[0].action,
        "GET https://keys.openpgp.org/vks/v1/by-email/a%2Bb@example.org"
    );
}

#[tokio::test]
async fn exact_path_escapes_non_ascii_local_part() {
    let (_s, net) = vks(
        "/vks/v1/by-email/%C3%9Cn%C3%AFcode@example.org",
        ResponseTemplate::new(404),
    )
    .await;
    assert_eq!(
        lookup(&net, "Ünïcode@example.org").await,
        Err(SourceError::NotFound)
    );
}

#[tokio::test]
async fn found_shows_only_matching_user_ids() {
    let (_s, net) = vks(ALICE, ok("fixtures/openpgp/alice.asc")).await;
    let found = lookup(&net, "alice@example.org").await.unwrap();
    assert!(found.rejected.is_empty());
    assert_eq!(found.keys.len(), 1);
    let k = &found.keys[0];
    assert_eq!(k.usable, Ok(()));
    assert!(!k.shown_user_ids.is_empty());
    assert!(
        k.shown_user_ids
            .iter()
            .all(|u| u.has_email("alice@example.org"))
    );
    assert_eq!(
        k.source.location,
        "https://keys.openpgp.org/vks/v1/by-email/alice@example.org"
    );
}

#[tokio::test]
async fn upper_case_query_matches() {
    let (_s, net) = vks(
        "/vks/v1/by-email/Alice@example.org",
        ok("fixtures/openpgp/alice.asc"),
    )
    .await;
    let found = lookup(&net, "Alice@Example.ORG").await.unwrap();
    assert_eq!(found.keys.len(), 1);
}

#[tokio::test]
async fn other_user_ids_are_not_shown() {
    let (_s, net) = vks(
        "/vks/v1/by-email/olivia@example.org",
        ok("fixtures/openpgp/olivia-two-uids.asc"),
    )
    .await;
    let found = lookup(&net, "olivia@example.org").await.unwrap();
    assert_eq!(found.keys.len(), 1);
    let k = &found.keys[0];
    let all = match &k.key {
        identity_core::PublicKey::OpenPgp(p) => p.user_ids.len(),
        other => panic!("{other:?}"),
    };
    assert_eq!(all, 1, "other user IDs are dropped from the summary");
    assert_eq!(k.shown_user_ids.len(), 1);
    assert!(k.shown_user_ids[0].has_email("olivia@example.org"));
}

#[tokio::test]
async fn mallory_served_for_alice_is_rejected() {
    let (_s, net) = vks(ALICE, ok("fixtures/openpgp/mallory-other.asc")).await;
    let found = lookup(&net, "alice@example.org").await.unwrap();
    assert!(found.keys.is_empty());
    assert_eq!(found.rejected.len(), 1);
    let r = &found.rejected[0];
    assert_eq!(r.reason, RejectReason::EmailMismatch);
    assert!(matches!(r.fingerprint, Some(Fingerprint::OpenPgp(_))));
}

#[tokio::test]
async fn concatenated_keys_keep_only_the_match() {
    let (_s, net) = vks(ALICE, ok("fixtures/openpgp/alice-mallory.gpg")).await;
    let found = lookup(&net, "alice@example.org").await.unwrap();
    assert_eq!(found.keys.len(), 1);
    assert_eq!(found.rejected.len(), 1);
    assert_eq!(found.rejected[0].reason, RejectReason::EmailMismatch);
    assert_ne!(
        Some(found.keys[0].fingerprint()),
        found.rejected[0].fingerprint
    );
}

#[tokio::test]
async fn revoked_user_id_does_not_match() {
    let (_s, net) = vks(
        "/vks/v1/by-email/rita@example.org",
        ok("fixtures/openpgp/rita-revoked-uid.asc"),
    )
    .await;
    let found = lookup(&net, "rita@example.org").await.unwrap();
    assert!(found.keys.is_empty());
    assert_eq!(found.rejected[0].reason, RejectReason::EmailMismatch);
}

#[tokio::test]
async fn not_found_is_not_found() {
    let (_s, net) = vks(ALICE, ResponseTemplate::new(404)).await;
    assert_eq!(
        lookup(&net, "alice@example.org").await,
        Err(SourceError::NotFound)
    );
}

#[tokio::test]
async fn rate_limited_with_retry_after() {
    let (_s, net) = vks(
        ALICE,
        ResponseTemplate::new(429).insert_header("retry-after", "60"),
    )
    .await;
    assert_eq!(
        lookup(&net, "alice@example.org").await,
        Err(SourceError::RateLimited {
            retry_after: Some(Duration::from_secs(60))
        })
    );
}

#[tokio::test]
async fn junk_html_and_empty_armor_are_malformed() {
    for rel in [
        "mock-sources/junk.bin",
        "mock-sources/not-found.html",
        "mock-sources/github-empty.gpg",
        "mock-sources/broken-armor.asc",
    ] {
        let (_s, net) = vks(ALICE, ok(rel)).await;
        assert!(
            matches!(
                lookup(&net, "alice@example.org").await,
                Err(SourceError::Malformed(_))
            ),
            "{rel}"
        );
    }
}

#[tokio::test]
async fn oversized_is_too_large() {
    let (_s, net) = vks(
        ALICE,
        ResponseTemplate::new(200).set_body_bytes(vec![b'a'; 1_000_001]),
    )
    .await;
    assert_eq!(
        lookup(&net, "alice@example.org").await,
        Err(SourceError::TooLarge)
    );
}

#[tokio::test]
async fn slow_answer_times_out() {
    let (_s, net) = vks(
        ALICE,
        ok("fixtures/openpgp/alice.asc").set_delay(Duration::from_secs(2)),
    )
    .await;
    let q = parse_query("alice@example.org").unwrap();
    let deadline = Instant::now() + Duration::from_millis(300);
    assert_eq!(
        VksSource.lookup(&q, Some(&net), deadline).await,
        Err(SourceError::Timeout)
    );
}

#[tokio::test]
async fn accepts_only_email_and_needs_a_net() {
    let mail = parse_query("alice@example.org").unwrap();
    assert!(VksSource.accepts(&mail));
    assert!(!VksSource.accepts(&parse_query("github:alice").unwrap()));
    assert!(!VksSource.accepts(&parse_query("alice").unwrap()));
    assert!(matches!(
        VksSource.lookup(&mail, None, soon()).await,
        Err(SourceError::Net(_))
    ));
}
