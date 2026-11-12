//! HTTP layer against loopback mock servers only (plan.md "Mock endpoints").

use std::net::SocketAddr;
use std::time::Duration;

use resolver::{Net, NetError, OriginMap, ResolverConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::Instant;
use url::Url;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MAX: usize = 1_000_000;

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

fn url(s: &str) -> Url {
    Url::parse(s).unwrap()
}

async fn serve(status: u16, body: &[u8]) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(status).set_body_bytes(body.to_vec()))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn get_200_returns_body_and_logs() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/alice.keys"))
        .and(header(
            "user-agent",
            concat!("send-secret/", env!("CARGO_PKG_VERSION")),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string("ssh-ed25519 AAAA\n"))
        .expect(1)
        .mount(&server)
        .await;
    let net = net(&[("https://github.com", *server.address())]);
    let got = net
        .get(&url("https://github.com/alice.keys"), soon())
        .await
        .unwrap();
    assert_eq!(got.body, b"ssh-ed25519 AAAA\n");
    assert_eq!(got.url.as_str(), "https://github.com/alice.keys");
    assert_eq!(got.first_url, got.url);
    let log = net.log().entries();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].action, "GET https://github.com/alice.keys");
    assert_eq!(log[0].outcome, "HTTP 200, 17 bytes");
    assert!(!net.log().render().contains("AAAA"));
}

#[tokio::test]
async fn get_404_is_not_found() {
    let server = serve(404, b"no such user").await;
    let net = net(&[("https://github.com", *server.address())]);
    let err = net
        .get(&url("https://github.com/nobody.keys"), soon())
        .await
        .unwrap_err();
    assert_eq!(err, NetError::NotFound);
    assert_eq!(net.log().entries()[0].outcome, "not found (HTTP 404)");
}

#[tokio::test]
async fn get_401_is_an_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).insert_header("www-authenticate", "Basic"))
        .mount(&server)
        .await;
    let net = net(&[("https://example.org", *server.address())]);
    let err = net
        .get(&url("https://example.org/k"), soon())
        .await
        .unwrap_err();
    assert_eq!(err, NetError::LoginRequired);
}

#[tokio::test]
async fn get_500_is_http_error_without_body() {
    let server = serve(500, b"SECRET-BODY-TEXT").await;
    let net = net(&[("https://example.org", *server.address())]);
    let err = net
        .get(&url("https://example.org/k"), soon())
        .await
        .unwrap_err();
    assert_eq!(err, NetError::Http(500));
    assert!(!net.log().render().contains("SECRET"));
}

#[tokio::test]
async fn slow_answer_times_out() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("late")
                .set_delay(Duration::from_secs(2)),
        )
        .mount(&server)
        .await;
    let net = net(&[("https://example.org", *server.address())]);
    let start = Instant::now();
    let err = net
        .get(
            &url("https://example.org/k"),
            Instant::now() + cfg().source_timeout,
        )
        .await
        .unwrap_err();
    assert_eq!(err, NetError::Timeout);
    assert!(start.elapsed() < Duration::from_millis(1500));
    assert_eq!(net.log().entries()[0].outcome, "timed out");
}

#[tokio::test]
async fn oversized_with_content_length_refused() {
    let server = serve(200, &vec![b'a'; MAX + 1]).await;
    let net = net(&[("https://example.org", *server.address())]);
    let err = net
        .get(&url("https://example.org/k"), soon())
        .await
        .unwrap_err();
    assert_eq!(err, NetError::TooLarge);
}

#[tokio::test]
async fn exactly_max_bytes_accepted() {
    let server = serve(200, &vec![b'a'; MAX]).await;
    let net = net(&[("https://example.org", *server.address())]);
    let got = net
        .get(&url("https://example.org/k"), soon())
        .await
        .unwrap();
    assert_eq!(got.body.len(), MAX);
}

/// A raw server that sends `len` bytes with no Content-Length (body ends
/// when the connection closes). wiremock always sets Content-Length.
async fn raw_server(len: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf).await;
        let _ = sock
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            .await;
        let chunk = vec![b'a'; 64 * 1024];
        let mut left = len;
        while left > 0 {
            let n = left.min(chunk.len());
            if sock.write_all(&chunk[..n]).await.is_err() {
                return;
            }
            left -= n;
        }
        let _ = sock.shutdown().await;
    });
    addr
}

#[tokio::test]
async fn oversized_without_content_length_refused() {
    let addr = raw_server(MAX + 1).await;
    let net = net(&[("https://example.org", addr)]);
    let err = net
        .get(&url("https://example.org/k"), soon())
        .await
        .unwrap_err();
    assert_eq!(err, NetError::TooLarge);
}

#[tokio::test]
async fn streamed_body_under_limit_accepted() {
    let addr = raw_server(1000).await;
    let net = net(&[("https://example.org", addr)]);
    let got = net
        .get(&url("https://example.org/k"), soon())
        .await
        .unwrap();
    assert_eq!(got.body.len(), 1000);
}

#[tokio::test]
async fn redirect_to_https_followed_and_logged() {
    let a = MockServer::start().await;
    let b = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://b.example.org/rel"),
        )
        .expect(1)
        .mount(&a)
        .await;
    Mock::given(method("GET"))
        .and(path("/rel"))
        .respond_with(ResponseTemplate::new(301).insert_header("location", "/key?x=1"))
        .expect(1)
        .mount(&b)
        .await;
    Mock::given(method("GET"))
        .and(path("/key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("KEY"))
        .expect(1)
        .mount(&b)
        .await;
    let net = net(&[
        ("https://a.example.org", *a.address()),
        ("https://b.example.org", *b.address()),
    ]);
    let got = net
        .get(&url("https://a.example.org/start"), soon())
        .await
        .unwrap();
    assert_eq!(got.body, b"KEY");
    assert_eq!(got.first_url.as_str(), "https://a.example.org/start");
    assert_eq!(got.url.as_str(), "https://b.example.org/key?x=1");
    let log: Vec<_> = net
        .log()
        .entries()
        .into_iter()
        .map(|e| format!("{} -> {}", e.action, e.outcome))
        .collect();
    assert_eq!(
        log,
        [
            "GET https://a.example.org/start -> HTTP 302, redirect to https://b.example.org/rel",
            "GET https://b.example.org/rel -> HTTP 301, redirect to https://b.example.org/key?x=1",
            "GET https://b.example.org/key?x=1 -> HTTP 200, 3 bytes",
        ]
    );
}

#[tokio::test]
async fn redirect_to_http_refused() {
    let a = MockServer::start().await;
    let b = serve(200, b"KEY").await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "http://b.example.org/k"),
        )
        .mount(&a)
        .await;
    let net = net(&[
        ("https://a.example.org", *a.address()),
        ("https://b.example.org", *b.address()),
    ]);
    let err = net
        .get(&url("https://a.example.org/k"), soon())
        .await
        .unwrap_err();
    assert!(matches!(err, NetError::NotHttps(_)), "{err:?}");
    assert!(b.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn redirect_without_location_is_an_error() {
    let a = serve(302, b"").await;
    let net = net(&[("https://a.example.org", *a.address())]);
    let err = net
        .get(&url("https://a.example.org/k"), soon())
        .await
        .unwrap_err();
    assert_eq!(err, NetError::BadRedirect);
}

#[tokio::test]
async fn redirect_loop_stops_at_5() {
    let a = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://a.example.org/loop"),
        )
        .mount(&a)
        .await;
    let net = net(&[("https://a.example.org", *a.address())]);
    let err = net
        .get(&url("https://a.example.org/loop"), soon())
        .await
        .unwrap_err();
    assert_eq!(err, NetError::TooManyRedirects(5));
    assert_eq!(a.received_requests().await.unwrap().len(), 6);
    assert_eq!(net.log().len(), 6);
}

#[tokio::test]
async fn non_loopback_mock_target_refused() {
    let mut map = OriginMap::new();
    map.insert("https://example.org", "10.0.0.1:80".parse().unwrap())
        .unwrap();
    let err = Net::with_mock_origins(&cfg(), map).unwrap_err();
    assert!(matches!(err, NetError::Setup(_)), "{err:?}");

    let mut map = OriginMap::new();
    map.insert("https://example.org", "[::1]:80".parse().unwrap())
        .unwrap();
    assert!(Net::with_mock_origins(&cfg(), map).is_ok());
}

#[tokio::test]
async fn unmapped_host_fails_without_connection() {
    let mapped = serve(200, b"KEY").await;
    let net = net(&[("https://mapped.example.org", *mapped.address())]);
    for u in [
        "https://unmapped.example.org/k",
        "https://mapped.example.org:8443/k",
    ] {
        let err = net.get(&url(u), soon()).await.unwrap_err();
        assert!(matches!(err, NetError::Unmapped(_)), "{u}: {err:?}");
    }
    assert!(mapped.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn plain_http_url_refused() {
    let server = serve(200, b"KEY").await;
    let net = net(&[("https://example.org", *server.address())]);
    let err = net
        .get(&url("http://example.org/k"), soon())
        .await
        .unwrap_err();
    assert!(matches!(err, NetError::NotHttps(_)), "{err:?}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn mock_map_answers_dns_check() {
    let server = serve(200, b"").await;
    let net = net(&[("https://openpgpkey.example.org", *server.address())]);
    assert!(
        net.host_has_address("openpgpkey.example.org", soon())
            .await
            .unwrap()
    );
    assert!(
        net.host_has_address("OpenPGPKey.Example.org", soon())
            .await
            .unwrap()
    );
    assert!(
        !net.host_has_address("openpgpkey.example.net", soon())
            .await
            .unwrap()
    );
    let log: Vec<_> = net
        .log()
        .entries()
        .into_iter()
        .map(|e| format!("{} -> {}", e.action, e.outcome))
        .collect();
    assert_eq!(
        log,
        [
            "DNS openpgpkey.example.org -> has an address",
            "DNS openpgpkey.example.org -> has an address",
            "DNS openpgpkey.example.net -> no address",
        ]
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn rate_limit_429_with_retry_after() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "120"))
        .mount(&server)
        .await;
    let net = net(&[("https://keys.openpgp.org", *server.address())]);
    let err = net
        .get(&url("https://keys.openpgp.org/vks/v1/by-email/a"), soon())
        .await
        .unwrap_err();
    assert_eq!(
        err,
        NetError::RateLimited {
            retry_after: Some(Duration::from_secs(120))
        }
    );
    assert!(err.to_string().contains("try again in 120 s"), "{err}");
}

#[tokio::test]
async fn rate_limit_429_without_retry_after() {
    let server = serve(429, b"slow down").await;
    let net = net(&[("https://keys.openpgp.org", *server.address())]);
    let err = net
        .get(&url("https://keys.openpgp.org/vks/v1/by-email/a"), soon())
        .await
        .unwrap_err();
    assert_eq!(err, NetError::RateLimited { retry_after: None });
}

#[tokio::test]
async fn cooldown_skips_host_and_says_so() {
    let limited = serve(429, b"").await;
    let other = serve(200, b"KEY").await;
    let net = net(&[
        ("https://keys.openpgp.org", *limited.address()),
        ("https://github.com", *other.address()),
    ]);
    let u = url("https://keys.openpgp.org/vks/v1/by-email/a");
    assert!(matches!(
        net.get(&u, soon()).await,
        Err(NetError::RateLimited { .. })
    ));
    let err = net
        .get(&url("https://keys.openpgp.org/other"), soon())
        .await
        .unwrap_err();
    match &err {
        NetError::CoolingDown { host, wait } => {
            assert_eq!(host, "keys.openpgp.org");
            assert!(*wait > Duration::from_secs(50), "{wait:?}");
        }
        e => panic!("not a cooldown: {e:?}"),
    }
    assert_eq!(limited.received_requests().await.unwrap().len(), 1);
    let log = net.log().entries();
    assert_eq!(log.len(), 2);
    assert!(
        log[1]
            .outcome
            .starts_with("skipped: keys.openpgp.org rate limited us"),
        "{}",
        log[1].outcome
    );
    // Other hosts are not affected.
    assert!(
        net.get(&url("https://github.com/alice.keys"), soon())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn cooldown_ends_after_retry_after() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("KEY"))
        .mount(&server)
        .await;
    let net = net(&[("https://example.org", *server.address())]);
    let u = url("https://example.org/k");
    assert!(net.get(&u, soon()).await.is_err());
    assert_eq!(net.get(&u, soon()).await.unwrap().body, b"KEY");
}

#[tokio::test]
async fn github_403_with_ratelimit_remaining_0() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("x-ratelimit-remaining", "0")
                .insert_header("retry-after", "30"),
        )
        .mount(&server)
        .await;
    let net = net(&[("https://github.com", *server.address())]);
    let err = net
        .get(&url("https://github.com/alice.keys"), soon())
        .await
        .unwrap_err();
    assert_eq!(
        err,
        NetError::RateLimited {
            retry_after: Some(Duration::from_secs(30))
        }
    );
}

#[tokio::test]
async fn plain_403_is_http_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403).insert_header("x-ratelimit-remaining", "12"))
        .mount(&server)
        .await;
    let net = net(&[("https://github.com", *server.address())]);
    let err = net
        .get(&url("https://github.com/alice.keys"), soon())
        .await
        .unwrap_err();
    assert_eq!(err, NetError::Http(403));
}
