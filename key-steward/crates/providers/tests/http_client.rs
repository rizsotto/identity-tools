//! Shared HTTP client against wiremock with the mock forge fixtures.

use std::path::PathBuf;

use providers::{AuthStyle, HttpClient, LocationKind, NetLog, ProviderError, Target, Token};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "ghp_FAKE0123456789abcdefTOKEN";

fn fixture(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/mock-forges")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn target() -> Target {
    Target::Account {
        base_url: "mock".into(),
        account: "octocat".into(),
    }
}

fn client(base: &str, auth: AuthStyle, log: &NetLog) -> HttpClient {
    HttpClient::new(
        LocationKind::GitHub,
        &target(),
        base,
        auth,
        Some(Token::new(TOKEN)),
        &[("x-github-api-version", "2026-03-10")],
        log.clone(),
    )
    .unwrap()
}

#[tokio::test]
async fn follows_next_links_and_sends_headers() {
    let server = MockServer::start().await;
    let next = format!(
        "<{}/user/keys?page=2&per_page=100>; rel=\"next\", <{}/user/keys?page=2&per_page=100>; rel=\"last\"",
        server.uri(),
        server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/user/keys"))
        .and(query_param("page", "2"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("github/user_keys_page2.json"), "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/keys"))
        .and(query_param("per_page", "100"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .and(header("x-github-api-version", "2026-03-10"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", next.as_str())
                .set_body_raw(fixture("github/user_keys.json"), "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let log = NetLog::new();
    let items = client(&server.uri(), AuthStyle::Bearer, &log)
        .get_all_pages("/user/keys?per_page=100")
        .await
        .unwrap();
    let ids: Vec<i64> = items.iter().map(|k| k["id"].as_i64().unwrap()).collect();
    assert_eq!(ids.len(), 3, "{ids:?}");
    assert_eq!(&ids[..2], &[101, 102]);

    let entries = log.entries();
    assert_eq!(entries.len(), 2);
    assert!(
        entries[0].action.starts_with("GET "),
        "{}",
        entries[0].action
    );
    assert!(entries[0].action.contains("/user/keys?per_page=100"));
    assert_eq!(entries[0].outcome, "HTTP 200, more pages");
    assert!(entries[1].action.contains("page=2"));
    assert_eq!(entries[1].outcome, "HTTP 200");
    assert_eq!(entries[0].target, "octocat at mock");
}

#[tokio::test]
async fn auth_header_styles() {
    let server = MockServer::start().await;
    Mock::given(path("/gl"))
        .and(header("private-token", TOKEN))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("gitlab/user_keys.json"), "application/json"),
        )
        .mount(&server)
        .await;
    Mock::given(path("/fj"))
        .and(header("authorization", format!("token {TOKEN}").as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(fixture("forgejo/user_keys.json"), "application/json"),
        )
        .mount(&server)
        .await;
    let log = NetLog::new();
    let gl = client(&server.uri(), AuthStyle::PrivateToken, &log)
        .get_json("/gl")
        .await
        .unwrap();
    assert!(gl.is_array());
    let fj = client(&server.uri(), AuthStyle::TokenPrefix, &log)
        .get_json("/fj")
        .await
        .unwrap();
    assert!(fj.is_array());
}

#[tokio::test]
async fn next_link_to_other_origin_is_refused() {
    let server = MockServer::start().await;
    let evil = MockServer::start().await;
    Mock::given(path("/user/keys"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "link",
                    format!("<{}/steal>; rel=\"next\"", evil.uri()).as_str(),
                )
                .set_body_raw("[]", "application/json"),
        )
        .mount(&server)
        .await;
    Mock::given(path("/steal"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("[]", "application/json"))
        .expect(0)
        .mount(&evil)
        .await;
    let log = NetLog::new();
    let err = client(&server.uri(), AuthStyle::Bearer, &log)
        .get_all_pages("/user/keys")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("refused"), "{err}");
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let server = MockServer::start().await;
    let evil = MockServer::start().await;
    Mock::given(path("/user/keys"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/steal", evil.uri()).as_str()),
        )
        .mount(&server)
        .await;
    Mock::given(path("/steal"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("[]", "application/json"))
        .expect(0)
        .mount(&evil)
        .await;
    let err = client(&server.uri(), AuthStyle::PrivateToken, &NetLog::new())
        .get_all_pages("/user/keys")
        .await
        .unwrap_err();
    assert!(
        matches!(err, ProviderError::HttpStatus { status: 302, .. }),
        "{err}"
    );
}

#[tokio::test]
async fn token_never_in_error_or_log() {
    let server = MockServer::start().await;
    // A server that echoes the token back, in a header and the body.
    Mock::given(path("/echo"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("x-echo", TOKEN)
                .set_body_string(format!("bad token {TOKEN}")),
        )
        .mount(&server)
        .await;
    Mock::given(path("/notjson"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("<html>{TOKEN}</html>")))
        .mount(&server)
        .await;

    let log = NetLog::new();
    let c = client(&server.uri(), AuthStyle::Bearer, &log);
    let mut errors = Vec::new();
    errors.push(c.get_json("/echo").await.unwrap_err());
    errors.push(c.get_json("/notjson").await.unwrap_err());
    // The token in the URL itself (a caller mistake) is scrubbed too.
    errors.push(
        c.get_json(&format!("/echo?access_token={TOKEN}"))
            .await
            .unwrap_err(),
    );
    errors.push(c.get_json(&format!("/{TOKEN}")).await.unwrap_err());
    // Connection errors name the URL.
    drop(server);
    errors.push(c.get_json(&format!("/x?t={TOKEN}")).await.unwrap_err());

    for e in &errors {
        for text in [e.to_string(), format!("{e:?}")] {
            assert!(!text.contains(TOKEN), "token in error: {text}");
        }
    }
    assert_eq!(log.entries().len(), errors.len());
    let rendered = log.render();
    assert!(!rendered.contains(TOKEN), "token in log: {rendered}");
    assert!(rendered.contains("[redacted]"), "{rendered}");
    assert!(rendered.contains("HTTP 401"), "{rendered}");
    assert!(!format!("{c:?}").contains(TOKEN), "token in client Debug");
}
