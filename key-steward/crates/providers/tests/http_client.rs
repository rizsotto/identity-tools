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

#[tokio::test]
async fn post_and_delete_are_logged_and_scrubbed() {
    let server = MockServer::start().await;
    let sent = serde_json::json!({ "title": "laptop", "key": "ssh-ed25519 AAAA" });
    Mock::given(method("POST"))
        .and(path("/user/keys"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .and(header("content-type", "application/json"))
        .and(wiremock::matchers::body_json(&sent))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({ "id": 7 })))
        .expect(1)
        .mount(&server)
        .await;
    // Error answers that echo the token, in JSON and in plain text.
    Mock::given(method("POST"))
        .and(path("/echo"))
        .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
            "message": "Validation failed",
            "errors": [{ "message": format!("bad {TOKEN}") }],
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/user/keys/7"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/user/keys/8"))
        .respond_with(ResponseTemplate::new(404).set_body_string(format!("no {TOKEN} here")))
        .mount(&server)
        .await;

    let log = NetLog::new();
    let c = client(&server.uri(), AuthStyle::Bearer, &log);
    let r = c.post_json("/user/keys", &sent).await.unwrap();
    assert_eq!(r.status, 201);
    assert_eq!(r.body["id"], 7);
    let r = c.post_json("/echo", &sent).await.unwrap();
    assert_eq!(r.status, 422);
    assert_eq!(r.body["message"], "Validation failed");
    let echoed = r.body.to_string();
    assert!(!echoed.contains(TOKEN), "{echoed}");
    assert!(echoed.contains("[redacted]"), "{echoed}");
    let r = c.delete("/user/keys/7").await.unwrap();
    assert_eq!((r.status, &r.body), (204, &serde_json::Value::Null));
    let r = c.delete("/user/keys/8").await.unwrap();
    assert_eq!(r.status, 404);
    assert_eq!(r.body, serde_json::json!("no [redacted] here"));
    // A token in the path (a caller mistake) and a connection error.
    let r = c.delete(&format!("/user/keys/{TOKEN}")).await.unwrap();
    assert_eq!(r.status, 404);
    // wiremock keeps dropped servers in a pool, so use a closed port.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_url = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let err = client(&closed_url, AuthStyle::Bearer, &log)
        .post_json(&format!("/x?t={TOKEN}"), &sent)
        .await
        .unwrap_err();
    for text in [err.to_string(), format!("{err:?}")] {
        assert!(!text.contains(TOKEN), "token in error: {text}");
    }

    let entries = log.entries();
    let lines: Vec<(&str, &str)> = entries
        .iter()
        .map(|e| (e.action.as_str(), e.outcome.as_str()))
        .collect();
    assert_eq!(lines.len(), 6, "{lines:?}");
    assert!(lines[0].0.starts_with("POST ") && lines[0].0.ends_with("/user/keys"));
    assert_eq!(lines[0].1, "HTTP 201");
    assert_eq!(lines[1].1, "HTTP 422");
    assert!(lines[2].0.starts_with("DELETE ") && lines[2].0.ends_with("/user/keys/7"));
    assert_eq!(lines[2].1, "HTTP 204");
    assert_eq!(lines[3].1, "HTTP 404");
    assert!(
        lines[4].0.ends_with("/user/keys/[redacted]"),
        "{}",
        lines[4].0
    );
    assert!(lines[5].0.starts_with("POST "));
    let rendered = log.render();
    assert!(!rendered.contains(TOKEN), "token in log: {rendered}");
    // The body is not logged: it holds the key, which the log does not need.
    assert!(!rendered.contains("ssh-ed25519"), "{rendered}");
}

#[tokio::test]
async fn long_text_reply_is_scrubbed_before_it_is_cut() {
    let server = MockServer::start().await;
    // The token starts at char 995, across the 1000 char cut.
    let text = format!("{}{TOKEN} tail", "x".repeat(995));
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(500).set_body_string(text))
        .mount(&server)
        .await;
    let r = client(&server.uri(), AuthStyle::Bearer, &NetLog::new())
        .delete("/user/keys/1")
        .await
        .unwrap();
    let body = r.body.as_str().unwrap();
    assert!(!body.contains(&TOKEN[..5]), "token part in reply: {body}");
    assert!(body.ends_with("[reda"), "{body}");
    assert!(body.chars().count() <= 1000);
    assert!(!r.is_success());
}

#[test]
fn only_2xx_is_success() {
    let reply = |status| providers::HttpReply {
        status,
        body: serde_json::Value::Null,
    };
    assert!(reply(201).is_success());
    assert!(reply(204).is_success());
    for s in [199, 301, 302, 304, 404, 422, 500] {
        assert!(!reply(s).is_success(), "{s}");
    }
}
