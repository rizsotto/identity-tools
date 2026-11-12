//! Mock forge helpers: fixtures from `key-steward/tests/mock-forges`.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use identity_core::Fingerprint;
use providers::{
    InMemoryTokenSource, KeyRef, LocationKind, NetLog, Purpose, Target, Token, TokenKey,
};
use serde_json::Value;

pub const TOKEN: &str = "fake-TOKEN-0123456789abcdef";

pub fn fixture(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/mock-forges")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// `expected.json`: the fingerprints in each fixture file.
pub fn expected() -> Value {
    serde_json::from_str(&fixture("expected.json")).unwrap()
}

/// SSH fingerprints listed in `expected.json` for `file`.
pub fn ssh_fprs(file: &str) -> Vec<Fingerprint> {
    expected()[file]["ssh_sha256"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Fingerprint::Ssh(v.as_str().unwrap().to_string()))
        .collect()
}

/// The OpenPGP primary fingerprint listed in `expected.json` for `file`.
pub fn openpgp_fpr(file: &str) -> Fingerprint {
    Fingerprint::OpenPgp(
        expected()[file]["openpgp_primary"]
            .as_str()
            .unwrap()
            .to_string(),
    )
}

pub fn account(base_url: &str) -> Target {
    account_named(base_url, "testuser")
}

pub fn account_named(base_url: &str, name: &str) -> Target {
    Target::Account {
        base_url: base_url.into(),
        account: name.into(),
    }
}

/// A forge whose `GET <prefix>/user` names `login` in `field`, and that has
/// nothing else.
pub async fn owner_only(prefix: &str, field: &str, login: &str) -> wiremock::MockServer {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::path(format!("{prefix}/user")))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({ field: login })),
        )
        .mount(&server)
        .await;
    server
}

/// The target is another account than the token's owner: list and
/// verify give an error naming both, after only the `/user` request.
pub async fn assert_owner_mismatch<P: providers::Provider>(
    p: &P,
    target: &Target,
    log: &NetLog,
    key: &KeyRef,
) {
    let err = p.list(target).await.unwrap_err();
    assert!(
        matches!(&err, providers::ProviderError::TokenOwner { owner, account }
            if owner == "someoneelse" && account == "testuser"),
        "{err:?}"
    );
    let err = p.verify(target, key).await.unwrap_err();
    assert!(
        matches!(err, providers::ProviderError::TokenOwner { .. }),
        "{err:?}"
    );
    let entries = log.entries();
    assert_eq!(entries.len(), 2, "{}", log.render());
    assert!(
        entries.iter().all(|e| e.action.ends_with("/user")),
        "{}",
        log.render()
    );
    assert_no_token(log, &[err.to_string()]);
}

pub fn tokens(kind: LocationKind, target: &Target) -> Arc<InMemoryTokenSource> {
    let src = InMemoryTokenSource::new();
    src.insert(
        TokenKey::for_target(kind, target).unwrap(),
        Token::new(TOKEN),
    );
    Arc::new(src)
}

pub fn key(fingerprint: Fingerprint, purpose: Purpose) -> KeyRef {
    KeyRef {
        fingerprint,
        purpose,
        identity_file: None,
    }
}

/// The token must not be in the log or in any text we show.
pub fn assert_no_token(log: &NetLog, texts: &[String]) {
    assert!(!log.render().contains(TOKEN), "{}", log.render());
    for t in texts {
        assert!(!t.contains(TOKEN), "{t}");
    }
}
