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
    Target::Account {
        base_url: base_url.into(),
        account: "testuser".into(),
    }
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
