//! Forge `add` and `remove` against the stateful fake forges.

mod common;

use common::*;
use identity_core::{PublicKey, SshPublicKey, parse_public_keys};
use providers::{
    AddOpts, GitHub, LocationKind, NetLog, OpenPgpReader, Provider, ProviderError, Purpose,
    RemoveOpts, Target, VerifyStatus,
};
use test_support::{FakeForge, Fault, FaultOn, Flavour, KeyList, TempGnupgHome};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const NEW_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAMl5AYo+0XU3NureorqVJl9BQCzJ/7O6oQuY+n0zaV+ new@test";
const NEW_BLOB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAMl5AYo+0XU3NureorqVJl9BQCzJ/7O6oQuY+n0zaV+";

fn new_key() -> PublicKey {
    let parsed = parse_public_keys(NEW_KEY.as_bytes()).unwrap();
    parsed.into_iter().next().unwrap().key.unwrap()
}

fn ssh(k: &PublicKey) -> &SshPublicKey {
    match k {
        PublicKey::Ssh(s) => s,
        _ => unreachable!(),
    }
}

fn add_opts(purpose: Purpose) -> AddOpts {
    AddOpts {
        purpose,
        title: None,
        like: None,
    }
}

fn remove_opts(purpose: Purpose) -> RemoveOpts {
    RemoveOpts {
        purpose,
        keep: None,
    }
}

async fn fake(flavour: Flavour) -> FakeForge {
    FakeForge::builder(flavour).token(TOKEN).start().await
}

fn github(api_url: &str, gnupg: &TempGnupgHome, log: &NetLog) -> (GitHub, Target) {
    let target = account("https://github.com");
    let p = GitHub::new(
        tokens(LocationKind::GitHub, &target),
        OpenPgpReader::with_home(gnupg.path()),
        log.clone(),
    )
    .with_api_url(api_url);
    (p, target)
}

/// `(method, path without query)` of the requests that change something.
fn writes(f: &FakeForge) -> Vec<(String, String)> {
    f.requests()
        .into_iter()
        .filter(|r| r.method == "POST" || r.method == "DELETE")
        .map(|r| (r.method, r.path))
        .collect()
}

fn count(f: &FakeForge, list: KeyList, blob: &str) -> usize {
    f.keys()
        .iter()
        .filter(|k| k.list == list && k.key == blob)
        .count()
}

/// Title made from the key comment and today's date, `YYYY-MM-DD`.
fn assert_default_title(title: &str, comment: &str) {
    let date = title
        .strip_prefix(comment)
        .and_then(|r| r.strip_prefix(' '))
        .unwrap_or_else(|| panic!("{title}"));
    let b = date.as_bytes();
    assert!(
        b.len() == 10
            && b[4] == b'-'
            && b[7] == b'-'
            && date.chars().filter(char::is_ascii_digit).count() == 8,
        "{title}"
    );
}

#[tokio::test]
async fn github_add_remove_against_fake() {
    let forge = fake(Flavour::GitHub).await;
    let gnupg = TempGnupgHome::new();
    let log = NetLog::new();
    let (p, target) = github(&forge.api_url(), &gnupg, &log);
    let key = new_key();
    let fpr = ssh(&key).fingerprint.clone();

    p.add(&target, &key, &add_opts(Purpose::SshAuth))
        .await
        .unwrap();
    // Owner check, then list, then the write.
    let reqs = forge.requests();
    assert_eq!(reqs[0].path, "/user", "{reqs:?}");
    assert_eq!(writes(&forge), [("POST".into(), "/user/keys".into())]);
    let added = forge
        .keys()
        .into_iter()
        .find(|k| k.key == NEW_BLOB)
        .unwrap();
    assert_eq!(added.list, KeyList::Auth);
    assert_default_title(&added.title, "new@test");
    let post = reqs.iter().find(|r| r.method == "POST").unwrap();
    let body = post.body.as_ref().unwrap();
    assert_eq!(body["key"], NEW_BLOB);
    assert_eq!(body["title"], added.title.as_str());
    assert_eq!(
        p.verify(&target, &common::key(fpr.clone(), Purpose::SshAuth))
            .await
            .unwrap(),
        VerifyStatus::Verified
    );

    // Already there: no second POST.
    p.add(&target, &key, &add_opts(Purpose::SshAuth))
        .await
        .unwrap();
    assert_eq!(writes(&forge).len(), 1);

    // Signing keys are separate objects.
    let opts = AddOpts {
        title: Some("sig-new".into()),
        ..add_opts(Purpose::SshSigning)
    };
    p.add(&target, &key, &opts).await.unwrap();
    assert_eq!(
        writes(&forge)[1],
        ("POST".into(), "/user/ssh_signing_keys".into())
    );
    let signing = forge
        .keys()
        .into_iter()
        .find(|k| k.list == KeyList::Signing && k.key == NEW_BLOB)
        .unwrap();
    assert_eq!(signing.title, "sig-new");

    // A taken title gets a number.
    p.remove(&target, &fpr, &remove_opts(Purpose::SshSigning))
        .await
        .unwrap();
    let dups = [
        forge.insert_key(KeyList::Auth, NEW_KEY, "sig-new", None),
        forge.insert_key(KeyList::Auth, NEW_KEY, "sig-new (2)", None),
    ];
    p.add(&target, &key, &opts).await.unwrap();
    let signing = forge
        .keys()
        .into_iter()
        .find(|k| k.list == KeyList::Signing && k.key == NEW_BLOB)
        .unwrap();
    assert_eq!(signing.title, "sig-new (3)");

    // Remove the auth objects only: by id, the signing key stays.
    let before = writes(&forge).len();
    p.remove(&target, &fpr, &remove_opts(Purpose::SshAuth))
        .await
        .unwrap();
    let w = writes(&forge);
    assert_eq!(w.len(), before + 3, "{w:?}");
    assert!(w[before..].iter().all(|(m, p)| m == "DELETE"
        && p.starts_with("/user/keys/")
        && (p != &format!("/user/keys/{}", signing.id))));
    for dup in dups {
        assert!(w.contains(&("DELETE".into(), format!("/user/keys/{dup}"))));
    }
    assert_eq!(count(&forge, KeyList::Auth, NEW_BLOB), 0);
    assert_eq!(count(&forge, KeyList::Signing, NEW_BLOB), 1);

    p.remove(&target, &fpr, &remove_opts(Purpose::SshSigning))
        .await
        .unwrap();
    assert_eq!(
        writes(&forge).last().unwrap(),
        &(
            "DELETE".to_string(),
            format!("/user/ssh_signing_keys/{}", signing.id)
        )
    );
    assert_eq!(count(&forge, KeyList::Signing, NEW_BLOB), 0);

    // Gone already: no DELETE.
    let before = writes(&forge).len();
    p.remove(&target, &fpr, &remove_opts(Purpose::SshAuth))
        .await
        .unwrap();
    assert_eq!(writes(&forge).len(), before);

    // Every write is logged, without the token.
    let r = log.render();
    assert!(r.contains("POST ") && r.contains("DELETE "), "{r}");
    assert_no_token(&log, &[]);
}

#[tokio::test]
async fn github_lost_response_no_duplicate() {
    let forge = fake(Flavour::GitHub).await;
    let gnupg = TempGnupgHome::new();
    let log = NetLog::new();
    let (p, target) = github(&forge.api_url(), &gnupg, &log);
    let key = new_key();
    let fpr = ssh(&key).fingerprint.clone();

    // Applied, answer lost: the list after the POST decides.
    forge.fail_next(FaultOn::Write, Fault::LoseResponse);
    p.add(&target, &key, &add_opts(Purpose::SshAuth))
        .await
        .unwrap();
    assert_eq!(writes(&forge).len(), 1);
    assert_eq!(count(&forge, KeyList::Auth, NEW_BLOB), 1);

    forge.fail_next(FaultOn::Write, Fault::CloseConnection { apply: true });
    p.add(&target, &key, &add_opts(Purpose::SshSigning))
        .await
        .unwrap();
    assert_eq!(writes(&forge).len(), 2);
    assert_eq!(count(&forge, KeyList::Signing, NEW_BLOB), 1);

    forge.fail_next(FaultOn::Write, Fault::LoseResponse);
    p.remove(&target, &fpr, &remove_opts(Purpose::SshAuth))
        .await
        .unwrap();
    assert_eq!(writes(&forge).len(), 3);
    assert_eq!(count(&forge, KeyList::Auth, NEW_BLOB), 0);

    // Not applied: an error, and no second try.
    forge.fail_next(FaultOn::Write, Fault::Status(500));
    let err = p
        .add(&target, &key, &add_opts(Purpose::SshAuth))
        .await
        .unwrap_err();
    assert!(
        matches!(err, ProviderError::WriteFailed { status: 500, .. }),
        "{err:?}"
    );
    assert_eq!(writes(&forge).len(), 4);
    assert_eq!(count(&forge, KeyList::Auth, NEW_BLOB), 0);

    forge.fail_next(FaultOn::Write, Fault::CloseConnection { apply: false });
    let err = p
        .remove(&target, &fpr, &remove_opts(Purpose::SshSigning))
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::Http(_)), "{err:?}");
    assert_eq!(writes(&forge).len(), 5);
    assert_eq!(count(&forge, KeyList::Signing, NEW_BLOB), 1);

    // The run after the failure finds the state and finishes.
    p.remove(&target, &fpr, &remove_opts(Purpose::SshSigning))
        .await
        .unwrap();
    assert_eq!(count(&forge, KeyList::Signing, NEW_BLOB), 0);
    assert_no_token(&log, &[]);
}

/// A forge whose lists are empty and whose writes all answer `status`
/// with the token in the body.
async fn echo_forge(status: u16) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "login": "testuser" })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(status)
                .insert_header("location", format!("https://evil.example/?t={TOKEN}"))
                .set_body_json(serde_json::json!({ "message": format!("token {TOKEN} bad") })),
        )
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn github_write_errors_hold_no_token() {
    let forge = fake(Flavour::GitHub).await;
    let gnupg = TempGnupgHome::new();
    let log = NetLog::new();
    let (p, target) = github(&forge.api_url(), &gnupg, &log);
    let key = new_key();
    let fpr = ssh(&key).fingerprint.clone();
    let mut texts = Vec::new();

    // 401 and 403: advice on the scopes, nothing written.
    let cases = [
        (401, Purpose::SshAuth, "write:public_key"),
        (403, Purpose::SshAuth, "write:public_key"),
        (403, Purpose::SshSigning, "write:ssh_signing_key"),
    ];
    for (status, purpose, scope) in cases {
        forge.fail_next(FaultOn::Write, Fault::Status(status));
        let err = p.add(&target, &key, &add_opts(purpose)).await.unwrap_err();
        assert!(
            matches!(&err, ProviderError::Denied { status: s, advice, .. }
                if *s == status && advice.contains(scope)),
            "{err:?}"
        );
        texts.push(err.to_string());
        texts.push(format!("{err:?}"));
    }
    assert_eq!(count(&forge, KeyList::Auth, NEW_BLOB), 0);

    p.add(&target, &key, &add_opts(Purpose::SshAuth))
        .await
        .unwrap();
    p.add(&target, &key, &add_opts(Purpose::SshSigning))
        .await
        .unwrap();
    for (purpose, scope) in [
        (Purpose::SshAuth, "admin:public_key"),
        (Purpose::SshSigning, "admin:ssh_signing_key"),
    ] {
        forge.fail_next(FaultOn::Write, Fault::Status(403));
        let err = p
            .remove(&target, &fpr, &remove_opts(purpose))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ProviderError::Denied { advice, .. } if advice.contains(scope)),
            "{err:?}"
        );
        texts.push(err.to_string());
    }
    assert_eq!(count(&forge, KeyList::Auth, NEW_BLOB), 1);

    // Only SSH keys for SSH purposes; refused before any request.
    let before = forge.requests().len();
    let err = p
        .add(&target, &key, &add_opts(Purpose::OpenPgp))
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::Unsupported(_)), "{err:?}");
    let err = p
        .remove(&target, &fpr, &remove_opts(Purpose::OpenPgp))
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::Unsupported(_)), "{err:?}");
    assert_eq!(forge.requests().len(), before);

    // The token's owner is another account: no write.
    let other = FakeForge::builder(Flavour::GitHub)
        .token(TOKEN)
        .login("someoneelse")
        .start()
        .await;
    let (q, _) = github(&other.api_url(), &gnupg, &log);
    let err = q
        .add(&target, &key, &add_opts(Purpose::SshAuth))
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::TokenOwner { .. }), "{err:?}");
    assert!(writes(&other).is_empty());

    // The forge's message is shown, scrubbed. A 3xx is never success.
    for status in [422, 302, 200] {
        let server = echo_forge(status).await;
        let (q, _) = github(&server.uri(), &gnupg, &log);
        let err = q
            .add(&target, &key, &add_opts(Purpose::SshAuth))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ProviderError::WriteFailed { status: s, .. } if *s == status),
            "{err:?}"
        );
        if status == 422 {
            assert!(err.to_string().contains("[redacted]"), "{err}");
        }
        texts.push(err.to_string());
        texts.push(format!("{err:?}"));
    }
    assert_no_token(&log, &texts);
}
