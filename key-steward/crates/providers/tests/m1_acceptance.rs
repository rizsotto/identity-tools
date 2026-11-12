//! M1 acceptance (T19): the whole read-only inventory, end to end.
//!
//! A temp `HOME` with SSH keys and an ssh config, a temp `GNUPGHOME`, two
//! test sshd processes and wiremock forges serving the fixtures in
//! `key-steward/tests/mock-forges` (plus the test's own keys). Then
//! `KeyList`, the ssh config import and the `CheckRunner` must give the
//! FR-1 rows and the right status for every location. No real home, no
//! real server, no network beyond 127.0.0.1.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64ct::{Base64, Encoding};
use common::{TOKEN, fixture};
use identity_core::{Fingerprint, Gpg, KeyAlgo, KeyKind, Severity, WeakReason};
use inventory::{
    Created, ImportOptions, KeyList, KeyRow, KeySource, KnownKey, Location, LocationKind,
    NewLocation, Purpose, Status, Store, Target, host_aliases, import_ssh_config,
};
use providers::{
    CheckOutcome, CheckRunner, Forgejo, GitHub, GitLab, InMemoryTokenSource, NetLog, OpenPgpReader,
    SshServer, Token, TokenKey,
};
use serde_json::{Value, json};
use test_support::{Sshd, TempGnupgHome, TempHome, check_not_real_home, current_user};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BASE: &str = env!("CARGO_TARGET_TMPDIR");

fn run(cmd: &mut Command) -> Vec<u8> {
    let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(
        out.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn keygen(home: &TempHome, name: &str, args: &[&str]) -> PathBuf {
    let path = home.ssh_dir().join(name);
    let mut cmd = Command::new("ssh-keygen");
    home.apply(&mut cmd)
        .args(["-q", "-f"])
        .arg(&path)
        .args(args);
    run(&mut cmd);
    path
}

fn gpg(home: &TempGnupgHome, args: &[&str]) -> Vec<u8> {
    let mut cmd = Command::new("gpg");
    home.apply(&mut cmd)
        .args(["--batch", "--quiet", "--pinentry-mode", "loopback"])
        .args(["--passphrase", ""])
        .args(args);
    run(&mut cmd)
}

/// The first OpenPGP packet (the primary public key) of `gpg --export`.
/// Forgejo returns this packet alone, base64 encoded (SPEC 15, fact 1).
fn first_packet(data: &[u8]) -> &[u8] {
    let b0 = data[0];
    assert!(b0 & 0x80 != 0, "not an OpenPGP packet");
    let (header, len) = if b0 & 0x40 != 0 {
        match data[1] {
            o @ 0..192 => (2, o as usize),
            o @ 192..224 => (3, ((o as usize - 192) << 8) + data[2] as usize + 192),
            255 => (
                6,
                u32::from_be_bytes(data[2..6].try_into().unwrap()) as usize,
            ),
            o => panic!("partial length {o}"),
        }
    } else {
        match b0 & 3 {
            0 => (2, data[1] as usize),
            1 => (3, u16::from_be_bytes([data[1], data[2]]) as usize),
            2 => (
                5,
                u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize,
            ),
            _ => panic!("indeterminate length"),
        }
    };
    &data[..header + len]
}

fn public_line(private: &Path) -> String {
    let mut p = private.as_os_str().to_owned();
    p.push(".pub");
    let text = fs::read_to_string(p).unwrap();
    let mut f = text.split_whitespace();
    format!("{} {}", f.next().unwrap(), f.next().unwrap())
}

/// A fixture list with `extra` appended, each made from the fixture's
/// first item so the shape stays the forge's.
fn fixture_plus(name: &str, extra: &[Value]) -> String {
    let mut list: Vec<Value> = serde_json::from_str(&fixture(name)).unwrap();
    let template = list[0].clone();
    for e in extra {
        let mut item = template.clone();
        for (k, v) in e.as_object().unwrap() {
            item[k] = v.clone();
        }
        list.push(item);
    }
    serde_json::to_string(&list).unwrap()
}

fn json_body(body: String) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body, "application/json")
}

struct LocalKeys {
    ed_line: String,
    alice: String,
    alice_armored: String,
    alice_packet: String,
}

/// GitHub: our ed25519 key on page 2 of the auth keys, not in the signing
/// keys, and Alice's GPG key.
async fn mock_github(k: &LocalKeys) -> MockServer {
    let server = MockServer::start().await;
    let auth = format!("Bearer {TOKEN}");
    let get = |p: &str| {
        Mock::given(method("GET"))
            .and(path(p.to_string()))
            .and(header("authorization", auth.as_str()))
    };
    get("/user")
        .respond_with(json_body(fixture("github/user.json")))
        .mount(&server)
        .await;
    get("/user/keys")
        .and(query_param("page", "2"))
        .respond_with(json_body(fixture_plus(
            "github/user_keys_page2.json",
            &[json!({"id": 901, "key": k.ed_line, "title": "acceptance"})],
        )))
        .mount(&server)
        .await;
    let next = format!(
        "<{}/user/keys?per_page=100&page=2>; rel=\"next\"",
        server.uri()
    );
    get("/user/keys")
        .and(query_param("per_page", "100"))
        .respond_with(
            json_body(fixture("github/user_keys.json")).insert_header("link", next.as_str()),
        )
        .mount(&server)
        .await;
    get("/user/ssh_signing_keys")
        .respond_with(json_body(fixture("github/user_ssh_signing_keys.json")))
        .mount(&server)
        .await;
    let key_id = &k.alice[k.alice.len() - 16..];
    get("/user/gpg_keys")
        .respond_with(json_body(fixture_plus(
            "github/user_gpg_keys.json",
            &[json!({
                "id": 902, "name": "Alice", "key_id": key_id, "subkeys": [],
                "raw_key": k.alice_armored,
            })],
        )))
        .mount(&server)
        .await;
    server
}

/// Self-hosted GitLab under `/gitlab`: our ed25519 key for signing only,
/// and Alice's GPG key.
async fn mock_gitlab(k: &LocalKeys) -> MockServer {
    let server = MockServer::start().await;
    let get = |p: &str| {
        Mock::given(method("GET"))
            .and(path(format!("/gitlab/api/v4{p}")))
            .and(header("private-token", TOKEN))
    };
    get("/user")
        .respond_with(json_body(fixture("gitlab/user.json")))
        .mount(&server)
        .await;
    get("/user/keys")
        .and(query_param("page", "2"))
        .respond_with(
            json_body(fixture_plus(
                "gitlab/user_keys_page2.json",
                &[json!({"id": 903, "key": k.ed_line, "usage_type": "signing"})],
            ))
            .insert_header("x-next-page", ""),
        )
        .mount(&server)
        .await;
    get("/user/keys")
        .and(query_param("per_page", "100"))
        .respond_with(json_body(fixture("gitlab/user_keys.json")).insert_header("x-next-page", "2"))
        .mount(&server)
        .await;
    get("/user/gpg_keys")
        .respond_with(json_body(fixture_plus(
            "gitlab/user_gpg_keys.json",
            &[json!({"id": 904, "key": k.alice_armored})],
        )))
        .mount(&server)
        .await;
    server
}

/// Forgejo: our ed25519 key (with a wrong `fingerprint` field, which must
/// not be trusted), and Alice's primary key packet.
async fn mock_forgejo(k: &LocalKeys) -> MockServer {
    let server = MockServer::start().await;
    let auth = format!("token {TOKEN}");
    let get = |p: &str| {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1{p}")))
            .and(header("authorization", auth.as_str()))
    };
    get("/user")
        .respond_with(json_body(fixture("forgejo/user.json")))
        .mount(&server)
        .await;
    get("/user/keys")
        .and(query_param("page", "2"))
        .respond_with(json_body(fixture("forgejo/user_keys_page2.json")))
        .mount(&server)
        .await;
    let next = format!(
        "<{}/api/v1/user/keys?limit=50&page=2>; rel=\"next\"",
        server.uri()
    );
    get("/user/keys")
        .and(query_param("limit", "50"))
        .respond_with(
            json_body(fixture_plus(
                "forgejo/user_keys.json",
                &[json!({
                    "id": 905, "key": k.ed_line, "title": "acceptance",
                    "fingerprint": "SHA256:763JIcOpkKAvQ9s9+VAhRzITy+8pWxunATagLvmYUZw",
                })],
            ))
            .insert_header("link", next.as_str()),
        )
        .mount(&server)
        .await;
    let key_id = &k.alice[k.alice.len() - 16..];
    get("/user/gpg_keys")
        .respond_with(json_body(fixture_plus(
            "forgejo/user_gpg_keys.json",
            &[json!({
                "id": 906, "key_id": key_id, "subkeys": [],
                "public_key": k.alice_packet,
            })],
        )))
        .mount(&server)
        .await;
    server
}

/// A Forgejo instance that refuses the token and echoes it back.
async fn mock_refusing() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!("bad token {TOKEN}")))
        .mount(&server)
        .await;
    server
}

fn row<'a>(list: &'a KeyList, fpr: &Fingerprint) -> &'a KeyRow {
    list.rows
        .iter()
        .find(|r| &r.fingerprint == fpr)
        .unwrap_or_else(|| panic!("no row {fpr:?}: {list:#?}"))
}

fn reasons(r: &KeyRow) -> Vec<(Severity, WeakReason)> {
    r.warnings
        .iter()
        .map(|w| (w.severity, w.reason.clone()))
        .collect()
}

fn recent(t: SystemTime) -> bool {
    SystemTime::now().duration_since(t).unwrap_or_default() < Duration::from_secs(600)
}

#[tokio::test(flavor = "multi_thread")]
async fn m1_acceptance() {
    // --- Local keys in a temp HOME and GNUPGHOME. ---
    let home = TempHome::new(BASE);
    let ssh_dir = home.ssh_dir();
    let ed = keygen(
        &home,
        "id_ed25519",
        &["-t", "ed25519", "-N", "", "-C", "laptop"],
    );
    let rsa = keygen(
        &home,
        "id_rsa",
        &["-t", "rsa", "-b", "2048", "-N", "", "-C", "old-rsa"],
    );
    let gnupg = TempGnupgHome::new();
    for p in [home.path(), gnupg.path()] {
        check_not_real_home(p).unwrap();
    }
    gpg(
        &gnupg,
        &[
            "--quick-gen-key",
            "Alice <alice@example.invalid>",
            "ed25519",
            "sign",
            "1y",
        ],
    );
    let colons = String::from_utf8(gpg(&gnupg, &["--with-colons", "--list-keys"])).unwrap();
    let alice = colons
        .lines()
        .find(|l| l.starts_with("fpr:"))
        .map(|l| l.split(':').nth(9).unwrap().to_string())
        .unwrap();
    gpg(
        &gnupg,
        &["--quick-add-key", &alice, "cv25519", "encr", "2y"],
    );
    let keys = LocalKeys {
        ed_line: public_line(&ed),
        alice: alice.clone(),
        alice_armored: String::from_utf8(gpg(&gnupg, &["--armor", "--export", &alice])).unwrap(),
        alice_packet: Base64::encode_string(first_packet(&gpg(&gnupg, &["--export", &alice]))),
    };

    // --- Servers: `alpha` and `beta` on one sshd, `gamma` on a second
    // sshd whose host key is not in known_hosts. Only id_ed25519 is
    // authorized. ---
    let sshd = Sshd::start(BASE);
    sshd.authorize(&ed);
    let stranger = Sshd::start(BASE);
    stranger.authorize(&ed);
    let known_hosts = home.path().join("known_hosts");
    fs::copy(sshd.known_hosts(), &known_hosts).unwrap();
    let known_before = fs::read(&known_hosts).unwrap();

    let user = current_user().name;
    let conf_d = ssh_dir.join("config.d");
    fs::create_dir(&conf_d).unwrap();
    let host = |alias: &str, port: u16, key: &str| {
        format!(
            "Host {alias}\n  HostName 127.0.0.1\n  Port {port}\n  User {user}\n  \
             IdentityFile ~/.ssh/{key}\n  UserKnownHostsFile {kh}\n  \
             GlobalKnownHostsFile /dev/null\n",
            kh = known_hosts.display()
        )
    };
    let config = ssh_dir.join("config");
    // An absolute Include: ssh reads a relative one from the passwd home.
    fs::write(
        &config,
        format!(
            "Include {}/*.conf\n{}{}Host *.example.invalid !skip\n  User nobody\n",
            conf_d.display(),
            host("alpha", sshd.port(), "id_ed25519"),
            host("nokey", sshd.port(), "id_absent"),
        ),
    )
    .unwrap();
    fs::write(
        conf_d.join("more.conf"),
        format!(
            "{}{}",
            host("beta", sshd.port(), "id_rsa"),
            host("gamma", stranger.port(), "id_ed25519"),
        ),
    )
    .unwrap();

    // --- Forges. ---
    let github = mock_github(&keys).await;
    let gitlab = mock_gitlab(&keys).await;
    let forgejo = mock_forgejo(&keys).await;
    let refusing = mock_refusing().await;
    let account = |base: String| Target::Account {
        base_url: base,
        account: "testuser".into(),
    };
    let gh = account("https://github.com".into());
    let gl = account(format!("{}/gitlab/", gitlab.uri()));
    let fj = account(forgejo.uri());
    let cb = account(refusing.uri());
    let tokens = InMemoryTokenSource::new();
    for (kind, t) in [
        (LocationKind::GitHub, &gh),
        (LocationKind::GitLab, &gl),
        (LocationKind::Forgejo, &fj),
        (LocationKind::Forgejo, &cb),
    ] {
        tokens.insert(TokenKey::for_target(kind, t).unwrap(), Token::new(TOKEN));
    }
    let tokens = Arc::new(tokens);

    // --- FR-1 key list, before any location exists. ---
    let db = home.path().join(".local/share/key-steward/inventory.db");
    let mut store = Store::open(&db).unwrap();
    let mut gpg_backend = Gpg::with_home(gnupg.path()).unwrap();
    let list = KeyList::load(&ssh_dir, &mut gpg_backend, &store).unwrap();
    assert!(list.problems.is_empty(), "{:?}", list.problems);
    assert_eq!(list.rows.len(), 3, "{list:#?}");
    let ed_fpr = list
        .rows
        .iter()
        .find(|r| r.name == "laptop")
        .unwrap()
        .fingerprint
        .clone();
    let rsa_fpr = list
        .rows
        .iter()
        .find(|r| r.name == "old-rsa")
        .unwrap()
        .fingerprint
        .clone();
    let alice_fpr = Fingerprint::OpenPgp(alice.clone());
    assert!(list.rows.iter().all(|r| r.location_count == 0));

    // --- UC-2: import the ssh config. ---
    let aliases = host_aliases(&config, home.path()).unwrap();
    assert_eq!(aliases, ["beta", "gamma", "alpha", "nokey"]);
    let known: Vec<KnownKey> = list
        .rows
        .iter()
        .filter_map(|r| match &r.source {
            KeySource::Ssh {
                private_path: Some(p),
                ..
            } => Some(KnownKey {
                private_path: p.clone(),
                fingerprint: r.fingerprint.clone(),
            }),
            _ => None,
        })
        .collect();
    assert_eq!(known.len(), 2);
    let report = import_ssh_config(
        &mut store,
        &ImportOptions::new(&config, home.path()),
        &known,
    )
    .unwrap();
    assert_eq!(report.added.len(), 3, "{report:?}");
    assert_eq!(report.without_key, ["nokey"]);
    assert!(report.failed.is_empty(), "{report:?}");
    let imported = store.list().unwrap();
    for loc in &imported {
        assert_eq!(loc.kind, LocationKind::SshServer);
        assert_eq!(loc.status, Status::Unverified);
        assert_eq!(loc.last_checked, None);
    }
    let alpha = &imported[2];
    match &alpha.target {
        Target::Ssh(h) => {
            assert_eq!(h.alias, "alpha");
            assert_eq!(h.hostname.as_deref(), Some("127.0.0.1"));
            assert_eq!(h.user.as_deref(), Some(user.as_str()));
            assert_eq!(h.port, Some(sshd.port()));
        }
        t => panic!("{t:?}"),
    }

    // --- Forge locations (added by hand in M1). ---
    let forge_locations = [
        (LocationKind::GitHub, &gh, &ed_fpr, Purpose::SshAuth),
        (LocationKind::GitHub, &gh, &ed_fpr, Purpose::SshSigning),
        (LocationKind::GitHub, &gh, &alice_fpr, Purpose::OpenPgp),
        (LocationKind::GitLab, &gl, &ed_fpr, Purpose::SshAuth),
        (LocationKind::GitLab, &gl, &ed_fpr, Purpose::SshSigning),
        (LocationKind::GitLab, &gl, &alice_fpr, Purpose::OpenPgp),
        (LocationKind::Forgejo, &fj, &ed_fpr, Purpose::SshAuth),
        (LocationKind::Forgejo, &fj, &alice_fpr, Purpose::OpenPgp),
        (LocationKind::Forgejo, &fj, &rsa_fpr, Purpose::SshAuth),
        (LocationKind::Forgejo, &cb, &rsa_fpr, Purpose::SshAuth),
    ];
    for (kind, target, key, purpose) in forge_locations {
        store
            .add(&NewLocation {
                kind,
                target: target.clone(),
                key: key.clone(),
                purpose,
            })
            .unwrap();
    }

    // --- Check every key's locations. ---
    let log = NetLog::new();
    let reader = || OpenPgpReader::with_home(gnupg.path());
    let runner = CheckRunner::new()
        .with(Arc::new(
            SshServer::new(log.clone())
                .with_config(&config)
                .with_known_hosts(&known_hosts)
                .with_home(home.path())
                .without_agent(),
        ))
        .with(Arc::new(
            GitHub::new(tokens.clone(), reader(), log.clone()).with_api_url(github.uri()),
        ))
        .with(Arc::new(GitLab::new(tokens.clone(), reader(), log.clone())))
        .with(Arc::new(Forgejo::new(
            tokens.clone(),
            reader(),
            log.clone(),
        )));

    let before = SystemTime::now() - Duration::from_secs(1);
    let list = KeyList::load(&ssh_dir, &mut gpg_backend, &store).unwrap();
    let mut checked = 0;
    for r in &list.rows {
        let identity = match &r.source {
            KeySource::Ssh { private_path, .. } => private_path.clone(),
            KeySource::OpenPgp => None,
        };
        let results = runner
            .check_key(&mut store, &r.fingerprint, identity.as_deref())
            .await
            .unwrap();
        for res in &results {
            assert!(
                matches!(res.outcome, CheckOutcome::Checked(_)),
                "{res:?}\n{}",
                log.render()
            );
        }
        checked += results.len();
    }
    assert_eq!(checked, 13);
    drop(store);

    // --- Statuses, read back from the database file. ---
    let store = Store::open(&db).unwrap();
    let locations = store.list().unwrap();
    assert_eq!(locations.len(), 13);
    let status = |kind: LocationKind,
                  label: &str,
                  key: &Fingerprint,
                  purpose: Purpose|
     -> Location {
        locations
            .iter()
            .find(|l| {
                l.kind == kind && l.target.label() == label && &l.key == key && l.purpose == purpose
            })
            .cloned()
            .unwrap_or_else(|| panic!("no location {kind} {label} {purpose:?}"))
    };
    let ssh = LocationKind::SshServer;
    let auth = Purpose::SshAuth;
    let expect: Vec<(Location, Status)> = vec![
        // FR-3: the authorized key logs in.
        (status(ssh, "alpha", &ed_fpr, auth), Status::Verified),
        // FR-3: a key that is not in authorized_keys.
        (status(ssh, "beta", &rsa_fpr, auth), Status::Missing),
        // GitHub: on page 2 of the auth keys; not a signing key.
        (
            status(LocationKind::GitHub, &gh.label(), &ed_fpr, auth),
            Status::Verified,
        ),
        (
            status(
                LocationKind::GitHub,
                &gh.label(),
                &ed_fpr,
                Purpose::SshSigning,
            ),
            Status::Missing,
        ),
        (
            status(
                LocationKind::GitHub,
                &gh.label(),
                &alice_fpr,
                Purpose::OpenPgp,
            ),
            Status::Verified,
        ),
        // GitLab: the key is there for signing only.
        (
            status(LocationKind::GitLab, &gl.label(), &ed_fpr, auth),
            Status::Missing,
        ),
        (
            status(
                LocationKind::GitLab,
                &gl.label(),
                &ed_fpr,
                Purpose::SshSigning,
            ),
            Status::Verified,
        ),
        (
            status(
                LocationKind::GitLab,
                &gl.label(),
                &alice_fpr,
                Purpose::OpenPgp,
            ),
            Status::Verified,
        ),
        // Forgejo: the fingerprint is computed from the key, not taken
        // from the server's field.
        (
            status(LocationKind::Forgejo, &fj.label(), &ed_fpr, auth),
            Status::Verified,
        ),
        (
            status(
                LocationKind::Forgejo,
                &fj.label(),
                &alice_fpr,
                Purpose::OpenPgp,
            ),
            Status::Verified,
        ),
        (
            status(LocationKind::Forgejo, &fj.label(), &rsa_fpr, auth),
            Status::Missing,
        ),
    ];
    for (loc, want) in &expect {
        assert_eq!(&loc.status, want, "{loc:?}\n{}", log.render());
    }

    // S-5: an unknown host key is an error with advice, never accepted.
    let gamma = status(ssh, "gamma", &ed_fpr, auth);
    match &gamma.status {
        Status::Error(r) => assert!(r.contains("host key is not known"), "{r}"),
        s => panic!("gamma: {s:?}\n{}", log.render()),
    }
    assert_eq!(fs::read(&known_hosts).unwrap(), known_before);
    assert!(!ssh_dir.join("known_hosts").exists());

    // A forge that refuses the token: an error that names the status and
    // not the token (S-4).
    let refused = status(LocationKind::Forgejo, &cb.label(), &rsa_fpr, auth);
    let refused_reason = match &refused.status {
        Status::Error(r) => r.clone(),
        s => panic!("{s:?}"),
    };
    assert!(refused_reason.contains("401"), "{refused_reason}");

    // FR-2: every location has its check time.
    for loc in &locations {
        let t = loc.last_checked.expect("last_checked");
        assert!(t >= before && recent(t), "{loc:?}");
    }

    // --- NFR-2: every network call is in the log; S-4: no token in the log,
    // in a status or in the database file. ---
    let entries = log.entries();
    let ssh_runs: Vec<_> = entries
        .iter()
        .filter(|e| e.kind == LocationKind::SshServer)
        .collect();
    assert_eq!(ssh_runs.len(), 3, "{}", log.render());
    for alias in ["alpha", "beta", "gamma"] {
        assert!(
            ssh_runs
                .iter()
                .any(|e| e.target == alias && e.action.contains(alias)),
            "{alias}\n{}",
            log.render()
        );
    }
    for (kind, t, server) in [
        (LocationKind::GitHub, &gh, &github),
        (LocationKind::GitLab, &gl, &gitlab),
        (LocationKind::Forgejo, &fj, &forgejo),
        (LocationKind::Forgejo, &cb, &refusing),
    ] {
        let logged = entries
            .iter()
            .filter(|e| e.kind == kind && e.target == t.label())
            .count();
        let received = server.received_requests().await.unwrap().len();
        assert!(received > 0);
        assert_eq!(logged, received, "{}: {}", t.label(), log.render());
    }
    assert!(!log.render().contains(TOKEN), "{}", log.render());
    for loc in &locations {
        if let Status::Error(r) = &loc.status {
            assert!(!r.contains(TOKEN), "{r}");
        }
    }
    let db_bytes = fs::read(&db).unwrap();
    assert!(
        !db_bytes.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()),
        "token in the database"
    );

    // --- FR-1 rows after the checks: all fields, counts and warnings. ---
    let list = KeyList::load(&ssh_dir, &mut gpg_backend, &store).unwrap();
    assert!(list.problems.is_empty(), "{:?}", list.problems);
    assert_eq!(list.rows.len(), 3);

    let e = row(&list, &ed_fpr);
    assert_eq!(e.kind, KeyKind::Ssh);
    assert_eq!(e.name, "laptop");
    assert_eq!(e.algo, KeyAlgo::Ed25519);
    assert!(matches!(&e.fingerprint, Fingerprint::Ssh(f) if f.starts_with("SHA256:")));
    assert!(matches!(e.created, Some(Created::FileDate(t)) if recent(t)));
    assert_eq!(e.expiry, None);
    assert!(e.subkeys.is_empty());
    assert_eq!(e.location_count, 7);
    assert_eq!(
        reasons(e),
        [(Severity::Warning, WeakReason::PrivateKeyUnencrypted)]
    );
    assert_eq!(
        e.source,
        KeySource::Ssh {
            public_path: ssh_dir.join("id_ed25519.pub"),
            private_path: Some(ed.clone()),
        }
    );

    let r = row(&list, &rsa_fpr);
    assert_eq!(r.name, "old-rsa");
    assert_eq!(r.algo, KeyAlgo::Rsa(2048));
    assert!(matches!(r.created, Some(Created::FileDate(t)) if recent(t)));
    assert_eq!(r.location_count, 3);
    assert_eq!(
        reasons(r),
        [
            (Severity::Warning, WeakReason::RsaTooShort(2048)),
            (Severity::Warning, WeakReason::PrivateKeyUnencrypted),
        ]
    );
    assert_eq!(
        r.source,
        KeySource::Ssh {
            public_path: ssh_dir.join("id_rsa.pub"),
            private_path: Some(rsa.clone()),
        }
    );

    let a = row(&list, &alice_fpr);
    assert_eq!(a.kind, KeyKind::OpenPgp);
    assert_eq!(a.name, "Alice <alice@example.invalid>");
    assert_eq!(a.algo, KeyAlgo::Ed25519);
    assert!(matches!(a.created, Some(Created::Key(t)) if recent(t)));
    let expiry = a.expiry.expect("Alice's key expires");
    assert!(expiry > SystemTime::now() + Duration::from_secs(300 * 86400));
    assert_eq!(a.subkeys.len(), 1, "{:?}", a.subkeys);
    assert_eq!(a.subkeys[0].algo, KeyAlgo::Cv25519);
    assert!(a.subkeys[0].expiry.expect("subkey expires") > expiry);
    assert_eq!(a.location_count, 3);
    assert!(a.warnings.is_empty(), "{:?}", a.warnings);
    assert_eq!(a.source, KeySource::OpenPgp);
}
