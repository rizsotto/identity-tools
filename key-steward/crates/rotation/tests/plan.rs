//! Plan and pre-flight (dry-run) against test sshd servers and fake
//! forges (T11).

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{BASE, fingerprint, keygen};
use identity_core::Fingerprint;
use inventory::{LocationId, LocationKind, NewLocation, Purpose, SshHost, Store, Target};
use providers::{
    Forgejo, GitHub, GitLab, InMemoryTokenSource, NetLog, OpenPgpReader, SshServer, Token, TokenKey,
};
use rotation::{
    Action, EngineEnv, KeyType, Outcome, Passphrase, Plan, PlanError, PlanRequest, ProviderMap,
    plan,
};
use test_support::{ClientConfig, FakeForge, Flavour, KeyList, Sshd, TempGnupgHome, TempHome};

const TOKEN: &str = "fake-plan-TOKEN-0123456789";

struct World {
    home: TempHome,
    a: Sshd,
    b: Sshd,
    c: Sshd,
    cc: ClientConfig,
    gh: FakeForge,
    gl: FakeForge,
    fj: FakeForge,
    gnupg: TempGnupgHome,
    db: PathBuf,
    env: EngineEnv,
    old_path: PathBuf,
    old_fpr: Fingerprint,
    old_line: String,
    log: NetLog,
    ids: BTreeMap<&'static str, LocationId>,
}

fn account(base: &str) -> Target {
    Target::Account {
        base_url: base.into(),
        account: "alice".into(),
    }
}

fn write_0600(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// Old key on srv-a (plain line), srv-b (line with options), srv-c
/// (sshd reads another file: the old key logs in, but is not in
/// `~/.ssh/authorized_keys`), GitHub (auth and signing), GitLab
/// (`auth_and_signing`) and Forgejo.
async fn world() -> World {
    let home = TempHome::new(BASE);
    let ssh = home.ssh_dir();
    let old_path = ssh.join("id_old");
    keygen(&old_path);
    let old_line = fs::read_to_string(ssh.join("id_old.pub")).unwrap();
    let old_fpr = fingerprint(&ssh.join("id_old.pub"));

    let a = Sshd::start_named(BASE, "srv-a");
    let b = Sshd::start_named(BASE, "srv-b");
    let c = Sshd::start_named_with(BASE, "srv-c", "AuthorizedKeysFile @DIR@/other_ak\n");
    a.authorize(&old_path);
    let client = fs::read_to_string(b.authorized_keys()).unwrap();
    write_0600(
        &b.authorized_keys(),
        &format!("{client}from=\"127.0.0.1\",no-pty {old_line}"),
    );
    write_0600(&c.dir().join("other_ak"), &old_line);
    let cc = ClientConfig::new(&[&a, &b, &c]);
    let config = fs::read_to_string(cc.ssh_config()).unwrap().replace(
        "IdentityFile none",
        &format!("IdentityFile {}", old_path.display()),
    );
    write_0600(&ssh.join("config"), &config);

    let forge = |f| async move {
        FakeForge::builder(f)
            .empty()
            .login("alice")
            .token(TOKEN)
            .start()
            .await
    };
    let gh = forge(Flavour::GitHub).await;
    let gl = forge(Flavour::GitLab).await;
    let fj = forge(Flavour::Forgejo).await;
    gh.insert_key(KeyList::Auth, &old_line, "old auth", None);
    gh.insert_key(KeyList::Signing, &old_line, "old signing", None);
    gl.insert_key(KeyList::Auth, &old_line, "old", Some("auth_and_signing"));
    fj.insert_key(KeyList::Auth, &old_line, "old", None);

    let db = home.path().join("data").join("ks.db");
    let mut store = Store::open(&db).unwrap();
    let mut ids = BTreeMap::new();
    let ssh_t = |alias: &str| Target::Ssh(SshHost::new(alias));
    let rows: Vec<(&'static str, LocationKind, Target, Purpose)> = vec![
        (
            "a",
            LocationKind::SshServer,
            ssh_t("srv-a"),
            Purpose::SshAuth,
        ),
        (
            "b",
            LocationKind::SshServer,
            ssh_t("srv-b"),
            Purpose::SshAuth,
        ),
        (
            "c",
            LocationKind::SshServer,
            ssh_t("srv-c"),
            Purpose::SshAuth,
        ),
        (
            "gh-auth",
            LocationKind::GitHub,
            account("https://github.com"),
            Purpose::SshAuth,
        ),
        (
            "gh-sign",
            LocationKind::GitHub,
            account("https://github.com"),
            Purpose::SshSigning,
        ),
        (
            "gl",
            LocationKind::GitLab,
            account(gl.base_url()),
            Purpose::SshAuth,
        ),
        (
            "fj",
            LocationKind::Forgejo,
            account(fj.base_url()),
            Purpose::SshAuth,
        ),
    ];
    for (name, kind, target, purpose) in rows {
        let id = store
            .add(&NewLocation {
                kind,
                target,
                key: old_fpr.clone(),
                purpose,
            })
            .unwrap()
            .id();
        ids.insert(name, id);
    }
    drop(store);

    let mut env = EngineEnv::new(&ssh, home.path());
    env.config_files = vec![ssh.join("config")];
    env.passphrase = Passphrase::Empty;
    env.comment = Some("new@test".into());
    World {
        home,
        a,
        b,
        c,
        cc,
        gh,
        gl,
        fj,
        gnupg: TempGnupgHome::new(),
        db,
        env,
        old_path,
        old_fpr,
        old_line,
        log: NetLog::new(),
        ids,
    }
}

impl World {
    fn providers(&self) -> ProviderMap {
        let tokens = Arc::new(InMemoryTokenSource::new());
        for (kind, base) in [
            (LocationKind::GitHub, "https://github.com"),
            (LocationKind::GitLab, self.gl.base_url()),
            (LocationKind::Forgejo, self.fj.base_url()),
        ] {
            let key = TokenKey::for_target(kind, &account(base)).unwrap();
            tokens.insert(key, Token::new(TOKEN));
        }
        let pgp = || OpenPgpReader::with_home(self.gnupg.path());
        let ssh = SshServer::new(self.log.clone())
            .with_config(self.home.ssh_dir().join("config"))
            .with_known_hosts(self.cc.known_hosts())
            .with_home(self.cc.home())
            .without_agent();
        ProviderMap::new()
            .with_ssh(ssh)
            .with(Box::new(
                GitHub::new(tokens.clone(), pgp(), self.log.clone())
                    .with_api_url(self.gh.api_url()),
            ))
            .with(Box::new(GitLab::new(
                tokens.clone(),
                pgp(),
                self.log.clone(),
            )))
            .with(Box::new(Forgejo::new(tokens, pgp(), self.log.clone())))
    }

    fn request(&self) -> PlanRequest {
        PlanRequest {
            key: self.old_path.display().to_string(),
            key_type: KeyType::Ed25519,
            new_path: Some(self.home.ssh_dir().join("id_new")),
            skip: Vec::new(),
            update_config: true,
        }
    }

    async fn plan(&self, req: &PlanRequest) -> Result<Plan, PlanError> {
        let store = Store::open(&self.db).unwrap();
        plan(&store, &self.providers(), &self.env, req).await
    }

    fn location<'p>(&self, p: &'p Plan, name: &str) -> &'p rotation::PlanLocation {
        let id = self.ids[name];
        p.locations.iter().find(|l| l.id == id).unwrap()
    }

    /// Every file under `dir`, with its bytes.
    fn files(dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let meta = fs::symlink_metadata(&p).unwrap();
            if meta.is_dir() {
                Self::files(&p, out);
            } else if meta.is_file() {
                out.insert(p.clone(), fs::read(&p).unwrap());
            }
        }
    }

    /// Local files (home, database), server files, forge keys and every
    /// forge write.
    fn snapshot(&self) -> (BTreeMap<PathBuf, Vec<u8>>, Vec<String>) {
        let mut files = BTreeMap::new();
        Self::files(self.home.path(), &mut files);
        for s in [&self.a, &self.b, &self.c] {
            Self::files(&s.server_home(), &mut files);
            files.insert(
                s.dir().join("other_ak"),
                fs::read(s.dir().join("other_ak")).unwrap_or_default(),
            );
        }
        let mut forge = Vec::new();
        for f in [&self.gh, &self.gl, &self.fj] {
            forge.push(format!("{:?}", f.keys()));
            for r in f.requests() {
                if r.method != "GET" {
                    forge.push(format!("{} {}", r.method, r.path));
                }
            }
        }
        (files, forge)
    }
}

fn actions(l: &rotation::PlanLocation) -> &[Action] {
    match &l.outcome {
        Outcome::Rotate(a) => a,
        other => panic!("{l:?} is {other:?}"),
    }
}

#[tokio::test]
async fn plan_lists_every_action() {
    let w = world().await;
    let p = w
        .plan(&w.request())
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", w.log.render()));

    assert_eq!(p.old_fingerprint, w.old_fpr);
    assert_eq!(p.old_path, w.old_path);
    assert!(
        p.keygen.contains("-t ed25519") && p.keygen.contains("-N ''"),
        "{}",
        p.keygen
    );

    // SSH: the line after which the new key goes, with the options.
    let a = actions(w.location(&p, "a"));
    assert_eq!(
        a,
        [
            Action::SshAdd {
                after_line: 2,
                options: None
            },
            Action::SshVerify,
            Action::SshRemove { line: 2 },
            Action::SshOldRefused,
        ]
    );
    let b = actions(w.location(&p, "b"));
    assert_eq!(
        b[0],
        Action::SshAdd {
            after_line: 2,
            options: Some("from=\"127.0.0.1\",no-pty".into())
        }
    );

    // Forges: owner check, POST, verify, DELETE with the key's id.
    let http = |l: &[Action]| -> Vec<String> {
        l.iter()
            .filter_map(|a| match a {
                Action::Http { method, path, .. } => Some(format!("{method} {path}")),
                _ => None,
            })
            .collect()
    };
    let gh_auth_id =
        w.gh.keys()
            .iter()
            .find(|k| k.list == KeyList::Auth)
            .unwrap()
            .id;
    let gh_sign_id =
        w.gh.keys()
            .iter()
            .find(|k| k.list == KeyList::Signing)
            .unwrap()
            .id;
    assert_eq!(
        http(actions(w.location(&p, "gh-auth"))),
        [
            "GET /user".to_string(),
            "POST /user/keys".into(),
            format!("DELETE /user/keys/{gh_auth_id}")
        ]
    );
    assert_eq!(
        http(actions(w.location(&p, "gh-sign"))),
        [
            "GET /user".to_string(),
            "POST /user/ssh_signing_keys".into(),
            format!("DELETE /user/ssh_signing_keys/{gh_sign_id}")
        ]
    );
    let gl_id = w.gl.keys()[0].id;
    let gl = actions(w.location(&p, "gl"));
    assert_eq!(
        http(gl),
        [
            "GET /api/v4/user".to_string(),
            "POST /api/v4/user/keys".into(),
            format!("DELETE /api/v4/user/keys/{gl_id}")
        ]
    );
    assert!(gl.iter().any(|a| matches!(a,
        Action::Http { method: "POST", note: Some(n), .. } if n.contains("auth_and_signing"))));
    let fj_id = w.fj.keys()[0].id;
    assert_eq!(
        http(actions(w.location(&p, "fj"))),
        [
            "GET /api/v1/user".to_string(),
            "POST /api/v1/user/keys".into(),
            format!("DELETE /api/v1/user/keys/{fj_id}")
        ]
    );
    assert!(
        w.location(&p, "gl")
            .notes
            .iter()
            .any(|n| n.contains("api scope"))
    );

    // Config in two phases: new line above the old one first, the old
    // line dropped at retire.
    let config = w.home.ssh_dir().join("config");
    let real = fs::canonicalize(&config).unwrap();
    assert_eq!(p.config.files.len(), 1);
    let changes = &p.config.files[0].changes;
    assert_eq!(changes.len(), 3, "{changes:?}");
    for c in changes {
        let new_line = format!("IdentityFile {}", w.home.ssh_dir().join("id_new").display());
        assert!(c.after.contains(&new_line), "{c:?}");
        assert!(c.after.trim_end().ends_with(c.before.trim()), "{c:?}");
    }
    assert_eq!(p.config_at_retire.len(), 3);
    for d in &p.config_at_retire {
        assert_eq!(d.path, real);
        assert!(d.text.contains("id_old"), "{d:?}");
    }

    // Retire: the moves; blocked by srv-c, where the old key stays.
    let retired = w.home.ssh_dir().join("retired");
    assert_eq!(
        p.retire,
        [
            (w.old_path.clone(), retired.join("id_old")),
            (
                w.old_path.with_file_name("id_old.pub"),
                retired.join("id_old.pub")
            ),
        ]
    );
    assert!(
        p.retire_blocked.iter().any(|r| r.contains("srv-c")),
        "{:?}",
        p.retire_blocked
    );
    assert!(p.warnings.iter().any(|w| w.contains("no passphrase")));

    // Text and JSON say the same.
    let text = p.render_text();
    for want in [
        "Dry-run: nothing has been changed.",
        "Locations that will be changed (6)",
        "Not touched (the old key stays there):",
        "srv-c",
        "add the new key after line 2 with the same options (from=\"127.0.0.1\",no-pty)",
        "remove line 2",
        &format!("DELETE /api/v4/user/keys/{gl_id}"),
        "before any removal: add `IdentityFile",
        "at retire: remove the old lines",
        &format!("move {}", w.old_path.display()),
        "will not run: the old key stays at srv-c",
    ] {
        assert!(text.contains(want), "{want:?} not in\n{text}");
    }
    let j = p.to_json();
    assert_eq!(j["dry_run"], true);
    assert_eq!(j["locations"].as_array().unwrap().len(), 7);
    assert_eq!(
        j["config"]["insert_before_removals"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(j["config"]["remove_at_retire"].as_array().unwrap().len(), 3);
    let gl_json = j["locations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["kind"] == "gitlab")
        .unwrap();
    assert!(
        gl_json["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["method"] == "DELETE" && a["path"] == format!("/api/v4/user/keys/{gl_id}"))
    );

    // No key blob or token in the output or the network log.
    let blob = w.old_line.split_whitespace().nth(1).unwrap();
    for out in [text, j.to_string(), w.log.render()] {
        assert!(!out.contains(blob) && !out.contains(TOKEN));
    }

    // The rotation `start` would write: the six rotated locations.
    let rot = p.new_rotation();
    assert_eq!(rot.locations.len(), 6);
    assert!(!rot.locations.contains(&w.ids["c"]));
}

#[tokio::test]
async fn plan_changes_nothing() {
    let w = world().await;
    let before = w.snapshot();
    let mut req = w.request();
    req.skip = vec![w.ids["fj"]];
    let p = w.plan(&req).await.unwrap();
    assert_eq!(w.location(&p, "fj").outcome, Outcome::Skipped);
    let after = w.snapshot();
    assert_eq!(before.1, after.1, "forge state");
    assert_eq!(
        before.0.keys().collect::<Vec<_>>(),
        after.0.keys().collect::<Vec<_>>()
    );
    for (path, bytes) in &before.0 {
        assert!(&after.0[path] == bytes, "{} changed", path.display());
    }
    assert!(!w.home.ssh_dir().join("id_new").exists());
    // Only reads went to the forges.
    for f in [&w.gh, &w.gl, &w.fj] {
        assert!(f.requests().iter().all(|r| r.method == "GET"));
    }
}

#[tokio::test]
async fn same_fingerprint_is_refused() {
    let w = world().await;
    let ssh = w.home.ssh_dir();
    // A "new" key that is the old key under another name.
    fs::hard_link(&w.old_path, ssh.join("id_copy")).unwrap();
    fs::hard_link(ssh.join("id_old.pub"), ssh.join("id_copy.pub")).unwrap();
    let mut req = w.request();
    req.new_path = Some(ssh.join("id_copy"));
    let r = w.plan(&req).await;
    assert!(
        matches!(&r, Err(PlanError::Refused(m)) if m.contains("same fingerprint")),
        "{r:?}"
    );
    req.new_path = Some(w.old_path.clone());
    assert!(matches!(w.plan(&req).await, Err(PlanError::Refused(_))));
    // By fingerprint: two files hold it, so it is ambiguous.
    let mut req = w.request();
    req.key = w.old_fpr.to_string();
    let r = w.plan(&req).await;
    assert!(
        matches!(&r, Err(PlanError::Refused(m)) if m.contains("several key files")),
        "{r:?}"
    );
    fs::remove_file(ssh.join("id_copy")).unwrap();
    fs::remove_file(ssh.join("id_copy.pub")).unwrap();
    assert_eq!(w.plan(&req).await.unwrap().old_path, w.old_path);
}

#[tokio::test]
async fn old_key_not_in_file_is_refused() {
    let w = world().await;
    let mut req = w.request();
    req.skip = ["a", "b", "gh-auth", "gh-sign", "gl", "fj"]
        .iter()
        .map(|n| w.ids[n])
        .collect();
    let p = w.plan(&req).await.unwrap();
    match &w.location(&p, "c").outcome {
        Outcome::NotRotated(r) => assert!(r.contains("not in ~/.ssh/authorized_keys"), "{r}"),
        other => panic!("{other:?}"),
    }
    assert!(p.rotated().is_empty());
    assert!(p.warnings.iter().any(|w| w.contains("start will refuse")));
    // The server file is as it was.
    assert!(
        !fs::read_to_string(w.c.authorized_keys())
            .unwrap()
            .contains(w.old_line.trim())
    );
}
