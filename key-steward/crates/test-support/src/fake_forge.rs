//! Stateful fake forges on wiremock: GitHub, GitLab and Forgejo.
//!
//! One responder holds the account's keys in shared state, so `POST` and
//! `DELETE` change what the next `GET` lists. Paths, pagination, status
//! codes and body fields follow the official API docs listed in
//! `spec/key-steward/milestones/M2/plan.md`, "Facts". Status codes are
//! the documented ones. Error bodies are close to the real ones, but
//! most of their text is not documented (M2 human check 4): no test may
//! rely on the text of any error body, only on the status.
//!
//! Only SSH keys can be written. GPG keys are seeded from the fixtures
//! and are read-only here.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use identity_core::{PublicKey, parse_public_keys};
use serde_json::{Value, json};
use wiremock::http::Method;
use wiremock::{Match, Mock, MockServer, Request, Respond, ResponseTemplate};

const CREATED_AT: &str = "2026-11-12T00:00:00Z";

/// Which forge API the fake speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// API at the root: `/user`, `/user/keys`, `/user/ssh_signing_keys`.
    GitHub,
    /// API under `/api/v4`.
    GitLab,
    /// API under `/api/v1`. Also Gitea and Codeberg.
    Forgejo,
}

impl Flavour {
    fn dir(self) -> &'static str {
        match self {
            Flavour::GitHub => "github",
            Flavour::GitLab => "gitlab",
            Flavour::Forgejo => "forgejo",
        }
    }

    fn api_root(self) -> &'static str {
        match self {
            Flavour::GitHub => "",
            Flavour::GitLab => "/api/v4",
            Flavour::Forgejo => "/api/v1",
        }
    }

    fn login_field(self) -> &'static str {
        match self {
            Flavour::GitLab => "username",
            _ => "login",
        }
    }

    /// The page size query parameter, its default and its largest value.
    fn paging(self) -> (&'static str, usize, usize) {
        match self {
            // GitHub: per_page default 30, max 100.
            Flavour::GitHub => ("per_page", 30, 100),
            // GitLab: per_page default 20, max 100.
            Flavour::GitLab => ("per_page", 20, 100),
            // Forgejo: limit default 30 (DEFAULT_PAGING_NUM), max 50
            // (MAX_RESPONSE_ITEMS).
            Flavour::Forgejo => ("limit", 30, 50),
        }
    }
}

/// The key list a key is in. Only GitHub has a separate signing list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyList {
    /// `/user/keys`.
    Auth,
    /// GitHub `/user/ssh_signing_keys`.
    Signing,
}

/// An SSH key held by the fake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeKey {
    pub id: u64,
    pub list: KeyList,
    /// `<type> <base64>`.
    pub key: String,
    pub title: String,
    /// GitLab only: `auth`, `signing` or `auth_and_signing`.
    pub usage_type: Option<String>,
}

/// A fault for one coming request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// Apply the request, then answer 502: the client never learns that
    /// it worked.
    LoseResponse,
    /// Do not apply the request; answer this status (for example 500 or
    /// 403) with the forge's error body.
    Status(u16),
    /// Close the connection without an answer, after applying the request
    /// if `apply` is set.
    CloseConnection { apply: bool },
}

/// Which request a fault hits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultOn {
    /// The next `POST` or `DELETE`.
    Write,
    /// The next request of any method.
    Any,
}

/// A request the fake received. Headers are not kept, so no token is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    pub method: String,
    /// Path and query, from the server root.
    pub path: String,
    pub body: Option<Value>,
    /// The status sent, `None` if the connection was closed.
    pub status: Option<u16>,
}

struct State {
    flavour: Flavour,
    base: String,
    token: String,
    max_per_page: Option<usize>,
    user: Value,
    keys: Vec<FakeKey>,
    gpg: Vec<Value>,
    next_id: u64,
    faults: Vec<(FaultOn, Fault)>,
    requests: Vec<RecordedRequest>,
}

/// Sets up a [`FakeForge`].
pub struct FakeForgeBuilder {
    flavour: Flavour,
    token: String,
    prefix: String,
    seed: bool,
    login: Option<String>,
    max_per_page: Option<usize>,
}

impl FakeForgeBuilder {
    /// The token the fake accepts. Default `fake-forge-token`.
    pub fn token(mut self, token: &str) -> Self {
        self.token = token.into();
        self
    }

    /// A path in front of the instance, like a self-hosted GitLab at
    /// `https://example.org/gitlab`.
    pub fn prefix(mut self, prefix: &str) -> Self {
        self.prefix = prefix.trim_end_matches('/').into();
        self
    }

    /// Start with no keys (the user from the fixtures stays).
    pub fn empty(mut self) -> Self {
        self.seed = false;
        self
    }

    /// The token owner's name, instead of the fixture's `testuser`.
    pub fn login(mut self, login: &str) -> Self {
        self.login = Some(login.into());
        self
    }

    /// Lower the forge's largest page size, so small lists span pages.
    pub fn max_per_page(mut self, n: usize) -> Self {
        self.max_per_page = Some(n.max(1));
        self
    }

    pub async fn start(self) -> FakeForge {
        let server = MockServer::start().await;
        let f = self.flavour;
        let mut user = fixture(f, "user.json");
        if let Some(login) = &self.login {
            user[f.login_field()] = json!(login);
        }
        let mut keys = Vec::new();
        let mut gpg = Vec::new();
        if self.seed {
            let mut lists = vec![
                ("user_keys.json", KeyList::Auth),
                ("user_keys_page2.json", KeyList::Auth),
            ];
            if f == Flavour::GitHub {
                lists.push(("user_ssh_signing_keys.json", KeyList::Signing));
            }
            for (file, list) in lists {
                for item in array(fixture(f, file)) {
                    keys.push(FakeKey {
                        id: item["id"].as_u64().expect("fixture key id"),
                        list,
                        key: item["key"].as_str().expect("fixture key").into(),
                        title: item["title"].as_str().unwrap_or_default().into(),
                        usage_type: item["usage_type"].as_str().map(str::to_string),
                    });
                }
            }
            gpg = array(fixture(f, "user_gpg_keys.json"));
        }
        let next_id = keys.iter().map(|k| k.id).max().unwrap_or(0) + 1;
        let base = format!("{}{}", server.uri(), self.prefix);
        let state = Arc::new(Mutex::new(State {
            flavour: f,
            base: base.clone(),
            token: self.token,
            max_per_page: self.max_per_page,
            user,
            keys,
            gpg,
            next_id,
            faults: Vec::new(),
            requests: Vec::new(),
        }));
        Mock::given(CloseNext(state.clone()))
            .respond_with_err({
                let state = state.clone();
                move |req: &Request| close(&state, req)
            })
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(wiremock::matchers::any())
            .respond_with(Responder(state.clone()))
            .mount(&server)
            .await;
        FakeForge {
            server,
            flavour: f,
            base,
            state,
        }
    }
}

/// A fake forge with one account. See the module docs.
pub struct FakeForge {
    server: MockServer,
    flavour: Flavour,
    base: String,
    state: Arc<Mutex<State>>,
}

impl FakeForge {
    pub fn builder(flavour: Flavour) -> FakeForgeBuilder {
        FakeForgeBuilder {
            flavour,
            token: "fake-forge-token".into(),
            prefix: String::new(),
            seed: true,
            login: None,
            max_per_page: None,
        }
    }

    /// A fake seeded from `key-steward/tests/mock-forges/<flavour>/`.
    pub async fn start(flavour: Flavour) -> FakeForge {
        Self::builder(flavour).start().await
    }

    pub fn flavour(&self) -> Flavour {
        self.flavour
    }

    /// The instance URL, for a GitLab or Forgejo target's `base_url`.
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// The API root: the GitHub provider's `with_api_url`.
    pub fn api_url(&self) -> String {
        format!("{}{}", self.base, self.flavour.api_root())
    }

    pub fn server(&self) -> &MockServer {
        &self.server
    }

    pub fn token(&self) -> String {
        self.lock().token.clone()
    }

    /// The token owner's name.
    pub fn login(&self) -> String {
        let s = self.lock();
        s.user[s.flavour.login_field()]
            .as_str()
            .unwrap_or_default()
            .into()
    }

    /// All SSH keys, in list order.
    pub fn keys(&self) -> Vec<FakeKey> {
        self.lock().keys.clone()
    }

    /// Adds a key without a request, as if the user added it on the web.
    /// `key` is `<type> <base64> [comment]`. Returns its id.
    pub fn insert_key(
        &self,
        list: KeyList,
        key: &str,
        title: &str,
        usage_type: Option<&str>,
    ) -> u64 {
        let encoded = encode(key).expect("insert_key: not one SSH public key");
        let mut s = self.lock();
        let id = s.next_id;
        s.next_id += 1;
        s.keys.push(FakeKey {
            id,
            list,
            key: encoded,
            title: title.into(),
            usage_type: usage_type.map(str::to_string),
        });
        id
    }

    /// Queues a fault. Faults hit requests in the order they were queued.
    pub fn fail_next(&self, on: FaultOn, fault: Fault) {
        self.lock().faults.push((on, fault));
    }

    /// Every request so far, in order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.lock().requests.clone()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

fn fixture(flavour: Flavour, name: &str) -> Value {
    let p: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/mock-forges")
        .join(flavour.dir())
        .join(name);
    let text = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("test-support: {}: {e}", p.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("test-support: {}: {e}", p.display()))
}

fn array(v: Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a,
        _ => panic!("test-support: fixture is not a list"),
    }
}

/// `<type> <base64>` of a single SSH public key, without comment.
fn encode(key: &str) -> Option<String> {
    let parsed = parse_public_keys(key.as_bytes()).ok()?;
    match parsed.as_slice() {
        [one] => match &one.key {
            Ok(PublicKey::Ssh(k)) => Some(k.encoded.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn fingerprint(encoded: &str) -> String {
    match parse_public_keys(encoded.as_bytes()).ok().as_deref() {
        Some([one]) => match &one.key {
            Ok(PublicKey::Ssh(k)) => k.fingerprint.to_string(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

fn is_write(m: &Method) -> bool {
    *m == Method::POST || *m == Method::DELETE
}

fn path_and_query(req: &Request) -> String {
    match req.url.query() {
        Some(q) => format!("{}?{q}", req.url.path()),
        None => req.url.path().to_string(),
    }
}

impl State {
    /// Takes the first queued fault if it hits this request.
    fn take_fault(&mut self, method: &Method) -> Option<Fault> {
        let (on, _) = self.faults.first()?;
        if *on == FaultOn::Any || is_write(method) {
            Some(self.faults.remove(0).1)
        } else {
            None
        }
    }

    fn record(&mut self, req: &Request, status: Option<u16>) {
        self.requests.push(RecordedRequest {
            method: req.method.to_string(),
            path: path_and_query(req),
            body: serde_json::from_slice(&req.body).ok(),
            status,
        });
    }

    fn authorized(&self, req: &Request) -> bool {
        let header = |name: &str| {
            req.headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let auth = header("authorization");
        let t = &self.token;
        let bearer = auth.as_deref() == Some(&format!("Bearer {t}"));
        let token = auth.as_deref() == Some(&format!("token {t}"));
        match self.flavour {
            // GitHub and Forgejo take both `Bearer` and `token`.
            Flavour::GitHub | Flavour::Forgejo => bearer || token,
            Flavour::GitLab => bearer || header("private-token").as_deref() == Some(t),
        }
    }

    /// The normal answer, applying any change.
    fn handle(&mut self, req: &Request) -> Reply {
        if !self.authorized(req) {
            return self.error(401);
        }
        let prefix = url_path(&self.base).to_string() + self.flavour.api_root();
        let Some(path) = req.url.path().strip_prefix(&prefix) else {
            return self.error(404);
        };
        let path = path.to_string();
        let lists: &[(&str, KeyList)] = match self.flavour {
            Flavour::GitHub => &[
                ("/user/keys", KeyList::Auth),
                ("/user/ssh_signing_keys", KeyList::Signing),
            ],
            _ => &[("/user/keys", KeyList::Auth)],
        };
        let m = &req.method;
        if path == "/user" && *m == Method::GET {
            return Reply::json(200, self.user.clone());
        }
        if path == "/user/gpg_keys" && *m == Method::GET {
            let items = self.gpg.clone();
            return self.page(req, &path, items);
        }
        for &(p, list) in lists {
            if path == p && *m == Method::GET {
                let items = self
                    .keys
                    .iter()
                    .filter(|k| k.list == list)
                    .map(|k| self.key_json(k))
                    .collect();
                return self.page(req, &path, items);
            }
            if path == p && *m == Method::POST {
                return self.add(req, list);
            }
            if let Some(id) = path.strip_prefix(p).and_then(|r| r.strip_prefix('/'))
                && *m == Method::DELETE
            {
                let at = id
                    .parse::<u64>()
                    .ok()
                    .and_then(|id| self.keys.iter().position(|k| k.list == list && k.id == id));
                return match at {
                    Some(i) => {
                        self.keys.remove(i);
                        Reply::new(204)
                    }
                    None => self.error(404),
                };
            }
        }
        if path == "/user/gpg_keys" {
            return Reply::json(
                501,
                json!({ "message": "GPG key writes are not modelled by FakeForge" }),
            );
        }
        self.error(404)
    }

    fn add(&mut self, req: &Request, list: KeyList) -> Reply {
        let f = self.flavour;
        let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
            // GitHub: "Problems parsing JSON", 400. GitLab and Forgejo
            // reject a body they cannot read with 400 too.
            return Reply::json(400, json!({ "message": "Problems parsing JSON" }));
        };
        let key = body["key"].as_str().filter(|s| !s.is_empty());
        let title = body["title"].as_str().filter(|s| !s.is_empty());
        let usage = match f {
            Flavour::GitLab => match body["usage_type"].as_str() {
                None => Some("auth_and_signing".to_string()),
                Some(u @ ("auth" | "signing" | "auth_and_signing")) => Some(u.to_string()),
                Some(_) => {
                    return Reply::json(
                        400,
                        json!({ "error": "usage_type does not have a valid value" }),
                    );
                }
            },
            _ => None,
        };
        // Required fields: GitHub `key`; GitLab and Forgejo `title` and `key`.
        let missing = match (f, key, title) {
            (_, None, _) => Some("key"),
            (Flavour::GitLab | Flavour::Forgejo, _, None) => Some("title"),
            _ => None,
        };
        if let Some(field) = missing {
            return match f {
                Flavour::GitHub => Reply::json(
                    422,
                    json!({
                        "message": format!("Invalid request.\n\n\"{field}\" wasn't supplied."),
                    }),
                ),
                Flavour::GitLab => {
                    Reply::json(400, json!({ "error": format!("{field} is missing") }))
                }
                Flavour::Forgejo => Reply::json(
                    422,
                    json!([{
                        "fieldNames": [capitalize(field)],
                        "classification": "RequiredError",
                        "message": "Required",
                    }]),
                ),
            };
        }
        let Some(encoded) = key.and_then(encode) else {
            return self.invalid("key", "is invalid");
        };
        if self.keys.iter().any(|k| k.list == list && k.key == encoded) {
            return self.invalid("key", "has already been taken");
        }
        // Forgejo and Gitea: a key title is unique per user
        // (models/asymkey/ssh_key.go AddPublicKey, ErrKeyNameAlreadyUsed;
        // routers/api/v1/repo/key.go HandleAddKeyError gives 422). GitHub
        // and GitLab document no such rule.
        if f == Flavour::Forgejo && self.keys.iter().any(|k| Some(k.title.as_str()) == title) {
            return Reply::json(422, json!({ "message": "Key title has been used" }));
        }
        let id = self.next_id;
        self.next_id += 1;
        let k = FakeKey {
            id,
            list,
            key: encoded,
            title: title.unwrap_or_default().into(),
            usage_type: usage,
        };
        let out = self.key_json(&k);
        self.keys.push(k);
        Reply::json(201, out)
    }

    /// A rejected key: GitHub and Forgejo 422, GitLab 400.
    fn invalid(&self, field: &str, why: &str) -> Reply {
        match self.flavour {
            Flavour::GitHub => Reply::json(
                422,
                json!({
                    "message": "Validation Failed",
                    "errors": [{ "resource": "PublicKey", "code": "custom", "field": field,
                                 "message": format!("{field} {why}") }],
                }),
            ),
            Flavour::GitLab => {
                let mut fields = json!({ field: [why] });
                if why.contains("taken") {
                    fields["fingerprint"] = json!([why]);
                }
                Reply::json(400, json!({ "message": fields }))
            }
            // HandleAddKeyError: ErrKeyAlreadyExist gives this text.
            Flavour::Forgejo if why.contains("taken") => Reply::json(
                422,
                json!({ "message": "Key content has been used as non-deploy key" }),
            ),
            Flavour::Forgejo => Reply::json(422, json!({ "message": format!("{field} {why}") })),
        }
    }

    fn key_json(&self, k: &FakeKey) -> Value {
        let id_url = format!(
            "{}{}/user/keys/{}",
            self.base,
            self.flavour.api_root(),
            k.id
        );
        match (self.flavour, k.list) {
            (Flavour::GitHub, KeyList::Auth) => json!({
                "key": k.key, "id": k.id, "url": id_url, "title": k.title,
                "created_at": CREATED_AT, "verified": true, "read_only": false,
            }),
            (Flavour::GitHub, KeyList::Signing) => json!({
                "key": k.key, "id": k.id, "title": k.title, "created_at": CREATED_AT,
            }),
            (Flavour::GitLab, _) => json!({
                "id": k.id, "title": k.title, "created_at": CREATED_AT,
                "expires_at": null, "key": k.key, "usage_type": k.usage_type,
            }),
            (Flavour::Forgejo, _) => json!({
                "id": k.id, "key": k.key, "url": id_url, "title": k.title,
                "fingerprint": fingerprint(&k.key), "created_at": CREATED_AT,
                "read_only": false, "key_type": "user",
                "user": { "id": self.user["id"], "login": self.user["login"] },
            }),
        }
    }

    /// One page of `items`, with the flavour's pagination headers.
    fn page(&self, req: &Request, path: &str, items: Vec<Value>) -> Reply {
        let (param, default, max) = self.flavour.paging();
        let max = self.max_per_page.map_or(max, |m| m.min(max));
        let query = |name: &str| {
            req.url
                .query_pairs()
                .find(|(k, _)| k == name)
                .and_then(|(_, v)| v.parse::<usize>().ok())
        };
        // Forgejo: limit=0 (or none) means the default page size.
        let per_page = match query(param) {
            Some(0) if self.flavour == Flavour::Forgejo => default,
            Some(n) => n,
            None => default,
        }
        .clamp(1, max);
        let page = query("page").unwrap_or(1).max(1);
        let total = items.len();
        let pages = total.div_ceil(per_page).max(1);
        let body: Vec<Value> = items
            .into_iter()
            .skip((page - 1) * per_page)
            .take(per_page)
            .collect();
        let link_to = |p: usize| {
            format!(
                "{}{}{path}?{param}={per_page}&page={p}",
                self.base,
                self.flavour.api_root()
            )
        };
        let mut rels = Vec::new();
        if page > 1 {
            rels.push(format!("<{}>; rel=\"prev\"", link_to(page - 1)));
        }
        if page < pages {
            rels.push(format!("<{}>; rel=\"next\"", link_to(page + 1)));
        }
        // GitHub sends `first` only when not on page 1, GitLab always.
        if page > 1 || self.flavour == Flavour::GitLab {
            rels.push(format!("<{}>; rel=\"first\"", link_to(1)));
        }
        if page < pages || self.flavour == Flavour::GitLab {
            rels.push(format!("<{}>; rel=\"last\"", link_to(pages)));
        }
        let mut resp = Reply::json(200, Value::Array(body));
        if !rels.is_empty() {
            resp = resp.header("link", rels.join(", "));
        }
        match self.flavour {
            Flavour::GitHub => {}
            Flavour::GitLab => {
                let next = if page < pages {
                    (page + 1).to_string()
                } else {
                    String::new()
                };
                let prev = if page > 1 {
                    (page - 1).to_string()
                } else {
                    String::new()
                };
                resp = resp
                    .header("x-page", page.to_string())
                    .header("x-per-page", per_page.to_string())
                    .header("x-next-page", next)
                    .header("x-prev-page", prev)
                    .header("x-total", total.to_string())
                    .header("x-total-pages", pages.to_string());
            }
            Flavour::Forgejo => {
                resp = resp.header("x-total-count", total.to_string());
            }
        }
        resp
    }

    /// The forge's error answer for `status`.
    fn error(&self, status: u16) -> Reply {
        let body = match (self.flavour, status) {
            (Flavour::GitHub, 401) => json!({ "message": "Bad credentials", "status": "401" }),
            (Flavour::GitHub, 403) => json!({
                "message": "Resource not accessible by personal access token", "status": "403",
            }),
            (Flavour::GitHub, 404) => json!({ "message": "Not Found", "status": "404" }),
            (Flavour::GitHub, _) => json!({ "message": "Server Error" }),
            (Flavour::GitLab, 403) => json!({
                "error": "insufficient_scope",
                "error_description":
                    "The request requires higher privileges than provided by the access token.",
                "scope": "api",
            }),
            (Flavour::GitLab, 404) => json!({ "message": "404 Not Found" }),
            (Flavour::GitLab, s) => json!({ "message": format!("{s} {}", reason(s)) }),
            (Flavour::Forgejo, 403) => json!({
                "message": "token does not have at least one of required scope(s): [write:user]",
            }),
            (Flavour::Forgejo, s) => json!({ "message": reason(s) }),
        };
        Reply::json(status, body)
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
        .unwrap_or_default()
}

/// The path part of an `http://host:port/path` URL.
fn url_path(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.find('/').map_or("", |i| &rest[i..])
}

/// An answer, kept as data so the status can be recorded.
struct Reply {
    status: u16,
    body: Option<Value>,
    headers: Vec<(&'static str, String)>,
}

impl Reply {
    fn new(status: u16) -> Reply {
        Reply {
            status,
            body: None,
            headers: Vec::new(),
        }
    }

    fn json(status: u16, body: Value) -> Reply {
        Reply {
            body: Some(body),
            ..Reply::new(status)
        }
    }

    fn header(mut self, name: &'static str, value: impl Into<String>) -> Reply {
        self.headers.push((name, value.into()));
        self
    }

    fn template(self) -> ResponseTemplate {
        let mut t = ResponseTemplate::new(self.status);
        for (name, value) in self.headers {
            t = t.insert_header(name, value.as_str());
        }
        match self.body {
            Some(b) => t.set_body_json(b),
            None => t,
        }
    }
}

struct Responder(Arc<Mutex<State>>);

impl Respond for Responder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let mut s = lock(&self.0);
        let resp = match s.take_fault(&req.method) {
            Some(Fault::LoseResponse) => {
                s.handle(req);
                s.record(req, Some(502));
                return ResponseTemplate::new(502)
                    .set_body_raw("<html>502 Bad Gateway</html>", "text/html");
            }
            Some(Fault::Status(code)) => s.error(code),
            // `CloseNext` takes these first.
            Some(Fault::CloseConnection { .. }) | None => s.handle(req),
        };
        s.record(req, Some(resp.status));
        resp.template()
    }
}

/// Matches when the next fault closes the connection for this request.
struct CloseNext(Arc<Mutex<State>>);

impl Match for CloseNext {
    fn matches(&self, req: &Request) -> bool {
        let s = lock(&self.0);
        matches!(s.faults.first(), Some((on, Fault::CloseConnection { .. }))
            if *on == FaultOn::Any || is_write(&req.method))
    }
}

/// Makes wiremock drop the connection without an answer.
#[derive(Debug)]
struct Closed;

impl std::fmt::Display for Closed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeForge closed the connection")
    }
}

impl std::error::Error for Closed {}

fn close(state: &Mutex<State>, req: &Request) -> Closed {
    let mut s = lock(state);
    if let Some(Fault::CloseConnection { apply: true }) = s.take_fault(&req.method) {
        s.handle(req);
    }
    s.record(req, None);
    Closed
}
